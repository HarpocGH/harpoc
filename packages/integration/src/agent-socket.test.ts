import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import {
  SSH_AGENT_FAILURE,
  SSH_AGENT_SIGN_RESPONSE,
  SSH_AGENT_SUCCESS,
  bindSession,
  buildUserauthRequest,
  connectAgent,
  generateHostKey,
  requestIdentities,
  requestSignature,
  verifyEd25519Signature,
} from "./helpers/agent-client.js";
import type { HostKey } from "./helpers/agent-client.js";
import { canon, keyNeedles } from "./helpers/key-needles.js";
import { runCli, startCliServer } from "./helpers/spawn-cli.js";
import type { CliServer } from "./helpers/spawn-cli.js";
import {
  sshFingerprint,
  sshKeyFixture,
  sshKeyFixturePath,
  sshPublicKeyBlob,
} from "./helpers/ssh-key-fixtures.js";

/**
 * The persistent agent socket on the built CLI (design M5, tranche B3):
 * `server start --ssh-agent --runtime-dir <dir>` on a real vault serves one
 * `ssh-agent.sock` per consumer directory, and a hand-built client — the
 * frames a real `ssh` sends, which core's live suite drives against a real
 * SSH server — binds to the pinned host key with `session-bind@openssh.com`,
 * has the vault sign a userauth request, and verifies the signature against
 * the identity's public half. The administrator's recipe runs as the README
 * gives it: `secret set --from-file`, `secret connection --known-host`,
 * `secret allow --host --ssh-agent-socket`, `policy grant`; the consumer's is
 * `ssh-agent status`. The consumer directory's `02750` group and the two-UID
 * exposure rows are the deployment recipe's and B6's.
 */

const PASSWORD = "agent-socket-master-pw-1";
const ARGON2_TIMEOUT_MS = 110_000;
const GRANTED = "agent-s";
const UNGRANTED = "agent-t";
const HANDLE = "secret://deploy-key";
const KEY_FIXTURE = "ed25519_openssh";
const SSH_AGENT_READY = /\[harpoc\] ssh-agent listening on 2 consumer sockets/;

interface AuditRow {
  event_type: string;
  secret_id: string | null;
  principal_id: string | null;
  ip_address: string | null;
  success: boolean;
  detail: Record<string, unknown> | null;
}

interface StatusReport {
  runtimeDir: string;
  consumers: Array<{
    consumer: string;
    socketPath: string;
    listening: boolean;
    identities: Array<{ keyType: string; fingerprint: string; comment: string; publicKey: string }>;
  }>;
}

// --runtime-dir is refused on win32 (the owner and mode of a directory cannot be checked there —
// RD-3), so `server start --ssh-agent` cannot start on the Windows legs until B7's pipe layout.
describe.skipIf(process.platform === "win32")(
  "the agent socket on the built CLI (server start --ssh-agent, session-bind, ssh-agent status)",
  () => {
    let root = "";
    let vaultDir = "";
    let runtimeDir = "";
    let daemon: CliServer | undefined;
    let host: HostKey | undefined;
    const keyBlob = sshPublicKeyBlob(KEY_FIXTURE);
    const outputs: string[] = [];
    const sessionIds: Buffer[] = [];

    const socketOf = (consumer: string): string => join(runtimeDir, consumer, "ssh-agent.sock");

    async function cli(args: string[], stdin?: string, timeoutMs?: number): Promise<string> {
      const run = await runCli(args, { vaultDir, stdin, timeoutMs });
      outputs.push(run.stdout, run.stderr);
      expect(run.code, `${args.join(" ")}: ${run.stderr}`).toBe(0);
      return run.stdout;
    }

    async function auditRows(event: string): Promise<AuditRow[]> {
      return JSON.parse(
        await cli(["audit", "--event", event, "--limit", "500", "--json"]),
      ) as AuditRow[];
    }

    const agentRows = async (): Promise<AuditRow[]> =>
      (await auditRows(AuditEventType.SECRET_USE)).filter(
        (row) => row.detail?.["context"] === "ssh_agent",
      );

    const listingRows = async (): Promise<AuditRow[]> =>
      (await auditRows(AuditEventType.VAULT_READ)).filter(
        (row) => row.detail?.["operation"] === "agent_socket_identities",
      );

    function userauthFor(sessionId: Buffer): Buffer {
      return buildUserauthRequest({
        sessionId,
        user: "deploy",
        service: "ssh-connection",
        method: "publickey",
        algorithm: "ssh-ed25519",
        publicKeyBlob: keyBlob,
      });
    }

    beforeAll(async () => {
      root = mkdtempSync(join(tmpdir(), "harpoc-asock-"));
      vaultDir = join(root, "vault");
      runtimeDir = join(root, "run");
      mkdirSync(vaultDir);
      // The deployment recipe's 0750 runtime directory and 02750 consumer directories;
      // `--runtime-dir` accepts 0750 or stricter (`(mode & 0o027) === 0`) owned by the daemon's user.
      mkdirSync(runtimeDir, { mode: 0o750 });
      chmodSync(runtimeDir, 0o750);
      for (const consumer of [GRANTED, UNGRANTED]) {
        mkdirSync(join(runtimeDir, consumer), { mode: 0o750 });
        chmodSync(join(runtimeDir, consumer), 0o750);
      }
      host = generateHostKey();

      // init leaves the vault unlocked with a session file; no unlock follows.
      await cli(["init"], `${PASSWORD}\n${PASSWORD}\n`, ARGON2_TIMEOUT_MS);
      await cli(["agent", "register", GRANTED]);
      await cli(["agent", "register", UNGRANTED]);
      await cli(["secret", "set", "deploy-key", "--from-file", sshKeyFixturePath(KEY_FIXTURE)]);
      await cli([
        "secret",
        "connection",
        HANDLE,
        "--known-host",
        `127.0.0.1 ${host.knownHostsKey}`,
      ]);
      await cli(["secret", "allow", HANDLE, "--host", "127.0.0.1", "--ssh-agent-socket"]);
      await cli([
        "policy",
        "grant",
        HANDLE,
        "--principal-type",
        "agent",
        "--principal-id",
        GRANTED,
        "--permissions",
        "use",
      ]);

      // No port and no /health: the readiness signal is the socket line the CLI prints once
      // every consumer socket is bound. --ssh-agent runs in the memory session (B5): the daemon
      // loads the session init wrote once and leaves it to the CLI below.
      daemon = startCliServer(
        ["server", "start", "--ssh-agent", "--runtime-dir", runtimeDir, "--session", "memory"],
        { vaultDir },
      );
      await daemon.waitForStderr(SSH_AGENT_READY);
    }, 180_000);

    afterAll(async () => {
      try {
        await daemon?.stop();
      } finally {
        if (root !== "") {
          rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        }
      }
    });

    it("serves one ssh-agent.sock per consumer directory, mode 0660, each with its server.start row", async () => {
      for (const consumer of [GRANTED, UNGRANTED]) {
        const stat = statSync(socketOf(consumer));
        expect(stat.isSocket()).toBe(true);
        expect((stat.mode & 0o777).toString(8)).toBe("660");
      }
      const rows = (await auditRows(AuditEventType.SERVER_START)).filter(
        (row) => row.detail?.["transport"] === "ssh-agent",
      );
      expect(rows.map((row) => row.detail?.["consumer"]).sort()).toEqual([GRANTED, UNGRANTED]);
      for (const row of rows) {
        expect(row.success).toBe(true);
        expect(row.detail).toMatchObject({ tokenless: true, tty_prompt: false });
      }
    }, 60_000);

    it("ssh-agent status lists the granted consumer's one identity by fingerprint and handle, and none for the other — with no vault to open", async () => {
      const run = await runCli(["ssh-agent", "status", "--runtime-dir", runtimeDir, "--json"], {
        vaultDir: join(root, "no-vault-here"),
      });
      outputs.push(run.stdout, run.stderr);
      expect(run.code, run.stderr).toBe(0);
      expect(existsSync(join(root, "no-vault-here"))).toBe(false);
      const report = JSON.parse(run.stdout) as StatusReport;
      const byName = Object.fromEntries(report.consumers.map((c) => [c.consumer, c]));
      expect(byName[GRANTED]).toMatchObject({ socketPath: socketOf(GRANTED), listening: true });
      expect(byName[GRANTED]?.identities).toEqual([
        {
          keyType: "ssh-ed25519",
          fingerprint: sshFingerprint(keyBlob),
          comment: HANDLE,
          publicKey: `ssh-ed25519 ${keyBlob.toString("base64")} ${HANDLE}`,
        },
      ]);
      expect(byName[UNGRANTED]).toMatchObject({ listening: true, identities: [] });
    }, 60_000);

    it("a bound sign: the client binds to the pinned host key, the vault signs the userauth request with the key it alone holds, and one secret.use row records the host", async () => {
      const sock = await connectAgent(socketOf(GRANTED));
      try {
        const sessionId = randomBytes(32);
        sessionIds.push(sessionId);
        const bound = await bindSession(sock, (host as HostKey).binding(sessionId));
        expect(bound.type).toBe(SSH_AGENT_SUCCESS);
        expect((await requestIdentities(sock)).identities.map((i) => i.comment)).toEqual([HANDLE]);
        const data = userauthFor(sessionId);
        const reply = await requestSignature(sock, { keyBlob, data, flags: 0 });

        expect(reply.type).toBe(SSH_AGENT_SIGN_RESPONSE);
        expect(verifyEd25519Signature(keyBlob, data, reply.payload)).toBe(true);
      } finally {
        sock.destroy();
      }
      const rows = (await agentRows()).filter((row) => row.success);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ principal_id: GRANTED, ip_address: null });
      expect(rows[0]?.secret_id).toEqual(expect.any(String));
      expect(rows[0]?.detail).toMatchObject({
        context: "ssh_agent",
        host: "127.0.0.1",
        key_type: "ssh-ed25519",
        interface: "ssh_agent",
      });
    }, 60_000);

    it("an unbound sign request is refused SSH_AGENT_FAILURE, with a failed secret.use row SSH_AGENT_UNBOUND", async () => {
      const sock = await connectAgent(socketOf(GRANTED));
      try {
        const sessionId = randomBytes(32);
        sessionIds.push(sessionId);
        const reply = await requestSignature(sock, {
          keyBlob,
          data: userauthFor(sessionId),
          flags: 0,
        });
        expect(reply.type).toBe(SSH_AGENT_FAILURE);
      } finally {
        sock.destroy();
      }
      const failed = (await agentRows()).filter((row) => !row.success);
      expect(failed).toHaveLength(1);
      expect(failed[0]).toMatchObject({ principal_id: GRANTED });
      expect(failed[0]?.detail).toMatchObject({
        error: ErrorCode.SSH_AGENT_UNBOUND,
        reason: "unbound",
      });
    }, 60_000);

    it("each listing writes one vault.read row naming its consumer — the count, the bound host key's fingerprint, count 0 for a host key no secret pins — and an inactive consumer's listing a failed row", async () => {
      const before = (await listingRows()).length;
      const unpinned = generateHostKey();
      const pinnedSession = randomBytes(32);
      const unpinnedSession = randomBytes(32);

      const sock = await connectAgent(socketOf(GRANTED));
      try {
        expect((await requestIdentities(sock)).identities).toHaveLength(1);
        expect((await bindSession(sock, (host as HostKey).binding(pinnedSession))).type).toBe(
          SSH_AGENT_SUCCESS,
        );
        expect((await requestIdentities(sock)).identities).toHaveLength(1);
      } finally {
        sock.destroy();
      }
      const hop = await connectAgent(socketOf(GRANTED));
      try {
        expect((await bindSession(hop, unpinned.binding(unpinnedSession))).type).toBe(
          SSH_AGENT_SUCCESS,
        );
        expect((await requestIdentities(hop)).identities).toEqual([]);
      } finally {
        hop.destroy();
      }
      await cli(["agent", "deactivate", UNGRANTED]);
      try {
        const inactive = await connectAgent(socketOf(UNGRANTED));
        try {
          expect((await requestIdentities(inactive)).identities).toEqual([]);
        } finally {
          inactive.destroy();
        }
      } finally {
        await cli(["agent", "activate", UNGRANTED]);
      }

      const after = await listingRows();
      const rows = after.slice(0, after.length - before);
      expect(
        rows.map((row) => [row.success, row.secret_id, row.principal_id, row.ip_address]),
      ).toEqual([
        [false, null, UNGRANTED, null],
        [true, null, GRANTED, null],
        [true, null, GRANTED, null],
        [true, null, GRANTED, null],
      ]);
      expect(rows.map((row) => row.detail)).toEqual([
        {
          operation: "agent_socket_identities",
          bound: false,
          error: ErrorCode.AGENT_INACTIVE,
          interface: "ssh_agent",
        },
        {
          operation: "agent_socket_identities",
          bound: true,
          count: 0,
          host_key_fingerprint: sshFingerprint(unpinned.hostKeyBlob),
          interface: "ssh_agent",
        },
        {
          operation: "agent_socket_identities",
          bound: true,
          count: 1,
          host_key_fingerprint: sshFingerprint((host as HostKey).hostKeyBlob),
          interface: "ssh_agent",
        },
        { operation: "agent_socket_identities", bound: false, count: 1, interface: "ssh_agent" },
      ]);
      const serialized = JSON.stringify(rows.map((row) => row.detail));
      const named = [HANDLE, GRANTED, UNGRANTED, "127.0.0.1"];
      for (const text of named) expect(serialized.includes(text)).toBe(false);
      for (const sid of [pinnedSession, unpinnedSession]) {
        expect(serialized.includes(sid.toString("hex"))).toBe(false);
        expect(serialized.includes(sid.toString("base64"))).toBe(false);
      }
      for (const blob of [keyBlob, (host as HostKey).hostKeyBlob, unpinned.hostKeyBlob]) {
        expect(serialized.includes(blob.toString("base64"))).toBe(false);
      }
    }, 60_000);

    it("neither the private key nor a session identifier reaches the daemon's output, the CLI's output or the audit trail", async () => {
      const trail = await cli(["audit", "--limit", "500", "--json"]);
      const needles = [
        ...keyNeedles("deploy key", sshKeyFixture(KEY_FIXTURE)).map((n) => n.value),
        ...sessionIds.flatMap((sid) => [sid.toString("hex"), sid.toString("base64")]),
      ];
      expect(needles.length).toBe(6);
      const swept = [daemon?.stdoutSoFar() ?? "", daemon?.stderrSoFar() ?? "", trail, ...outputs];
      for (const text of swept) {
        for (const needle of needles) expect(canon(text).includes(needle)).toBe(false);
      }
    }, 60_000);

    it("the daemon stops on SIGTERM: one server.stop row per consumer socket, naming its consumer, and each socket is removed", async () => {
      const server = daemon as CliServer;
      await server.stop();
      expect(server.child.exitCode).toBe(0);
      const rows = (await auditRows(AuditEventType.SERVER_STOP)).filter(
        (row) => row.detail?.["transport"] === "ssh-agent",
      );
      expect(rows.map((row) => row.detail?.["consumer"]).sort()).toEqual([GRANTED, UNGRANTED]);
      for (const row of rows)
        expect(row.detail).toMatchObject({ tokenless: true, trigger: "SIGTERM" });
      for (const consumer of [GRANTED, UNGRANTED])
        expect(existsSync(socketOf(consumer))).toBe(false);
    }, 60_000);
  },
);
