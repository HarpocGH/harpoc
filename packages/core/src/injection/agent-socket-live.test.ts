import { spawn, spawnSync } from "node:child_process";
import { createPrivateKey, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ssh2 from "ssh2";
import type { AuthContext, Connection, ParsedKey, Server as SshServer } from "ssh2";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import type { VaultError } from "@harpoc/shared";
import { registerAgents } from "../__fixtures__/engine-seams.js";
import { WINDOWS_PIPE_CONSUMER_RIGHTS } from "../session/owner-only.js";
import { VaultEngine } from "../vault-engine.js";
import { system32Path } from "../win32-paths.js";
import { resolveExecutable } from "./allowlist.js";
import {
  SSH_AGENT_FAILURE,
  SSH_AGENT_SUCCESS,
  bindSession,
  buildUserauthRequest,
  connectAgent,
  hostKeyBinding,
  parseIdentities,
  requestIdentities,
  requestSignature,
} from "./__fixtures__/agent-client.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { AgentSocketServer } from "./ssh-agent/agent-socket-server.js";
import { loadPrivateKey } from "./ssh-agent/key-loader.js";
import {
  buildSshEnv,
  sshHardeningArgs,
  writeIdentityFile,
  writeKnownHosts,
  writeTempSshFile,
} from "./ssh-common.js";

vi.mock("../crypto/argon2.js", async (importOriginal) =>
  (await import("../__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

/**
 * The persistent agent socket end to end (design M5, tranche B3): the real
 * OpenSSH client, with the production hardening argv, authenticates against a
 * real SSH server through `AgentSocketServer` on a real engine — the key held
 * only by the vault, `session-bind@openssh.com` binding the connection to the
 * server's host key before the signature, the host judged through the secret's
 * pinned known_hosts line and its host allowlist. The client binds first on
 * every agent connection it opens (`sshconnect2.c` `get_agent_identities`);
 * the hand-built client covers what a real ssh never sends: a sign request
 * without a bind and a bind to a host key no secret pins.
 *
 * The server side is the `ssh2` package (core's devDependency, as in
 * `ssh-live-auth.test.ts`); it does not advertise
 * `publickey-hostbound-v00@openssh.com`, so the client signs the plain
 * `publickey` userauth request. Its host key is the fixture `ecdsa384_openssh`
 * — distinct from both user keys — so the pinned line is the fixture's `.pub`.
 * The socket is a named pipe on win32 and a Unix socket in a 0700 temporary
 * directory elsewhere; the consumer directory, its mode and the two-UID
 * exposure rows are the CLI's and B6's.
 */

const { Server, utils } = ssh2;

// The native Win32-OpenSSH client is the only one that opens a named pipe as
// SSH_AUTH_SOCK (`ssh-live-auth.test.ts`): it is pinned the same way here.
const SSH =
  process.platform === "win32"
    ? (resolveExecutable(
        join(process.env.SystemRoot ?? "C:\\Windows", "System32", "OpenSSH", "ssh.exe"),
        [],
      ) ?? resolveNativeSshClient("ssh"))
    : resolveNativeSshClient("ssh");

const CONSUMER = "agent-live";
const STRANGER = "agent-stranger";
const HOST_KEY = "ecdsa384_openssh";
const UNPINNED_HOST_KEY = "rsa_openssh";
const JUMP_HOST_KEY = "ecdsa521_openssh";
const KEYS = [
  { handle: "secret://deploy-ed", name: "deploy-ed", fixture: "ed25519_openssh" },
  { handle: "secret://deploy-ec", name: "deploy-ec", fixture: "ecdsa256_openssh" },
] as const;

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__", "ssh");
const fixture = (name: string): string => readFileSync(join(FIXTURES, name), "utf8");
const publicLine = (name: string): string =>
  fixture(`${name}.pub`).trim().split(/\s+/).slice(0, 2).join(" ");

/** The fixture key's private material in the forms a leak would take: PEM body lines, the JWK scalar. */
function privateNeedles(name: string): string[] {
  const pem = fixture(name);
  const lines = pem.split(/\r?\n/).filter((line) => line.length >= 16 && !line.startsWith("-----"));
  const parsed = utils.parseKey(pem) as ParsedKey;
  const jwk = createPrivateKey(parsed.getPrivatePEM()).export({ format: "jwk" });
  const scalar = Buffer.from(jwk.d as string, "base64url");
  return [
    ...lines,
    scalar.toString("base64url"),
    scalar.toString("base64"),
    scalar.toString("hex"),
  ];
}

/** The hardening argv as an ssh_config `Host *` block: a ProxyJump's own ssh is passed `-F` and none of the `-o` options. */
function hardeningConfig(args: readonly string[]): string {
  const lines = ["Host *"];
  for (let i = 0; i < args.length; i += 2) {
    const value = args[i + 1] as string;
    if (args[i] === "-o") lines.push(`  ${value.replace("=", " ")}`);
    else if (args[i] === "-i") lines.push(`  IdentityFile "${value}"`);
    else if (args[i] !== "-F") throw new Error(`unmapped hardening flag ${String(args[i])}`);
  }
  return `${lines.join("\n")}\n`;
}

it("ssh-live tier: required legs fail instead of skipping when ssh is unresolvable", () => {
  if (SSH === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no ssh client resolves',
    );
  }
});

interface AuthEvent {
  method: string;
  key?: string;
  signed?: boolean;
  verified?: boolean;
}

describe.skipIf(SSH === null)(
  "the agent socket under a real ssh (session-bind, engine-backed)",
  () => {
    let sshServer: SshServer | undefined;
    let port = 0;
    let jumpServer: SshServer | undefined;
    let jumpPort = 0;
    const jumpClients = new Set<Connection>();
    const jumpEvents: AuthEvent[] = [];
    let tempDir = "";
    let engine: VaultEngine | undefined;
    let socket: AgentSocketServer | undefined;
    let strangerSocket: AgentSocketServer | undefined;
    let restrictedSocket: AgentSocketServer | undefined;
    let reducedSocket: AgentSocketServer | undefined;
    const ids: Record<string, string> = {};
    const blobs: Record<string, Buffer> = {};
    const events: AuthEvent[] = [];
    const outputs: string[] = [];
    const needles: string[] = [];

    const vault = (): VaultEngine => engine as VaultEngine;
    const useRows = () =>
      vault()
        .queryAudit({ eventType: AuditEventType.SECRET_USE })
        .filter((row) => row.detail?.["context"] === "ssh_agent");
    const rowIds = (): Set<number> => new Set(useRows().map((row) => row.id));
    const rowsSince = (seen: Set<number>) => useRows().filter((row) => !seen.has(row.id));

    function socketPath(consumer: string): string {
      return process.platform === "win32"
        ? `\\\\.\\pipe\\harpoc-agent-live-${consumer}-${randomBytes(6).toString("hex")}`
        : join(tempDir, `${consumer}.sock`);
    }

    const pin = (pinPort: number, hostKey: string): string =>
      `[127.0.0.1]:${String(pinPort)} ${publicLine(hostKey)}`;

    function expectScratchConfigOnly(stderr: string): void {
      const reads = [...stderr.matchAll(/Reading configuration data ([^\r\n]+)/g)].map((m) =>
        (m[1] as string).trim(),
      );
      expect(reads.length).toBe(2);
      expect(reads.every((file) => file === "config")).toBe(true);
      expect(/[\\/]\.ssh[\\/]/.test(stderr)).toBe(false);
      expect(stderr.includes("ssh_config")).toBe(false);
    }

    function runSsh(
      identityFixture: string,
      authSock: string,
      viaJump = false,
    ): Promise<{ exit: number | null; stdout: string; stderr: string }> {
      const kh = writeKnownHosts([
        `[127.0.0.1]:${String(port)} ${publicLine(HOST_KEY)}`,
        ...(viaJump ? [pin(jumpPort, JUMP_HOST_KEY)] : []),
      ]);
      const identity = writeIdentityFile(publicLine(identityFixture));
      const hardening = sshHardeningArgs(kh.file, identity.file, 10);
      const config = viaJump
        ? writeTempSshFile("harpoc-ssh-cfg-", "config", hardeningConfig(hardening))
        : undefined;
      const args = [
        ...(config === undefined
          ? hardening
          : ["-F", basename(config.file), "-J", `testuser@127.0.0.1:${String(jumpPort)}`]),
        "-v",
        "-p",
        String(port),
        "-l",
        "testuser",
        "--",
        "127.0.0.1",
        "whoami",
      ];
      return new Promise<{ exit: number | null; stdout: string; stderr: string }>(
        (resolve, reject) => {
          const child = spawn(SSH as string, args, {
            env: buildSshEnv(authSock, []),
            stdio: ["ignore", "pipe", "pipe"],
            ...(config === undefined ? {} : { cwd: dirname(config.file) }),
          });
          const timer = setTimeout(() => {
            child.kill();
            for (const client of jumpClients) client.end();
          }, 25_000);
          let stdout = "";
          let stderr = "";
          child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
          child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
          child.on("error", reject);
          child.on("close", (code) => {
            clearTimeout(timer);
            outputs.push(stdout, stderr);
            // The server records each auth event before it replies: every event has landed by the
            // child's close, and the negative rows wait for the flushed tick, not a sleep.
            setImmediate(() => resolve({ exit: code, stdout, stderr }));
          });
        },
      ).finally(async () => {
        await Promise.all(
          [...jumpClients].map(
            (client) => new Promise<void>((resolve) => client.once("close", () => resolve())),
          ),
        );
        kh.dispose();
        identity.dispose();
        config?.dispose();
      });
    }

    /** The real `ssh-add -l` beside the resolved ssh, on `authSock`: the agent's listing, nothing signed. */
    function runSshAdd(
      authSock: string,
    ): Promise<{ exit: number | null; stdout: string; stderr: string }> {
      return new Promise((resolve, reject) => {
        const child = spawn(join(dirname(SSH as string), "ssh-add.exe"), ["-l"], {
          env: buildSshEnv(authSock, []),
          stdio: ["ignore", "pipe", "pipe"],
        });
        const timer = setTimeout(() => child.kill(), 25_000);
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
        child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
        child.on("error", reject);
        child.on("close", (code) => {
          clearTimeout(timer);
          outputs.push(stdout, stderr);
          resolve({ exit: code, stdout, stderr });
        });
      });
    }

    /** As the pipe's owner (WRITE_DAC is the owner's own), remove every DACL entry but `sid`'s; the DACL left, in SDDL. */
    function keepOnlyEntry(path: string, sid: string): string {
      const name = path.slice("\\\\.\\pipe\\".length);
      const res = spawnSync(
        system32Path("WindowsPowerShell", "v1.0", "powershell.exe"),
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "$ErrorActionPreference='Stop';$s=[System.Security.Principal.SecurityIdentifier];" +
            `$q=[System.IO.Pipes.NamedPipeClientStream]::new('.','${name}',[System.IO.Pipes.PipeAccessRights]'ReadData, ReadPermissions, ChangePermissions',[System.IO.Pipes.PipeOptions]::None,[System.Security.Principal.TokenImpersonationLevel]::Identification,[System.IO.HandleInheritability]::None);` +
            "$q.Connect(5000);try{$a=$q.GetAccessControl();" +
            `foreach($r in @($a.GetAccessRules($true,$true,$s))){if($r.IdentityReference.Value -ne '${sid}'){[void]$a.RemoveAccessRuleSpecific($r)}};` +
            "$q.SetAccessControl($a);[System.Console]::Out.Write($q.GetAccessControl().GetSecurityDescriptorSddlForm('Access'))}finally{$q.Dispose()}",
        ],
        { encoding: "utf8", shell: false, windowsHide: true, timeout: 15_000 },
      );
      expect(res.status).toBe(0);
      return res.stdout;
    }

    beforeAll(async () => {
      const userKeys = KEYS.map((k) => ({
        name: k.name,
        parsed: utils.parseKey(fixture(k.fixture)),
      }));
      const authenticate = (sink: AuthEvent[], ctx: AuthContext): void => {
        if (ctx.method !== "publickey") {
          sink.push({ method: ctx.method });
          ctx.reject(["publickey"]);
          return;
        }
        const offered = userKeys.find(
          ({ parsed }) =>
            !(parsed instanceof Error) &&
            ctx.key.algo === parsed.type &&
            ctx.key.data.equals(parsed.getPublicSSH()),
        );
        if (offered === undefined || offered.parsed instanceof Error || !ctx.signature) {
          sink.push({ method: ctx.method, key: offered?.name, signed: false });
          if (offered) ctx.accept();
          else ctx.reject(["publickey"]);
          return;
        }
        const verified = offered.parsed.verify(
          ctx.blob as Buffer,
          ctx.signature,
          (ctx as unknown as { hashAlgo?: string }).hashAlgo,
        );
        needles.push(ctx.signature.toString("base64"), ctx.signature.toString("hex"));
        sink.push({ method: ctx.method, key: offered.name, signed: true, verified });
        if (verified) ctx.accept();
        else ctx.reject(["publickey"]);
      };
      const srv = new Server({ hostKeys: [fixture(HOST_KEY)] }, (client) => {
        client
          .on("authentication", (ctx) => authenticate(events, ctx))
          .on("ready", () => {
            client.on("session", (accept) => {
              accept().on("exec", (acceptExec) => {
                const stream = acceptExec();
                stream.write("live-ok\n");
                stream.exit(0);
                stream.end();
              });
            });
          })
          .on("error", () => {
            /* client-side disconnects after a refused signature are expected here */
          });
      });
      sshServer = srv;
      await new Promise<void>((resolve) => {
        srv.listen(0, "127.0.0.1", () => {
          port = (srv.address() as { port: number }).port;
          resolve();
        });
      });
      const hop = new Server({ hostKeys: [fixture(JUMP_HOST_KEY)] }, (client) => {
        jumpClients.add(client);
        client
          .on("authentication", (ctx) => authenticate(jumpEvents, ctx))
          .on("ready", () => {
            client.on("tcpip", (accept, reject, info) => {
              if (info.destIP !== "127.0.0.1" || info.destPort !== port) {
                reject();
                return;
              }
              const channel = accept();
              const upstream = connect(port, "127.0.0.1");
              upstream.on("error", () => channel.destroy());
              channel.on("close", () => upstream.destroy());
              channel.pipe(upstream).pipe(channel);
            });
          })
          .on("close", () => jumpClients.delete(client))
          .on("error", () => undefined);
      });
      jumpServer = hop;
      await new Promise<void>((resolve) => {
        hop.listen(0, "127.0.0.1", () => {
          jumpPort = (hop.address() as { port: number }).port;
          resolve();
        });
      });

      tempDir = mkdtempSync(join(tmpdir(), "harpoc-asl-"));
      engine = new VaultEngine({
        dbPath: join(tempDir, "vault.db"),
        sessionPath: join(tempDir, "session.json"),
      });
      await engine.initVault("agent-socket-live-pw");
      registerAgents(engine, CONSUMER, STRANGER);
      for (const key of KEYS) {
        await engine.createSecret({
          name: key.name,
          type: SecretType.API_KEY,
          value: new Uint8Array(Buffer.from(fixture(key.fixture))),
        });
        await engine.setInjectionPolicy(key.handle, {
          host_allowlist: ["127.0.0.1"],
          ssh_agent_socket: true,
        });
        await engine.setConnectionConfig(key.handle, {
          ssh: { known_hosts: [`[127.0.0.1]:${String(port)} ${publicLine(HOST_KEY)}`] },
        });
        ids[key.name] = await engine.resolveSecretId(key.handle);
        engine.grantPolicy(
          {
            secretId: ids[key.name] as string,
            principalType: "agent",
            principalId: CONSUMER,
            permissions: ["use"],
          },
          "test-admin",
        );
        blobs[key.name] = loadPrivateKey(fixture(key.fixture)).publicKeyBlob;
        needles.push(...privateNeedles(key.fixture));
      }
      const onError = (err: VaultError): void => {
        outputs.push(`${err.code}: ${err.message}`);
      };
      socket = await AgentSocketServer.start({
        socketPath: socketPath(CONSUMER),
        consumer: CONSUMER,
        engine,
        onError,
      });
      strangerSocket = await AgentSocketServer.start({
        socketPath: socketPath(STRANGER),
        consumer: STRANGER,
        engine,
        onError,
      });
    });

    afterAll(async () => {
      const settled = await Promise.allSettled([
        socket?.stop(),
        strangerSocket?.stop(),
        restrictedSocket?.stop(),
        reducedSocket?.stop(),
        engine?.destroy(),
        new Promise<void>((resolve) => {
          if (sshServer) sshServer.close(() => resolve());
          else resolve();
        }),
        new Promise<void>((resolve) => {
          for (const client of jumpClients) client.end();
          if (jumpServer) jumpServer.close(() => resolve());
          else resolve();
        }),
      ]);
      if (tempDir !== "") {
        rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
      const failed = settled.find(
        (result): result is PromiseRejectedResult => result.status === "rejected",
      );
      if (failed) throw failed.reason;
    });

    beforeEach(() => {
      events.length = 0;
      jumpEvents.length = 0;
    });

    it("binds and signs for an allowlisted, pinned host: ssh authenticates with key 1 and the engine audits one secret.use row with the bound host", async () => {
      const seen = rowIds();
      const r = await runSsh("ed25519_openssh", (socket as AgentSocketServer).socketPath);

      expect(r.exit, r.stderr).toBe(0);
      expect(r.stdout.trim()).toBe("live-ok");
      // The client bound its agent connection to the server's host key before listing.
      expect(r.stderr).toContain("bound agent to hostkey");
      expect(events.some((e) => e.key === "deploy-ed" && e.signed && e.verified)).toBe(true);
      expect(
        events.filter((e) => e.method === "publickey").every((e) => e.key === "deploy-ed"),
      ).toBe(true);
      const rows = rowsSince(seen);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        success: true,
        secret_id: ids["deploy-ed"],
        principal_type: "agent",
        principal_id: CONSUMER,
      });
      expect(rows[0]?.detail).toMatchObject({
        context: "ssh_agent",
        host: "127.0.0.1",
        key_type: "ssh-ed25519",
        interface: "ssh_agent",
      });
    }, 30_000);

    it("IdentitiesOnly with the second key's public half: of two granted keys the server is offered and signs with key 2 alone", async () => {
      const seen = rowIds();
      const r = await runSsh("ecdsa256_openssh", (socket as AgentSocketServer).socketPath);

      expect(r.exit, r.stderr).toBe(0);
      expect(
        events.filter((e) => e.method === "publickey").every((e) => e.key === "deploy-ec"),
      ).toBe(true);
      expect(events.some((e) => e.key === "deploy-ec" && e.signed && e.verified)).toBe(true);
      const rows = rowsSince(seen);
      expect(rows.map((row) => row.secret_id)).toEqual([ids["deploy-ec"]]);
      expect(rows[0]?.detail).toMatchObject({ host: "127.0.0.1", key_type: "ecdsa-sha2-nistp256" });
    }, 30_000);

    it("a bound host outside the secret's host allowlist: the sign is refused, ssh is denied, and a failed secret.use row names the host and HOST_NOT_ALLOWED", async () => {
      await vault().setInjectionPolicy("secret://deploy-ed", {
        host_allowlist: ["example.invalid"],
        ssh_agent_socket: true,
      });
      try {
        const seen = rowIds();
        const r = await runSsh("ed25519_openssh", (socket as AgentSocketServer).socketPath);

        expect(r.exit).not.toBe(0);
        expect(r.stderr).toContain("Permission denied");
        expect(events.some((e) => e.signed)).toBe(false);
        const rows = rowsSince(seen);
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          success: false,
          secret_id: ids["deploy-ed"],
          principal_id: CONSUMER,
        });
        expect(rows[0]?.detail).toMatchObject({
          context: "ssh_agent",
          host: "127.0.0.1",
          error: ErrorCode.HOST_NOT_ALLOWED,
        });
      } finally {
        await vault().setInjectionPolicy("secret://deploy-ed", {
          host_allowlist: ["127.0.0.1"],
          ssh_agent_socket: true,
        });
      }
    }, 30_000);

    it("a consumer without a grant: its socket answers no identity, ssh is denied, and no secret.use row is written", async () => {
      const seen = rowIds();
      const r = await runSsh("ed25519_openssh", (strangerSocket as AgentSocketServer).socketPath);

      expect(r.exit).not.toBe(0);
      expect(r.stderr).toContain("Permission denied");
      expect(events.some((e) => e.signed)).toBe(false);
      expect(rowsSince(seen)).toEqual([]);
      const sock = await connectAgent((strangerSocket as AgentSocketServer).socketPath);
      try {
        expect(parseIdentities(await requestIdentities(sock))).toEqual([]);
      } finally {
        sock.close();
      }
    }, 30_000);

    it("a hand-built unbound connection lists both granted keys by handle, and its sign request is refused with a SSH_AGENT_UNBOUND row", async () => {
      const sock = await connectAgent((socket as AgentSocketServer).socketPath);
      try {
        const beforeListing = rowIds();
        const listed = parseIdentities(await requestIdentities(sock));
        expect(listed.map((identity) => identity.comment).sort()).toEqual([
          "secret://deploy-ec",
          "secret://deploy-ed",
        ]);
        expect(rowsSince(beforeListing)).toEqual([]);
        const sessionId = randomBytes(32);
        needles.push(sessionId.toString("hex"), sessionId.toString("base64"));
        const keyBlob = blobs["deploy-ed"] as Buffer;
        const seen = rowIds();
        const reply = await requestSignature(sock, {
          keyBlob,
          data: buildUserauthRequest({
            sessionId,
            user: "testuser",
            service: "ssh-connection",
            method: "publickey",
            algorithm: "ssh-ed25519",
            publicKeyBlob: keyBlob,
          }),
          flags: 0,
        });

        expect(reply.type).toBe(SSH_AGENT_FAILURE);
        const rows = rowsSince(seen);
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          success: false,
          secret_id: ids["deploy-ed"],
          principal_id: CONSUMER,
        });
        expect(rows[0]?.detail).toMatchObject({
          context: "ssh_agent",
          error: ErrorCode.SSH_AGENT_UNBOUND,
          reason: "unbound",
        });
      } finally {
        sock.close();
      }
    }, 30_000);

    it("a bind to a host key no secret pins: the bind verifies, the bound listing is empty, and the sign is refused with a SSH_AGENT_UNBOUND row", async () => {
      const sock = await connectAgent((socket as AgentSocketServer).socketPath);
      try {
        const sessionId = randomBytes(32);
        needles.push(sessionId.toString("hex"), sessionId.toString("base64"));
        const bound = await bindSession(sock, {
          ...hostKeyBinding(UNPINNED_HOST_KEY, sessionId),
          isForwarding: false,
        });
        expect(bound.type).toBe(SSH_AGENT_SUCCESS);
        expect(parseIdentities(await requestIdentities(sock))).toEqual([]);
        const keyBlob = blobs["deploy-ed"] as Buffer;
        const seen = rowIds();
        const reply = await requestSignature(sock, {
          keyBlob,
          data: buildUserauthRequest({
            sessionId,
            user: "testuser",
            service: "ssh-connection",
            method: "publickey",
            algorithm: "ssh-ed25519",
            publicKeyBlob: keyBlob,
          }),
          flags: 0,
        });

        expect(reply.type).toBe(SSH_AGENT_FAILURE);
        const rows = rowsSince(seen);
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          success: false,
          secret_id: ids["deploy-ed"],
          principal_id: CONSUMER,
        });
        expect(rows[0]?.detail).toMatchObject({
          context: "ssh_agent",
          error: ErrorCode.SSH_AGENT_UNBOUND,
          reason: "host_unpinned",
        });
      } finally {
        sock.close();
      }
    }, 30_000);

    it("a jump host and its target are each signed for as a direct session", async () => {
      await vault().setConnectionConfig("secret://deploy-ed", {
        ssh: { known_hosts: [pin(port, HOST_KEY), pin(jumpPort, JUMP_HOST_KEY)] },
      });
      try {
        const seen = rowIds();
        const r = await runSsh("ed25519_openssh", (socket as AgentSocketServer).socketPath, true);

        expectScratchConfigOnly(r.stderr);
        expect(r.exit, r.stderr).toBe(0);
        expect(r.stdout.trim()).toBe("live-ok");
        expect(r.stderr.split("bound agent to hostkey").length - 1).toBe(2);
        expect(jumpEvents.some((e) => e.key === "deploy-ed" && e.signed && e.verified)).toBe(true);
        expect(events.some((e) => e.key === "deploy-ed" && e.signed && e.verified)).toBe(true);
        const rows = rowsSince(seen).sort((a, b) => a.id - b.id);
        expect(
          rows.map((row) => [row.success, row.secret_id, row.principal_id, row.detail?.["port"]]),
        ).toEqual([
          [true, ids["deploy-ed"], CONSUMER, jumpPort],
          [true, ids["deploy-ed"], CONSUMER, port],
        ]);
        for (const row of rows) {
          expect(row.detail).toMatchObject({
            context: "ssh_agent",
            host: "127.0.0.1",
            key_type: "ssh-ed25519",
            interface: "ssh_agent",
          });
        }
        expect(rows.some((row) => row.detail?.["reason"] === "forwarding")).toBe(false);
      } finally {
        await vault().setConnectionConfig("secret://deploy-ed", {
          ssh: { known_hosts: [pin(port, HOST_KEY)] },
        });
      }
    }, 30_000);

    it("ssh -J to a target whose host key the secret does not pin: the jump is signed for, the target's bound listing omits the key so ssh asks no signature there and is denied, and the one secret.use row names the jump", async () => {
      await vault().setConnectionConfig("secret://deploy-ed", {
        ssh: { known_hosts: [pin(jumpPort, JUMP_HOST_KEY)] },
      });
      try {
        const seen = rowIds();
        const r = await runSsh("ed25519_openssh", (socket as AgentSocketServer).socketPath, true);

        expectScratchConfigOnly(r.stderr);
        expect(r.exit).not.toBe(0);
        expect(r.stderr).toContain("Permission denied");
        expect(r.stderr.split("bound agent to hostkey").length - 1).toBe(2);
        expect(jumpEvents.some((e) => e.key === "deploy-ed" && e.signed && e.verified)).toBe(true);
        expect(events.some((e) => e.key === "deploy-ed")).toBe(true);
        expect(events.some((e) => e.signed)).toBe(false);
        const rows = rowsSince(seen);
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          success: true,
          secret_id: ids["deploy-ed"],
          principal_id: CONSUMER,
        });
        expect(rows[0]?.detail).toMatchObject({
          context: "ssh_agent",
          host: "127.0.0.1",
          port: jumpPort,
        });
      } finally {
        await vault().setConnectionConfig("secret://deploy-ed", {
          ssh: { known_hosts: [pin(port, HOST_KEY)] },
        });
      }
    }, 30_000);

    it.runIf(process.platform === "win32")(
      "win32 only (the pipe's DACL): with the DACL replaced for the consumer (BUILTIN\\Users standing in), ssh still authenticates through the pipe and the engine audits one secret.use row",
      async () => {
        restrictedSocket = await AgentSocketServer.start({
          socketPath: socketPath(CONSUMER),
          consumer: CONSUMER,
          engine: vault(),
          onError: (err) => outputs.push(`${err.code}: ${err.message}`),
          win32ConsumerSid: "S-1-5-32-545",
        });
        const seen = rowIds();
        const r = await runSsh("ed25519_openssh", restrictedSocket.socketPath);

        expect(r.exit, r.stderr).toBe(0);
        expect(r.stdout.trim()).toBe("live-ok");
        expect(r.stderr).toContain("bound agent to hostkey");
        expect(events.some((e) => e.key === "deploy-ed" && e.signed && e.verified)).toBe(true);
        const rows = rowsSince(seen);
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          success: true,
          secret_id: ids["deploy-ed"],
          principal_type: "agent",
          principal_id: CONSUMER,
        });
        expect(rows[0]?.detail).toMatchObject({ context: "ssh_agent", host: "127.0.0.1" });
      },
      30_000,
    );

    it.runIf(process.platform === "win32")(
      "win32 only (the consumer's grant decides): the DACL the server sets for the consumer (BUILTIN\\Users standing in), reduced to the consumer's entry alone, lets the real ssh-add list both keys through the pipe",
      async () => {
        reducedSocket = await AgentSocketServer.start({
          socketPath: socketPath(CONSUMER),
          consumer: CONSUMER,
          engine: vault(),
          onError: (err) => outputs.push(`${err.code}: ${err.message}`),
          win32ConsumerSid: "S-1-5-32-545",
        });
        try {
          expect(keepOnlyEntry(reducedSocket.socketPath, "S-1-5-32-545")).toBe(
            `D:P(A;;0x${WINDOWS_PIPE_CONSUMER_RIGHTS.toString(16)};;;BU)`,
          );
          const r = await runSshAdd(reducedSocket.socketPath);

          expect(r.exit, r.stderr).toBe(0);
          expect(r.stdout).toContain("secret://deploy-ed");
          expect(r.stdout).toContain("secret://deploy-ec");
        } finally {
          await reducedSocket.stop();
        }
      },
      60_000,
    );

    it("no audit row, no ssh output and no onError report carries a private key or a session identifier", () => {
      const trail = JSON.stringify(vault().queryAudit());
      expect(needles.length).toBeGreaterThan(8);
      for (const text of [trail, ...outputs]) {
        for (const needle of needles) expect(text.includes(needle)).toBe(false);
      }
    });
  },
);
