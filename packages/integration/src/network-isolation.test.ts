import { generateKeyPairSync } from "node:crypto";
import { existsSync } from "node:fs";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { createServer as createTcpServer } from "node:net";
import type { Server as TcpServer } from "node:net";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode, VaultError } from "@harpoc/shared";
import type { UseSecretAction } from "@harpoc/shared";
import {
  controlledPathDirs,
  forceNetworkIsolationUnavailableForTests,
  requireNetworkIsolation,
  resolveExecutable,
} from "@harpoc/core";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { assertTierAvailable, tierRequired } from "./helpers/platform-tiers.js";

/**
 * Network isolation e2e (thesis §4.5.3 layer 4).
 *
 * The real-kernel proof: a credentialed child spawned under an isolation
 * policy must not reach even a loopback listener (D5 — loopback stays
 * blocked), while the identical un-isolated control does. Linux exercises
 * `unshare -rn` (or the bwrap tier behind it, whose fresh namespace carries an
 * empty loopback of its own — the connect is refused instead of unreachable,
 * exit 7 either way), macOS `sandbox-exec` — attempt-and-skip on the live probe,
 * so a runner with restricted user namespaces skips visibly instead of
 * failing (the keystore-suite pattern). The refusal path runs everywhere:
 * natively on Windows (the platform genuinely cannot isolate) and via the
 * core force-hook elsewhere.
 */

const PASSWORD = "integration-test-pw";
const SECRET = "sk-netiso-secret-1a2b3c4d5e";
const NODE = process.execPath;

async function setupVault(
  networkIsolation: boolean,
): Promise<{ vault: TestVault; handle: string }> {
  const vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
  const created = await vault.engine.createSecret({
    name: "netiso-key",
    type: "api_key",
    value: new Uint8Array(Buffer.from(SECRET, "utf8")),
  });
  await vault.engine.setInjectionPolicy(
    created.handle,
    { command_allowlist: [NODE], network_isolation: networkIsolation },
    { acknowledge_interpreters: true },
  );
  return { vault, handle: created.handle };
}

function fetchAction(port: number) {
  return {
    type: "process" as const,
    command: NODE,
    args: [
      "-e",
      `fetch("http://127.0.0.1:${port}/ping", { signal: AbortSignal.timeout(5000) })` +
        `.then(() => process.exit(0), () => process.exit(7))`,
    ],
    env_var: "TOKEN",
  };
}

const posixWithIsolation = process.platform === "linux" || process.platform === "darwin";

describe.skipIf(!posixWithIsolation)("network isolation — real kernel (Linux/macOS)", () => {
  let server: Server;
  let port: number;
  let hits = 0;
  let available = false;

  beforeAll(async () => {
    let probeError: unknown;
    try {
      await requireNetworkIsolation("/bin/true", []);
      available = true;
    } catch (err) {
      probeError = err;
      available = false;
    }
    assertTierAvailable("isolation", available, probeError);
    server = createServer((_req, res) => {
      hits++;
      res.writeHead(200);
      res.end("pong");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    if (addr === null || typeof addr === "string") throw new Error("no port");
    port = addr.port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  beforeEach(() => {
    hits = 0;
  });

  it("control: the un-isolated child reaches the loopback listener", async (ctx) => {
    if (!available) return ctx.skip();
    const { vault, handle } = await setupVault(false);
    try {
      const res = await vault.engine.useSecret(handle, fetchAction(port));
      if (res.type !== "process") throw new Error("expected process result");
      expect(res.exit_code).toBe(0);
      expect(hits).toBe(1);
    } finally {
      await destroyTestVault(vault);
    }
  });

  it("isolated: the credentialed child cannot reach even loopback (D5)", async (ctx) => {
    if (!available) return ctx.skip();
    const { vault, handle } = await setupVault(true);
    try {
      const res = await vault.engine.useSecret(handle, fetchAction(port));
      if (res.type !== "process") throw new Error("expected process result");
      // Exactly 7 pins BOTH halves: the wrapper ran the payload and returned
      // its status (exec in place for unshare and sandbox-exec, a monitor for
      // bwrap — a broken wrapper would exit with its own code without ever
      // running the payload), and the connect failed inside the namespace
      // rather than the child never starting.
      expect(res.exit_code).toBe(7);
      expect(hits).toBe(0);

      // The spawn is audited as isolated, with the live mechanism.
      const used = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
      const isolated = used.find((e) => e.detail?.network_isolation === true);
      expect(isolated).toBeDefined();
      expect(["unshare", "sandbox-exec", "bwrap"]).toContain(isolated?.detail?.isolation_mechanism);
    } finally {
      await destroyTestVault(vault);
    }
  });
});

// M-P2-20 (test-review-2026-10-09): git, ssh and sftp spawn their own clients
// through the same seam, and under network_isolation that client must not
// reach a loopback listener the identical un-isolated action does reach. The
// listener accepts and closes, so the control fails on the protocol (git: an
// empty reply; ssh and sftp: the banner exchange cut) and the isolated client
// on the kernel: told apart by the listener's connection count, the client's
// own connect-failure line and the row's isolation posture — every row carries
// the policy's flags (sftp's since 2026-10-14); git's and ssh's result rows the
// mechanism too, while sftp's connect refusal is thrown after the spawn, so its
// row is the engine's refusal row: the flags, no mechanism, and the error
// SSH_CONNECT_FAILED either way.
const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveExecutable("ssh", controlledPathDirs());
const SFTP = resolveExecutable("sftp", controlledPathDirs());

interface IsolationCell {
  context: "git" | "ssh" | "sftp";
  action: (port: number, dir: string) => UseSecretAction;
  /** The `error` both halves carry: the result's for git and ssh, the refusal's for sftp. */
  error: string | undefined;
  /** The line the client prints when its own connect is refused; null where nothing surfaces it. */
  refused: RegExp | null;
}

const CELLS: IsolationCell[] = [
  {
    context: "git",
    action: (port, dir) => ({
      type: "git",
      operation: "clone",
      repository: `http://127.0.0.1:${String(port)}/repo.git`,
      working_directory: join(dir, "clone"),
      timeout_ms: 20_000,
    }),
    error: undefined,
    refused: /Failed to connect to 127\.0\.0\.1 port \d+/,
  },
  {
    context: "ssh",
    action: (port) => ({
      type: "ssh",
      host: "127.0.0.1",
      port,
      user: "deploy",
      command: "true",
      timeout_ms: 20_000,
    }),
    error: ErrorCode.SSH_CONNECT_FAILED,
    refused: /connect to host 127\.0\.0\.1 port \d+/,
  },
  {
    context: "sftp",
    action: (port, dir) => ({
      type: "sftp",
      host: "127.0.0.1",
      port,
      user: "deploy",
      operation: "download",
      remote_path: "/srv/report.txt",
      local_path: join(dir, "report.txt"),
      timeout_ms: 20_000,
    }),
    error: ErrorCode.SSH_CONNECT_FAILED,
    refused: null,
  },
];

describe.skipIf(!posixWithIsolation)(
  "network isolation — real kernel, git / ssh / sftp (M-P2-20)",
  () => {
    let listener: TcpServer;
    let port: number;
    let connections = 0;
    let available = false;

    beforeAll(async () => {
      let probeError: unknown;
      try {
        await requireNetworkIsolation("/bin/true", []);
        available = true;
      } catch (err) {
        probeError = err;
        available = false;
      }
      assertTierAvailable("isolation", available, probeError);
      // Every leg that exports the ssh-live tier ships the three clients.
      if ((GIT === null || SSH === null || SFTP === null) && tierRequired("ssh-live")) {
        throw new Error(
          'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but git, ssh or sftp is unresolvable',
        );
      }
      listener = createTcpServer((socket) => {
        connections++;
        socket.destroy();
      });
      await new Promise<void>((resolve, reject) => {
        listener.once("error", reject);
        listener.listen(0, "127.0.0.1", resolve);
      });
      const addr = listener.address();
      if (addr === null || typeof addr === "string") throw new Error("no port");
      port = addr.port;
    });

    afterAll(async () => {
      if (listener !== undefined)
        await new Promise<void>((resolve) => listener.close(() => resolve()));
    });

    beforeEach(() => {
      connections = 0;
    });

    /** A vault whose one secret — an SSH private key — may drive all three clients at the listener. */
    async function clientVault(
      networkIsolation: boolean,
    ): Promise<{ vault: TestVault; handle: string; keyLine: string }> {
      const vault = createTestVault();
      await vault.engine.initVault(PASSWORD);
      const { privateKey } = generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { type: "pkcs1", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      });
      const created = await vault.engine.createSecret({
        name: "netiso-client-key",
        type: "api_key",
        value: new Uint8Array(Buffer.from(privateKey, "utf8")),
      });
      await vault.engine.setInjectionPolicy(created.handle, {
        url_allowlist: [`http://127.0.0.1:${String(port)}/*`],
        command_allowlist: [GIT as string, SSH as string, SFTP as string],
        host_allowlist: ["127.0.0.1"],
        network_isolation: networkIsolation,
      });
      await vault.engine.setConnectionConfig(created.handle, {
        ssh: { known_hosts: ["127.0.0.1 ssh-ed25519 AAAA"] },
      });
      return { vault, handle: created.handle, keyLine: privateKey.split("\n")[1] as string };
    }

    /** The use's `error` and stderr, whether the context returns its failure or throws it. */
    async function attempt(
      vault: TestVault,
      handle: string,
      action: UseSecretAction,
    ): Promise<{ error: string | undefined; stderr: string }> {
      try {
        const res = await vault.engine.useSecret(handle, action);
        return {
          error: "error" in res ? res.error : undefined,
          stderr: "stderr" in res ? res.stderr : "",
        };
      } catch (err) {
        if (!(err instanceof VaultError)) throw err;
        return { error: err.code, stderr: "" };
      }
    }

    it.for(CELLS.map((cell) => [cell.context, cell] as const))(
      "%s control: the un-isolated client reaches the loopback listener",
      async ([, cell], ctx) => {
        if (!available || GIT === null || SSH === null || SFTP === null)
          return ctx.skip("isolation unavailable, or git / ssh / sftp unresolvable");
        const { vault, handle, keyLine } = await clientVault(false);
        try {
          const outcome = await attempt(vault, handle, cell.action(port, vault.tmpDir));
          expect(connections).toBeGreaterThan(0);
          expect(outcome.error).toBe(cell.error);
          if (cell.refused !== null) expect(outcome.stderr).not.toMatch(cell.refused);
          expect(outcome.stderr).not.toContain(keyLine);
          const [row] = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE, limit: 1 });
          expect(row?.detail).toMatchObject({ context: cell.context, network_isolation: false });
          if (cell.context === "sftp")
            expect(row?.detail).toMatchObject({ error: ErrorCode.SSH_CONNECT_FAILED });
          expect(row?.detail?.isolation_mechanism).toBeUndefined();
        } finally {
          await destroyTestVault(vault);
        }
      },
    );

    it.for(CELLS.map((cell) => [cell.context, cell] as const))(
      "%s isolated: the kernel refuses the client's connect",
      async ([, cell], ctx) => {
        if (!available || GIT === null || SSH === null || SFTP === null)
          return ctx.skip("isolation unavailable, or git / ssh / sftp unresolvable");
        const { vault, handle, keyLine } = await clientVault(true);
        try {
          const outcome = await attempt(vault, handle, cell.action(port, vault.tmpDir));
          expect(connections).toBe(0);
          expect(outcome.error).toBe(cell.error);
          if (cell.refused !== null) expect(outcome.stderr).toMatch(cell.refused);
          expect(outcome.stderr).not.toContain(keyLine);
          const [row] = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE, limit: 1 });
          expect(row?.detail).toMatchObject({ context: cell.context, network_isolation: true });
          if (cell.context === "sftp") {
            expect(row?.detail).toMatchObject({ error: ErrorCode.SSH_CONNECT_FAILED });
            expect(row?.detail?.isolation_mechanism).toBeUndefined();
          } else {
            expect(["unshare", "sandbox-exec", "bwrap"]).toContain(
              row?.detail?.isolation_mechanism,
            );
          }
        } finally {
          await destroyTestVault(vault);
        }
      },
    );
  },
);

describe("network isolation — fail-closed refusal", () => {
  // Windows exercises the real unsupported-platform path; elsewhere the
  // force-hook stands in (only unavailability can be forced — tightening).
  beforeEach(() => {
    if (process.platform !== "win32") {
      forceNetworkIsolationUnavailableForTests("forced for integration test");
    }
  });

  afterEach(() => {
    forceNetworkIsolationUnavailableForTests(null);
  });

  it("refuses the use, spawns nothing, and audits the denial", async () => {
    const { vault, handle } = await setupVault(true);
    const marker = join(vault.tmpDir, "ran.marker");
    try {
      await expect(
        vault.engine.useSecret(handle, {
          type: "process",
          command: NODE,
          args: ["-e", `require("node:fs").writeFileSync(process.argv[1], "ran")`, marker],
          env_var: "TOKEN",
        }),
      ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });

      // No process ever ran — fail closed means refused before the spawn.
      expect(existsSync(marker)).toBe(false);

      const used = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
      expect(used.some((e) => e.detail?.error === "NETWORK_ISOLATION_UNAVAILABLE")).toBe(true);
    } finally {
      await destroyTestVault(vault);
    }
  });

  it("control: a secret without the flag still executes on the same platform", async () => {
    const { vault, handle } = await setupVault(false);
    const marker = join(vault.tmpDir, "ran.marker");
    try {
      const res = await vault.engine.useSecret(handle, {
        type: "process",
        command: NODE,
        args: ["-e", `require("node:fs").writeFileSync(process.argv[1], "ran")`, marker],
        env_var: "TOKEN",
      });
      if (res.type !== "process") throw new Error("expected process result");
      expect(res.exit_code).toBe(0);
      expect(existsSync(marker)).toBe(true);
    } finally {
      await destroyTestVault(vault);
    }
  });
});
