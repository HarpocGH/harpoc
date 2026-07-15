import { existsSync } from "node:fs";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { forceNetworkIsolationUnavailableForTests, requireNetworkIsolation } from "@harpoc/core";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

/**
 * Network isolation e2e (thesis §4.5.3 layer 4).
 *
 * The real-kernel proof: a credentialed child spawned under an isolation
 * policy must not reach even a loopback listener (D5 — loopback stays
 * blocked), while the identical un-isolated control does. Linux exercises
 * `unshare -rn`, macOS `sandbox-exec` — attempt-and-skip on the live probe,
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
    try {
      await requireNetworkIsolation("/bin/true", []);
      available = true;
    } catch {
      available = false;
    }
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
      // The fetch failed inside the namespace/sandbox — the child ran (the
      // wrapper exec'd it) but its socket never reached the listener.
      expect(res.exit_code).not.toBe(0);
      expect(hits).toBe(0);

      // The spawn is audited as isolated, with the live mechanism.
      const used = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
      const isolated = used.find((e) => e.detail?.network_isolation === true);
      expect(isolated).toBeDefined();
      expect(["unshare", "sandbox-exec"]).toContain(isolated?.detail?.isolation_mechanism);
    } finally {
      await destroyTestVault(vault);
    }
  });
});

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
