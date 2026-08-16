import { existsSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { forceFsIsolationUnavailableForTests, requireFsIsolation } from "@harpoc/core";
import type { FsIsolationMechanism } from "@harpoc/core";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { assertTierAvailable } from "./helpers/platform-tiers.js";

/**
 * Filesystem isolation e2e (thesis §4.5.3 layer 4).
 *
 * The real-kernel proof: a credentialed child spawned under an isolation
 * policy must not be able to persist anything — it may read what it needs to
 * run, but a write leaves no file behind — while the identical un-isolated
 * control writes its marker. Linux exercises `setpriv` with a Landlock
 * ruleset, macOS `sandbox-exec` with the deny-write profile — attempt-and-skip
 * on the live probe, so a runner whose util-linux predates the `--landlock-*`
 * options (ubuntu-24.04 ships 2.39) skips visibly instead of failing (the
 * keystore-suite pattern). The refusal path runs everywhere: natively on
 * Windows (the platform genuinely cannot isolate) and via the core force-hook
 * elsewhere.
 */

const PASSWORD = "integration-test-pw";
const SECRET = "sk-fsiso-secret-9f8e7d6c5b";
const NODE = process.execPath;

async function setupVault(fsIsolation: boolean): Promise<{ vault: TestVault; handle: string }> {
  const vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
  const created = await vault.engine.createSecret({
    name: "fsiso-key",
    type: "api_key",
    value: new Uint8Array(Buffer.from(SECRET, "utf8")),
  });
  await vault.engine.setInjectionPolicy(
    created.handle,
    { command_allowlist: [NODE], fs_isolation: fsIsolation },
    { acknowledge_interpreters: true },
  );
  return { vault, handle: created.handle };
}

/**
 * Write `target` and exit 0, or exit 7 when the write is refused. Exactly 7
 * pins BOTH halves the way the network suite's exit code does: the wrapper
 * exec'd the payload in place (a broken wrapper would exit with its own code
 * without ever running the payload) and the write failed inside the
 * ruleset/sandbox rather than the child never starting.
 */
function writeAction(target: string) {
  return {
    type: "process" as const,
    command: NODE,
    args: [
      "-e",
      `try { require("node:fs").writeFileSync(process.argv[1], "ran"); process.exit(0); }` +
        ` catch { process.exit(7); }`,
      target,
    ],
    env_var: "TOKEN",
  };
}

const posixWithIsolation = process.platform === "linux" || process.platform === "darwin";

describe.skipIf(!posixWithIsolation)("filesystem isolation — real kernel (Linux/macOS)", () => {
  let available = false;
  let mechanism: FsIsolationMechanism | null = null;

  beforeAll(async () => {
    let probeError: unknown;
    try {
      const wrap = await requireFsIsolation("/bin/true", []);
      mechanism = wrap.mechanism;
      available = true;
    } catch (err) {
      probeError = err;
      available = false;
    }
    assertTierAvailable("fs-isolation", available, probeError);
  });

  it("control: the un-isolated child writes its marker file", async (ctx) => {
    if (!available) return ctx.skip();
    const { vault, handle } = await setupVault(false);
    const marker = join(vault.tmpDir, "ran.marker");
    try {
      const res = await vault.engine.useSecret(handle, writeAction(marker));
      if (res.type !== "process") throw new Error("expected process result");
      expect(res.exit_code).toBe(0);
      expect(existsSync(marker)).toBe(true);
    } finally {
      await destroyTestVault(vault);
    }
  });

  it("isolated: the credentialed child cannot persist the credential", async (ctx) => {
    if (!available) return ctx.skip();
    const { vault, handle } = await setupVault(true);
    const marker = join(vault.tmpDir, "ran.marker");
    try {
      const res = await vault.engine.useSecret(handle, writeAction(marker));
      if (res.type !== "process") throw new Error("expected process result");
      expect(res.exit_code).toBe(7);
      expect(existsSync(marker)).toBe(false);

      // The spawn is audited as isolated, with the live mechanism.
      const used = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
      const isolated = used.find((e) => e.detail?.fs_isolation === true);
      expect(isolated).toBeDefined();
      expect(["landlock", "sandbox-exec"]).toContain(isolated?.detail?.fs_isolation_mechanism);
    } finally {
      await destroyTestVault(vault);
    }
  });

  it("isolated: /dev/null follows the wrapper's own write grant", async (ctx) => {
    if (!available) return ctx.skip();
    // The two mechanisms carve /dev/null out differently, and both are pinned
    // here rather than one being skipped. Landlock REQUIRES a rule for every
    // handled access class, so `LANDLOCK_PREFIX_ARGS` grants
    // `path-beneath:write-file:/dev/null` explicitly and the write succeeds
    // (verified against a real kernel: debian trixie, util-linux 2.41).
    // `SANDBOX_EXEC_DENY_WRITE_PROFILE` is a blanket `(deny file-write*)` with
    // no allow clause, and Apple's sandbox needs an explicit
    // `(allow file-write* … "/dev/null")` for the device node, so the same
    // write is refused there. Either constant edited to say otherwise trips
    // this test.
    const expected = mechanism === "landlock" ? 0 : 7;
    const { vault, handle } = await setupVault(true);
    try {
      const res = await vault.engine.useSecret(handle, writeAction("/dev/null"));
      if (res.type !== "process") throw new Error("expected process result");
      expect(res.exit_code).toBe(expected);
    } finally {
      await destroyTestVault(vault);
    }
  });
});

describe("filesystem isolation — fail-closed refusal", () => {
  // Windows exercises the real unsupported-platform path; elsewhere the
  // force-hook stands in (only unavailability can be forced — tightening).
  beforeEach(() => {
    if (process.platform !== "win32") {
      forceFsIsolationUnavailableForTests("forced for integration test");
    }
  });

  afterEach(() => {
    forceFsIsolationUnavailableForTests(null);
  });

  it("refuses the use, spawns nothing, and audits the denial", async () => {
    const { vault, handle } = await setupVault(true);
    const marker = join(vault.tmpDir, "ran.marker");
    try {
      await expect(vault.engine.useSecret(handle, writeAction(marker))).rejects.toMatchObject({
        code: ErrorCode.FS_ISOLATION_UNAVAILABLE,
      });

      // No process ever ran — fail closed means refused before the spawn.
      expect(existsSync(marker)).toBe(false);

      const used = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
      expect(used.some((e) => e.detail?.error === "FS_ISOLATION_UNAVAILABLE")).toBe(true);
    } finally {
      await destroyTestVault(vault);
    }
  });

  it("control: a secret without the flag still executes on the same platform", async () => {
    const { vault, handle } = await setupVault(false);
    const marker = join(vault.tmpDir, "ran.marker");
    try {
      const res = await vault.engine.useSecret(handle, writeAction(marker));
      if (res.type !== "process") throw new Error("expected process result");
      expect(res.exit_code).toBe(0);
      expect(existsSync(marker)).toBe(true);
    } finally {
      await destroyTestVault(vault);
    }
  });
});
