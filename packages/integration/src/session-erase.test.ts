import { existsSync, linkSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it, expect, afterEach } from "vitest";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

/**
 * T11 (second level): the core unit pin covers `SessionManager.eraseSession`
 * directly; this one walks the path an operator takes — unlock writes a
 * session file, `lock()` erases it — and asserts the same property on the
 * bytes that were actually on disk. A hard link keeps the inode reachable
 * after the unlink, so the freed blocks can be read back.
 */

const PASSWORD = "session-erase-test-pw";

let vault: TestVault | undefined;

afterEach(async () => {
  if (vault) await destroyTestVault(vault).catch(() => undefined);
  vault = undefined;
});

describe("session file secure erase (T11)", () => {
  it("lock() leaves no session key material in the freed blocks", async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);

    const before = readFileSync(vault.sessionPath);
    const parsed = JSON.parse(before.toString("utf8")) as {
      session_key: string;
      wrapped_kek: string;
    };
    expect(parsed.session_key.length).toBeGreaterThan(0);

    const alias = join(vault.tmpDir, "session-inode-alias");
    linkSync(vault.sessionPath, alias);

    await vault.engine.lock();

    expect(existsSync(vault.sessionPath)).toBe(false);

    const after = readFileSync(alias);
    expect(after.length).toBe(before.length);
    expect(after.toString("utf8")).not.toContain(parsed.session_key);
    expect(after.toString("utf8")).not.toContain(parsed.wrapped_kek);
    expect(after.equals(before)).toBe(false);
  });
});
