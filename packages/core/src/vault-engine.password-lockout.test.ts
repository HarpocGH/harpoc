import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, VaultState } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import type { VaultEngineOptions } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-ve-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
});

// Every engine a case opens beside `engine` is destroyed here, on the failure
// path too, before its directory is removed (an open store is EBUSY on win32).
const secondEngines: VaultEngine[] = [];
function secondEngine(options: VaultEngineOptions): VaultEngine {
  const opened = new VaultEngine(options);
  secondEngines.push(opened);
  return opened;
}

afterEach(async () => {
  for (const opened of secondEngines.splice(0)) await opened.destroy();
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("password change", () => {
  it("changes password and re-unlocks with new password", async () => {
    await engine.initVault("old-pass1");
    await engine.createSecret({
      name: "keep",
      type: "api_key",
      value: new Uint8Array(Buffer.from("secret-val")),
    });

    await engine.changePassword("old-pass1", "new-pass1");
    await engine.lock();

    const engine2 = secondEngine({ dbPath, sessionPath });
    await engine2.unlock("new-pass1");

    const value = await engine2.getSecretValue("secret://keep");
    expect(Buffer.from(value).toString()).toBe("secret-val");

    await engine2.destroy();
  });

  it("rejects change with wrong old password as INVALID_PASSWORD", async () => {
    await engine.initVault("correct-pass");

    await expectVaultError(
      () => engine.changePassword("wrong-pass", "new-pass1"),
      ErrorCode.INVALID_PASSWORD,
    );
  });

  it("wrong-old-password changePassword feeds the shared lockout counter", async () => {
    await engine.initVault("correct-pass");

    // 5 wrong changePassword attempts trip the lockout (same counter as unlock).
    for (let i = 0; i < 5; i++) {
      await expect(engine.changePassword("wrong-pass", "new-pass1")).rejects.toMatchObject({
        code: ErrorCode.INVALID_PASSWORD,
      });
    }

    await expect(engine.changePassword("wrong-pass", "new-pass1")).rejects.toMatchObject({
      code: ErrorCode.LOCKOUT_ACTIVE,
    });
  });

  it("changePassword and unlock share one lockout counter", async () => {
    await engine.initVault("correct-pass");

    // 3 wrong changePassword attempts + 2 wrong unlock attempts = 5 → lockout.
    for (let i = 0; i < 3; i++) {
      await expect(engine.changePassword("wrong", "new-pass1")).rejects.toMatchObject({
        code: ErrorCode.INVALID_PASSWORD,
      });
    }
    for (let i = 0; i < 2; i++) {
      await expect(engine.unlock("wrong")).rejects.toMatchObject({
        code: ErrorCode.INVALID_PASSWORD,
      });
    }

    await expect(engine.unlock("correct-pass")).rejects.toMatchObject({
      code: ErrorCode.LOCKOUT_ACTIVE,
    });
  });

  it("successful changePassword resets the lockout counter and leaves data intact", async () => {
    await engine.initVault("correct-pass");
    await engine.createSecret({
      name: "keep",
      type: "api_key",
      value: new Uint8Array(Buffer.from("secret-val")),
    });

    // A few wrong attempts, then a correct change.
    for (let i = 0; i < 3; i++) {
      await expectVaultError(
        () => engine.changePassword("wrong", "new-pass1"),
        ErrorCode.INVALID_PASSWORD,
      );
    }
    // Data survived the failed attempts (wrapped KEK untouched).
    const before = await engine.getSecretValue("secret://keep");
    expect(Buffer.from(before).toString()).toBe("secret-val");

    await engine.changePassword("correct-pass", "new-pass1");

    // Counter reset: 4 wrong unlocks after the reset must NOT lock out.
    await engine.lock();
    for (let i = 0; i < 4; i++) {
      const eng = secondEngine({ dbPath, sessionPath });
      await expect(eng.unlock("still-wrong")).rejects.toMatchObject({
        code: ErrorCode.INVALID_PASSWORD,
      });
      await eng.destroy();
    }
  });

  it("audits a wrong-old-password changePassword as success:false", async () => {
    await engine.initVault("correct-pass");
    await expectVaultError(
      () => engine.changePassword("wrong-pass", "new-pass1"),
      ErrorCode.INVALID_PASSWORD,
    );

    const events = engine.queryAudit();
    const denied = events.find(
      (e) => e.event_type === AuditEventType.VAULT_PASSWORD_CHANGE && e.success === false,
    );
    expect(denied).toMatchObject({
      success: false,
      secret_id: null,
      principal_type: null,
      detail: { error: ErrorCode.INVALID_PASSWORD },
    });
  });

  it("old password no longer works after change", async () => {
    await engine.initVault("old-pass1");
    await engine.changePassword("old-pass1", "new-pass1");
    await engine.lock();

    const engine2 = secondEngine({ dbPath, sessionPath });
    await expectVaultError(() => engine2.unlock("old-pass1"), ErrorCode.INVALID_PASSWORD);
    await engine2.destroy();
  });

  it("rejects weak new password on changePassword", async () => {
    await engine.initVault("password");

    await expectVaultError(
      () => engine.changePassword("password", "short"),
      ErrorCode.WEAK_PASSWORD,
    );
  });
});

describe("lockout mechanism", () => {
  it("triggers lockout after 5 failed unlock attempts", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    for (let i = 0; i < 5; i++) {
      const eng = secondEngine({ dbPath, sessionPath });
      try {
        await eng.unlock("wrong123");
      } catch {
        // Expected INVALID_PASSWORD
      }
      await eng.destroy();
    }

    // 6th attempt should hit lockout
    const eng = secondEngine({ dbPath, sessionPath });
    await expectVaultError(() => eng.unlock("wrong123"), ErrorCode.LOCKOUT_ACTIVE);
    await eng.destroy();
  });

  it("lockout rejects even the correct password", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    for (let i = 0; i < 5; i++) {
      const eng = secondEngine({ dbPath, sessionPath });
      try {
        await eng.unlock("wrong123");
      } catch {
        // Expected
      }
      await eng.destroy();
    }

    // Correct password during lockout should also fail
    const eng = secondEngine({ dbPath, sessionPath });
    await expectVaultError(() => eng.unlock("correct1"), ErrorCode.LOCKOUT_ACTIVE);
    await eng.destroy();
  });

  it("resets failed attempt counter on successful unlock", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    // 4 failed attempts (just below threshold)
    for (let i = 0; i < 4; i++) {
      const eng = secondEngine({ dbPath, sessionPath });
      try {
        await eng.unlock("wrong123");
      } catch {
        // Expected
      }
      await eng.destroy();
    }

    // Successful unlock resets counter
    const eng = secondEngine({ dbPath, sessionPath });
    await eng.unlock("correct1");
    await eng.lock();
    await eng.destroy();

    // 4 more failed attempts should NOT trigger lockout (counter was reset)
    for (let i = 0; i < 4; i++) {
      const eng2 = secondEngine({ dbPath, sessionPath });
      try {
        await eng2.unlock("wrong123");
      } catch {
        // Expected
      }
      await eng2.destroy();
    }

    // 5th attempt should still succeed (total 4 since reset)
    const eng3 = secondEngine({ dbPath, sessionPath });
    try {
      await eng3.unlock("correct1");
      expect(eng3.getState()).toBe(VaultState.UNLOCKED);
    } finally {
      await eng3.destroy();
    }
  });
});
