import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_SESSION_TTL_MS,
  ErrorCode,
  SESSION_CLEANUP_INTERVAL_MS,
  VaultState,
  VAULT_VERSION,
  VAULT_VERSION_FLOOR,
} from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import type { VaultEngineOptions } from "./vault-engine.js";
import { SqliteStore } from "./storage/sqlite-store.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

// The session key the engine wraps the live keys with (writeNewSession) and
// unwraps them with (loadSession), kept by reference for the C5 wipe pins.
const sessionKeys = vi.hoisted(() => ({
  wrapping: [] as Uint8Array[],
  unwrapping: [] as Uint8Array[],
}));

vi.mock("./crypto/aes-gcm.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/aes-gcm.js")>();
  const { AAD_SESSION_KEK } = await import("@harpoc/shared");
  return {
    ...original,
    encrypt: (...args: Parameters<typeof original.encrypt>) => {
      if (args[2] === AAD_SESSION_KEK) sessionKeys.wrapping.push(args[0]);
      return original.encrypt(...args);
    },
    decrypt: (...args: Parameters<typeof original.decrypt>) => {
      if (args[4] === AAD_SESSION_KEK) sessionKeys.unwrapping.push(args[0]);
      return original.decrypt(...args);
    },
  };
});

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

describe("vault version guard", () => {
  const setVaultVersion = (version: string): void => {
    const db = new Database(dbPath);
    db.prepare("UPDATE vault_meta SET value = ? WHERE key = 'vault_version'").run(version);
    db.close();
  };

  const expectUnlockCorrupted = async (): Promise<void> => {
    const engine2 = secondEngine({ dbPath, sessionPath });
    try {
      await expectVaultError(() => engine2.unlock("password"), ErrorCode.VAULT_CORRUPTED);
    } finally {
      await engine2.destroy();
    }
  };

  it("refuses a vault stamped with a numerically newer version", async () => {
    await engine.initVault("password");
    await engine.lock();
    const major = parseInt(VAULT_VERSION.split(".")[0] as string, 10);
    setVaultVersion(`${major + 1}.0.0`);
    await expectUnlockCorrupted();
  });

  it("refuses a newer multi-digit minor version", async () => {
    await engine.initVault("password");
    await engine.lock();
    const major = parseInt(VAULT_VERSION.split(".")[0] as string, 10);
    setVaultVersion(`${major}.10.0`);
    await expectUnlockCorrupted();
  });

  it("refuses a malformed stored version (fail closed)", async () => {
    await engine.initVault("password");
    await engine.lock();
    setVaultVersion("banana");
    await expectUnlockCorrupted();
  });

  it("names a malformed stored version as malformed, not as newer", async () => {
    await engine.initVault("password");
    await engine.lock();
    setVaultVersion("banana");

    const engine2 = secondEngine({ dbPath, sessionPath });
    try {
      await expect(engine2.unlock("password")).rejects.toMatchObject({
        code: ErrorCode.VAULT_CORRUPTED,
        message: expect.stringContaining("Vault version banana is not a valid version stamp"),
      });
    } finally {
      await engine2.destroy();
    }
  });

  it.each(["0.9.0", "1.0.0", "1.4.1"])(
    "refuses a vault stamped %s — below the v1.5 floor — naming harpoc init (R2)",
    async (stamp) => {
      await engine.initVault("password");
      await engine.lock();
      setVaultVersion(stamp);

      const engine2 = secondEngine({ dbPath, sessionPath });
      try {
        const err = await expectVaultError(
          () => engine2.unlock("password"),
          ErrorCode.VAULT_CORRUPTED,
        );
        expect(err.message).toBe(
          `Vault corrupted: Vault version ${stamp} predates the supported minimum ${VAULT_VERSION_FLOOR} and cannot be upgraded — move or delete the vault directory and run harpoc init`,
        );
      } finally {
        await engine2.destroy();
      }
    },
  );

  it("opens a vault stamped at the floor by a later 1.5.x binary's ceiling (the floor is not equality)", async () => {
    await engine.initVault("password");
    await engine.lock();
    setVaultVersion(VAULT_VERSION_FLOOR);

    const engine2 = secondEngine({ dbPath, sessionPath });
    await engine2.unlock("password");
    expect(engine2.getState()).toBe(VaultState.UNLOCKED);
    await engine2.destroy();
  });

  it("refuses to unlock a vault whose vault_version row is missing (N2)", async () => {
    await engine.initVault("password");
    await engine.lock();
    const db = new Database(dbPath);
    db.prepare("DELETE FROM vault_meta WHERE key = 'vault_version'").run();
    db.close();
    await expectUnlockCorrupted();
  });
});

describe("the wrapped key hierarchy", () => {
  it("a corrupted wrapped_jwt_key with the correct password refuses VAULT_CORRUPTED and counts no failed attempt", async () => {
    await engine.initVault("password");
    await engine.lock();
    const db = new Database(dbPath);
    const row = db.prepare("SELECT value FROM vault_meta WHERE key = 'wrapped_jwt_key'").get() as {
      value: string;
    };
    const corrupted = (row.value.startsWith("A") ? "B" : "A") + row.value.slice(1);
    db.prepare("UPDATE vault_meta SET value = ? WHERE key = 'wrapped_jwt_key'").run(corrupted);
    db.close();

    const engine2 = secondEngine({ dbPath, sessionPath });
    try {
      await expect(engine2.unlock("password")).rejects.toMatchObject({
        code: ErrorCode.VAULT_CORRUPTED,
      });
    } finally {
      await engine2.destroy();
    }

    const check = new Database(dbPath);
    const attempts = check
      .prepare("SELECT value FROM vault_meta WHERE key = 'failed_attempts'")
      .get() as { value: string } | undefined;
    check.close();
    expect(attempts?.value ?? "0").toBe("0");
  });
});

describe("unlock() store handle on failure paths", () => {
  it("closes the freshly opened store on wrong password", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    const closeSpy = vi.spyOn(SqliteStore.prototype, "close");
    const eng = secondEngine({ dbPath, sessionPath });
    closeSpy.mockClear();
    await expect(eng.unlock("wrong123")).rejects.toMatchObject({
      code: ErrorCode.INVALID_PASSWORD,
    });
    expect(closeSpy).toHaveBeenCalledTimes(1);
    closeSpy.mockRestore();
    await eng.destroy();
  });

  it("closes the freshly opened store when lockout is active", async () => {
    await engine.initVault("correct1");
    await engine.lock();
    for (let i = 0; i < 5; i++) {
      const e = secondEngine({ dbPath, sessionPath });
      await expectVaultError(() => e.unlock("wrong123"), ErrorCode.INVALID_PASSWORD);
      await e.destroy();
    }

    const closeSpy = vi.spyOn(SqliteStore.prototype, "close");
    const eng = secondEngine({ dbPath, sessionPath });
    closeSpy.mockClear();
    await expect(eng.unlock("correct1")).rejects.toMatchObject({
      code: ErrorCode.LOCKOUT_ACTIVE,
    });
    expect(closeSpy).toHaveBeenCalledTimes(1);
    closeSpy.mockRestore();
    await eng.destroy();
  });

  it("closes the freshly opened store on corrupted meta", async () => {
    await engine.initVault("correct1");
    await engine.lock();
    const db = new Database(dbPath);
    db.prepare("DELETE FROM vault_meta WHERE key = 'kdf_salt'").run();
    db.close();

    const closeSpy = vi.spyOn(SqliteStore.prototype, "close");
    const eng = secondEngine({ dbPath, sessionPath });
    closeSpy.mockClear();
    await expectVaultError(() => eng.unlock("correct1"), ErrorCode.VAULT_CORRUPTED);
    expect(closeSpy).toHaveBeenCalledTimes(1);
    closeSpy.mockRestore();
    await eng.destroy();
  });

  it("does not close a live engine's store on a failed re-unlock", async () => {
    await engine.initVault("correct1");

    const closeSpy = vi.spyOn(SqliteStore.prototype, "close");
    closeSpy.mockClear();
    await expect(engine.unlock("wrong123")).rejects.toMatchObject({
      code: ErrorCode.INVALID_PASSWORD,
    });
    expect(closeSpy).not.toHaveBeenCalled();
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
    closeSpy.mockRestore();
  });
});

describe("key-buffer wiping on re-unlock / re-load", () => {
  const allZero = (buf: Uint8Array): boolean => buf.every((b) => b === 0);

  it("wipes the old KEK/JWT/audit buffers when unlock() runs over a live engine", async () => {
    await engine.initVault("password");
    const oldKek = (engine as unknown as { kek: Uint8Array }).kek;
    const oldJwt = (engine as unknown as { jwtKey: Uint8Array }).jwtKey;
    const oldAudit = (engine as unknown as { auditKey: Uint8Array }).auditKey;
    expect(allZero(oldKek)).toBe(false);

    await engine.unlock("password");

    // Old buffers zeroed, and the engine is a working vault afterwards.
    expect(allZero(oldKek)).toBe(true);
    expect(allZero(oldJwt)).toBe(true);
    expect(allZero(oldAudit)).toBe(true);
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
    await engine.createSecret({ name: "still-works", type: "api_key" });
    expect(engine.listSecrets().map((s) => s.name)).toContain("still-works");
  });

  it("wipes the old key buffers when loadSession() runs over a live engine", async () => {
    await engine.initVault("password");
    const oldKek = (engine as unknown as { kek: Uint8Array }).kek;
    expect(allZero(oldKek)).toBe(false);

    const loaded = await engine.loadSession();
    expect(loaded).toBe(true);

    expect(allZero(oldKek)).toBe(true);
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
  });

  it("does not seal a working engine when a re-unlock fails (wrong password)", async () => {
    await engine.initVault("password");
    const kek = (engine as unknown as { kek: Uint8Array }).kek;

    await expectVaultError(() => engine.unlock("wrong-password"), ErrorCode.INVALID_PASSWORD);

    // The live keys survive a failed re-unlock.
    expect(allZero(kek)).toBe(false);
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
  });
});

// C5 (test-review-2026-10-09): every seal path's wipeKeys() call and the
// session key's two wipes, observed on the live buffers.
describe("key-buffer wiping on the seal paths and of the session key (C5)", () => {
  const allZero = (buf: Uint8Array): boolean => buf.every((b) => b === 0);

  function liveKeys(e: VaultEngine): Uint8Array[] {
    const keys = e as unknown as { kek: Uint8Array; jwtKey: Uint8Array; auditKey: Uint8Array };
    return [keys.kek, keys.jwtKey, keys.auditKey];
  }

  afterEach(() => {
    vi.useRealTimers();
  });

  it("lock() wipes the live KEK, JWT key and audit key", async () => {
    await engine.initVault("password");
    const keys = liveKeys(engine);
    expect(keys.map(allZero)).toEqual([false, false, false]);

    await engine.lock();

    expect(keys.map(allZero)).toEqual([true, true, true]);
  });

  it("destroy() wipes the live KEK, JWT key and audit key", async () => {
    await engine.initVault("password");
    const keys = liveKeys(engine);
    expect(keys.map(allZero)).toEqual([false, false, false]);

    await engine.destroy();

    expect(keys.map(allZero)).toEqual([true, true, true]);
  });

  it("the session monitor's expiry seal wipes the live keys (fake timers)", async () => {
    vi.useFakeTimers();
    await engine.initVault("password");
    const keys = liveKeys(engine);
    expect(keys.map(allZero)).toEqual([false, false, false]);

    vi.setSystemTime(Date.now() + DEFAULT_SESSION_TTL_MS + 1);
    await vi.advanceTimersByTimeAsync(SESSION_CLEANUP_INTERVAL_MS);
    await vi.waitFor(() => expect(engine.getState()).toBe(VaultState.SEALED));

    expect(keys.map(allZero)).toEqual([true, true, true]);
  });

  it("the lazy expiry seal on the next operation wipes the live keys", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    await engine.initVault("password");
    const keys = liveKeys(engine);
    expect(keys.map(allZero)).toEqual([false, false, false]);

    vi.setSystemTime(Date.now() + DEFAULT_SESSION_TTL_MS + 1);
    await expectVaultError(() => engine.listSecrets(), ErrorCode.VAULT_LOCKED);

    expect(keys.map(allZero)).toEqual([true, true, true]);
  });

  it("writing a session wipes the session key that wrapped the live keys", async () => {
    sessionKeys.wrapping.length = 0;

    await engine.initVault("password");

    expect(sessionKeys.wrapping).toHaveLength(1);
    expect(sessionKeys.wrapping[0]?.length).toBe(32);
    expect(allZero(sessionKeys.wrapping[0] as Uint8Array)).toBe(true);
  });

  it("loading a session wipes the session key that unwrapped the live keys", async () => {
    await engine.initVault("password");
    sessionKeys.unwrapping.length = 0;

    const loaded = secondEngine({ dbPath, sessionPath });
    expect(await loaded.loadSession()).toBe(true);

    expect(sessionKeys.unwrapping).toHaveLength(1);
    expect(sessionKeys.unwrapping[0]?.length).toBe(32);
    expect(allZero(sessionKeys.unwrapping[0] as Uint8Array)).toBe(true);
    expect(loaded.getState()).toBe(VaultState.UNLOCKED);
  });
});

describe("lifecycle", () => {
  it("starts sealed", () => {
    expect(engine.getState()).toBe(VaultState.SEALED);
  });

  it("initializes and unlocks a new vault", async () => {
    const { vaultId } = await engine.initVault("password");
    expect(vaultId).toBeTruthy();
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
  });

  it("locks and seals", async () => {
    await engine.initVault("password");
    await engine.lock();
    expect(engine.getState()).toBe(VaultState.SEALED);
  });

  it("unlocks an existing vault", async () => {
    await engine.initVault("my-pass1");
    await engine.lock();

    const engine2 = secondEngine({ dbPath, sessionPath });
    await engine2.unlock("my-pass1");
    expect(engine2.getState()).toBe(VaultState.UNLOCKED);
    await engine2.destroy();
  });

  it("rejects wrong password on unlock", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    const engine2 = secondEngine({ dbPath, sessionPath });
    await expectVaultError(() => engine2.unlock("wrong123"), ErrorCode.INVALID_PASSWORD);
    await engine2.destroy();
  });

  it("rejects operations when sealed", async () => {
    await expectVaultError(() => engine.listSecrets(), ErrorCode.VAULT_LOCKED);
  });

  it("loadSession closes store on vault_id mismatch (no handle leak)", async () => {
    await engine.initVault("password");
    // destroy preserves session file, unlike lock which erases it
    await engine.destroy();

    // Tamper session file vault_id
    const raw = readFileSync(sessionPath, "utf-8");
    const session = JSON.parse(raw);
    session.vault_id = "tampered-vault-id";
    writeFileSync(sessionPath, JSON.stringify(session));

    const engine2 = secondEngine({ dbPath, sessionPath });
    const result = await engine2.loadSession();
    expect(result).toBe(false);
    expect(engine2.getState()).toBe(VaultState.SEALED);
    // engine2 should not have a store to close — no leaked handle
    await engine2.destroy();
  });

  it("rejects weak password on initVault", async () => {
    await expectVaultError(() => engine.initVault("short"), ErrorCode.WEAK_PASSWORD);
  });

  it("refuses to re-init an existing vault and preserves its secrets", async () => {
    await engine.initVault("original1");
    await engine.createSecret({
      name: "survivor",
      type: "api_key",
      value: new Uint8Array(Buffer.from("still-here")),
    });
    await engine.lock();

    const engine2 = secondEngine({ dbPath, sessionPath });
    await expectVaultError(() => engine2.initVault("newpass1"), ErrorCode.VAULT_ALREADY_EXISTS);
    expect(engine2.getState()).toBe(VaultState.SEALED);

    await engine2.unlock("original1");
    const value = await engine2.getSecretValue("secret://survivor");
    expect(Buffer.from(value).toString()).toBe("still-here");
    await engine2.destroy();
  });

  it("refuses initVault on an already-unlocked engine", async () => {
    await engine.initVault("original1");
    await expect(engine.initVault("original1")).rejects.toMatchObject({
      code: ErrorCode.VAULT_ALREADY_EXISTS,
    });
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
  });
});

describe("key hierarchy instantiation (thesis §5.3.2)", () => {
  it.each(["wrapped_jwt_key", "wrapped_audit_key"])(
    "refuses to unlock a vault missing %s — no derivation fallback",
    async (prefix) => {
      await engine.initVault("password");
      await engine.destroy();

      const db = new Database(dbPath);
      db.prepare("DELETE FROM vault_meta WHERE key IN (?, ?, ?)").run(
        prefix,
        `${prefix}_iv`,
        `${prefix}_tag`,
      );
      db.close();

      const engine2 = secondEngine({ dbPath, sessionPath });
      try {
        const err = await expectVaultError(
          () => engine2.unlock("password"),
          ErrorCode.VAULT_CORRUPTED,
        );
        expect(err.message).toBe(`Vault corrupted: Missing ${prefix}`);
      } finally {
        await engine2.destroy();
      }
      expect(engine2.getState()).toBe(VaultState.SEALED);
    },
  );
});

describe("destroy() correctness", () => {
  it("sets state to SEALED after destroy", async () => {
    await engine.initVault("password");
    expect(engine.getState()).toBe(VaultState.UNLOCKED);

    await engine.destroy();
    expect(engine.getState()).toBe(VaultState.SEALED);
  });

  it("rejects listSecrets after destroy", async () => {
    await engine.initVault("password");
    await engine.destroy();

    await expectVaultError(() => engine.listSecrets(), ErrorCode.VAULT_LOCKED);
  });

  it("rejects createSecret after destroy", async () => {
    await engine.initVault("password");
    await engine.destroy();

    await expectVaultError(
      () =>
        engine.createSecret({
          name: "fail",
          type: "api_key",
          value: new Uint8Array(Buffer.from("v")),
        }),
      ErrorCode.VAULT_LOCKED,
    );
  });
});

describe("double lock / double destroy edge cases", () => {
  it("lock on sealed vault does not throw", async () => {
    await engine.initVault("password");
    await engine.lock();

    // Second lock should not throw — it's already sealed, auditLogger is null
    await engine.lock();
    expect(engine.getState()).toBe(VaultState.SEALED);
  });

  it("destroy is idempotent", async () => {
    await engine.initVault("password");
    await engine.destroy();
    await engine.destroy();
    expect(engine.getState()).toBe(VaultState.SEALED);
  });
});

// M-T2b-12 (test-review-2026-10-09): a no-toString tripwire for the long-lived
// keys — the live KEK, JWT key and audit key themselves, and any Buffer holding
// the same bytes, throw if stringified while a workflow runs over them.
describe("long-lived key buffers are never stringified (M-T2b-12)", () => {
  it("a workflow over the live keys stringifies none of them", async () => {
    await engine.initVault("password");
    const live = engine as unknown as { kek: Uint8Array; jwtKey: Uint8Array; auditKey: Uint8Array };
    const keys = [live.kek, live.jwtKey, live.auditKey];
    const copies = keys.map((key) => Buffer.from(key));
    const trips: string[] = [];
    const trip = (where: string): never => {
      trips.push(where);
      throw new Error(`tripwire: a long-lived key was stringified (${where})`);
    };
    for (const key of keys) {
      Object.defineProperty(key, "toString", {
        value: () => trip("key.toString"),
        configurable: true,
      });
    }
    const bufferToString = Buffer.prototype.toString;
    const tripwire = vi.spyOn(Buffer.prototype, "toString").mockImplementation(function (
      this: Buffer,
      ...args: unknown[]
    ) {
      if (copies.some((copy) => copy.equals(this))) trip(`Buffer#toString(${String(args[0])})`);
      return bufferToString.apply(this, args as Parameters<Buffer["toString"]>);
    });
    try {
      await engine.createSecret({
        name: "tripwire",
        type: "api_key",
        value: new Uint8Array(Buffer.from("tripwire-value")),
      });
      await engine.getSecretValue("secret://tripwire");
      await engine.rotateSecret("secret://tripwire", new Uint8Array(Buffer.from("tripwire-next")));
      const token = engine.createToken("tripwire-user", ["read"], undefined, {
        principalType: "user",
      });
      engine.verifyToken(token);
      engine.listSecrets();
      engine.queryAudit({});
      engine.verifyAuditChain();
      await engine.lock();
    } finally {
      tripwire.mockRestore();
    }

    expect(trips).toEqual([]);
  });
});
