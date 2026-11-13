import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext } from "@harpoc/shared";
import { AuditEventType, ErrorCode, VaultState } from "@harpoc/shared";
import type { DecryptedAuditEvent } from "./audit/audit-query.js";
import { VaultEngine } from "./vault-engine.js";
import type { VaultEngineOptions } from "./vault-engine.js";
import type { SessionKeyProtector } from "./session/session-key-protector.js";
import { SqliteStore } from "./storage/sqlite-store.js";
import { nonReadAuditCount } from "./__fixtures__/engine-seams.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

// Every unlock key the engine draws, kept by reference, so a case can watch
// the engine wipe a key it never handed out.
const drawnKeys = vi.hoisted(() => [] as Uint8Array[]);

vi.mock("./crypto/key-hierarchy.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/key-hierarchy.js")>();
  return {
    ...original,
    wrapKekWithUnlockKey: (...args: Parameters<typeof original.wrapKekWithUnlockKey>) => {
      const slot = original.wrapKekWithUnlockKey(...args);
      drawnKeys.push(slot.unlockKey);
      return slot;
    },
  };
});

const PASSWORD = "unlock-key-pass";
const SLOT_ROWS = [
  "wrapped_kek_uk",
  "wrapped_kek_uk_iv",
  "wrapped_kek_uk_tag",
  "unlock_key_enrolled_at",
];
const INJECTED = new Error("injected write failure");

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-uk-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
  drawnKeys.length = 0;
});

// Every engine a case opens beside `engine` is destroyed here, on the failure
// path too, before its directory is removed (an open store is EBUSY on win32).
const secondEngines: VaultEngine[] = [];
function secondEngine(options: VaultEngineOptions = { dbPath, sessionPath }): VaultEngine {
  const opened = new VaultEngine(options);
  secondEngines.push(opened);
  return opened;
}

afterEach(async () => {
  vi.restoreAllMocks();
  for (const opened of secondEngines.splice(0)) await opened.destroy();
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function readMeta(key: string): string | undefined {
  const store = new SqliteStore(dbPath);
  try {
    return store.getMeta(key);
  } finally {
    store.close();
  }
}

function rowsOf(reader: VaultEngine, eventType: AuditEventType): DecryptedAuditEvent[] {
  return reader.queryAudit({ eventType });
}

function statusReads(reader: VaultEngine): DecryptedAuditEvent[] {
  return rowsOf(reader, AuditEventType.VAULT_READ).filter(
    (row) => row.detail?.operation === "unlock_key_status",
  );
}

function liveStore(of: VaultEngine): SqliteStore {
  return (of as unknown as { store: SqliteStore }).store;
}

function failNextAuditInsert(of: VaultEngine): void {
  vi.spyOn(liveStore(of), "insertAuditEvent").mockImplementationOnce(() => {
    throw INJECTED;
  });
}

function failOnMetaKey(key: string): void {
  const original = SqliteStore.prototype.setMeta;
  vi.spyOn(SqliteStore.prototype, "setMeta").mockImplementation(function (
    this: SqliteStore,
    metaKey: string,
    value: string,
  ) {
    if (metaKey === key) throw INJECTED;
    original.call(this, metaKey, value);
  });
}

const allZero = (buf: Uint8Array): boolean => buf.every((b) => b === 0);
const wrongKey = (): Uint8Array => new Uint8Array(randomBytes(32));

/** A vault with an enrolled slot; `engine` stays unlocked by password. */
async function enrolledVault(): Promise<Uint8Array> {
  await engine.initVault(PASSWORD);
  return engine.enrollUnlockKey();
}

describe("enrolment (enrollUnlockKey, unlockKeyStatus)", () => {
  it("returns a fresh 32-byte key and writes the slot's four rows, none of them the key", async () => {
    const key = await enrolledVault();

    expect(key instanceof Uint8Array).toBe(true);
    expect(key.length).toBe(32);
    expect(allZero(key)).toBe(false);
    const values = SLOT_ROWS.map(readMeta);
    expect(values.every((value) => typeof value === "string" && value.length > 0)).toBe(true);
    expect(values.includes(Buffer.from(key).toString("base64"))).toBe(false);
  });

  it("unlockKeyStatus reports no slot, the slot with its enrolment time, then none after revoke — one vault.read row a read and no other", async () => {
    await engine.initVault(PASSWORD);
    expect(await engine.unlockKeyStatus()).toEqual({ enrolled: false });

    const before = new Date().toISOString();
    await engine.enrollUnlockKey();
    const after = new Date().toISOString();

    const rows = nonReadAuditCount(engine);
    const status = await engine.unlockKeyStatus();
    expect(nonReadAuditCount(engine)).toBe(rows);
    expect(status.enrolled).toBe(true);
    const enrolledAt = status.enrolledAt as string;
    expect(enrolledAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(enrolledAt >= before && enrolledAt <= after).toBe(true);
    expect(enrolledAt).toBe(readMeta("unlock_key_enrolled_at"));

    await engine.revokeUnlockKey();
    expect(await engine.unlockKeyStatus()).toEqual({ enrolled: false });
    expect(statusReads(engine)).toHaveLength(3);
  });

  it("writes one vault.unlock_key.enroll row per enrolment — replaced false, then true — and a replaced key stops unlocking", async () => {
    const first = await enrolledVault();
    const second = await engine.enrollUnlockKey();

    const rows = rowsOf(engine, AuditEventType.VAULT_UNLOCK_KEY_ENROLL);
    expect(rows.map((row) => row.detail)).toEqual([{ replaced: true }, { replaced: false }]);
    for (const row of rows) {
      expect(row).toMatchObject({
        success: true,
        secret_id: null,
        principal_type: null,
        principal_id: null,
        session_id: expect.any(String),
      });
    }

    await engine.lock();
    // The replaced key is a wrong key now, and counts as one.
    await expectVaultError(() => secondEngine().unlockWithKey(first), ErrorCode.INVALID_UNLOCK_KEY);
    expect(readMeta("failed_attempts")).toBe("1");
    const reopened = secondEngine();
    await reopened.unlockWithKey(second);
    expect(reopened.getState()).toBe(VaultState.UNLOCKED);
  });

  it("an engine unlocked from the session file reads the status but cannot enrol or revoke — UNLOCK_KEY_PASSWORD_REQUIRED, one failed row each", async () => {
    await engine.initVault(PASSWORD);
    const loaded = secondEngine();
    expect(await loaded.loadSession()).toBe(true);

    expect(await loaded.unlockKeyStatus()).toEqual({ enrolled: false });
    await expectVaultError(() => loaded.enrollUnlockKey(), ErrorCode.UNLOCK_KEY_PASSWORD_REQUIRED);
    await expectVaultError(() => loaded.revokeUnlockKey(), ErrorCode.UNLOCK_KEY_PASSWORD_REQUIRED);

    expect(readMeta("wrapped_kek_uk")).toBeUndefined();
    expect(drawnKeys.length).toBe(0);
    for (const eventType of [
      AuditEventType.VAULT_UNLOCK_KEY_ENROLL,
      AuditEventType.VAULT_UNLOCK_KEY_REVOKE,
    ]) {
      expect(rowsOf(loaded, eventType)).toEqual([
        expect.objectContaining({
          success: false,
          detail: { error: ErrorCode.UNLOCK_KEY_PASSWORD_REQUIRED },
        }),
      ]);
    }

    // The password engine loses the right when it re-loads from the session file.
    expect(await engine.loadSession()).toBe(true);
    await expectVaultError(() => engine.enrollUnlockKey(), ErrorCode.UNLOCK_KEY_PASSWORD_REQUIRED);
  });

  it("an engine unlocked by the unlock key cannot enrol or revoke until it unlocks by password", async () => {
    const key = await enrolledVault();
    await engine.lock();
    const viaKey = secondEngine();
    await viaKey.unlockWithKey(key);

    await expectVaultError(() => viaKey.enrollUnlockKey(), ErrorCode.UNLOCK_KEY_PASSWORD_REQUIRED);
    await expectVaultError(() => viaKey.revokeUnlockKey(), ErrorCode.UNLOCK_KEY_PASSWORD_REQUIRED);
    expect(readMeta("wrapped_kek_uk")).toBeDefined();
    expect(drawnKeys.length).toBe(1);

    await viaKey.unlock(PASSWORD);
    await viaKey.revokeUnlockKey();
    expect(readMeta("wrapped_kek_uk")).toBeUndefined();
  });

  it("a sealed engine refuses the three administration calls with VAULT_LOCKED", async () => {
    await engine.initVault(PASSWORD);
    await engine.lock();

    await expectVaultError(() => engine.enrollUnlockKey(), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => engine.revokeUnlockKey(), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => engine.unlockKeyStatus(), ErrorCode.VAULT_LOCKED);
  });
});

describe("unlockKeyStatus' vault.read row (A5)", () => {
  const OPERATOR: CallerContext = {
    principal_type: "user",
    principal_id: "operator",
    interface: "cli",
  };

  it("the trusted path: one row after the read — NULL principal columns, no interface key, no enrolment time — and the answer unchanged", async () => {
    await engine.initVault(PASSWORD);
    await engine.enrollUnlockKey();
    const before = nonReadAuditCount(engine);

    const status = await engine.unlockKeyStatus();

    expect(status).toEqual({ enrolled: true, enrolledAt: readMeta("unlock_key_enrolled_at") });
    expect(nonReadAuditCount(engine)).toBe(before);
    const reads = statusReads(engine);
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({
      event_type: AuditEventType.VAULT_READ,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      success: true,
      session_id: expect.any(String),
    });
    expect(reads[0]?.detail).toEqual({ operation: "unlock_key_status" });
    expect(JSON.stringify(reads[0]?.detail).includes(status.enrolledAt as string)).toBe(false);
  });

  it("with a caller: the caller's principal and interface on the row", async () => {
    await engine.initVault(PASSWORD);

    expect(await engine.unlockKeyStatus(OPERATOR)).toEqual({ enrolled: false });

    expect(
      statusReads(engine).map((row) => [row.principal_type, row.principal_id, row.detail]),
    ).toEqual([["user", "operator", { operation: "unlock_key_status", interface: "cli" }]]);
  });

  it("throws the logger's error and answers nothing when its row cannot be written", async () => {
    await engine.initVault(PASSWORD);
    await engine.enrollUnlockKey();
    failNextAuditInsert(engine);

    await expect(engine.unlockKeyStatus()).rejects.toBe(INJECTED);
    vi.restoreAllMocks();

    expect(statusReads(engine)).toEqual([]);
  });
});

describe("unlockWithKey", () => {
  it("unlocks a fresh engine from the key alone; its vault.unlock row carries detail.method credential", async () => {
    const key = await enrolledVault();
    await engine.createSecret({
      name: "kept",
      type: "api_key",
      value: new Uint8Array(Buffer.from("kept-value")),
    });
    await engine.lock();

    const viaKey = secondEngine();
    await viaKey.unlockWithKey(key);

    expect(viaKey.getState()).toBe(VaultState.UNLOCKED);
    expect(Buffer.from(await viaKey.getSecretValue("secret://kept")).toString()).toBe("kept-value");
    const [row] = rowsOf(viaKey, AuditEventType.VAULT_UNLOCK);
    expect(row).toMatchObject({
      success: true,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      session_id: expect.any(String),
    });
    expect(row?.detail).toEqual({ method: "credential" });
  });

  it("a directory without a vault is VAULT_NOT_FOUND — nothing unlocked, the key wiped", async () => {
    const key = wrongKey();

    await expectVaultError(() => engine.unlockWithKey(key), ErrorCode.VAULT_NOT_FOUND);

    expect(engine.getState()).toBe(VaultState.SEALED);
    expect(liveStore(engine)).toBeNull();
    expect(allZero(key)).toBe(true);
  });

  it("the password path's vault.unlock rows carry no detail (byte-identical to before the slot)", async () => {
    await engine.initVault(PASSWORD);
    await engine.lock();
    const viaPassword = secondEngine();
    await viaPassword.unlock(PASSWORD);

    const rows = rowsOf(viaPassword, AuditEventType.VAULT_UNLOCK);
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row).toMatchObject({
        success: true,
        principal_type: null,
        principal_id: null,
        detail: null,
      });
    }
  });

  it("the slot is KEK-level: after a password change the same key still unlocks, as does the new password", async () => {
    const key = await enrolledVault();
    await engine.changePassword(PASSWORD, "changed-pass1");
    await engine.lock();

    const viaKey = secondEngine();
    await viaKey.unlockWithKey(key);
    expect(viaKey.getState()).toBe(VaultState.UNLOCKED);
    await viaKey.lock();

    const viaPassword = secondEngine();
    await viaPassword.unlock("changed-pass1");
    expect(viaPassword.getState()).toBe(VaultState.UNLOCKED);
  });

  it("writes the session file as unlock() does — another engine loads it", async () => {
    const key = await enrolledVault();
    await engine.lock();
    await secondEngine().unlockWithKey(key);

    const loaded = secondEngine();
    expect(await loaded.loadSession()).toBe(true);
    expect(loaded.getState()).toBe(VaultState.UNLOCKED);
  });

  it("a session write that fails seals it: SESSION_KEYSTORE_UNAVAILABLE, no session file, nothing counted, the key wiped", async () => {
    class FailingProtector implements SessionKeyProtector {
      readonly scheme = "dpapi" as const;
      async protect(): Promise<Uint8Array> {
        throw new Error("helper timed out");
      }
      async unprotect(blob: Uint8Array): Promise<Uint8Array> {
        return blob;
      }
    }
    const key = await enrolledVault();
    await engine.lock();

    const failing = secondEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FailingProtector(),
    });
    await expectVaultError(
      () => failing.unlockWithKey(key),
      ErrorCode.SESSION_KEYSTORE_UNAVAILABLE,
    );

    expect(failing.getState()).toBe(VaultState.SEALED);
    expect(existsSync(sessionPath)).toBe(false);
    expect(readMeta("failed_attempts")).toBe("0");
    expect(allZero(key)).toBe(true);
  });

  it("over a live engine: a right key flips the unlock method to credential (the enrol then refused), a wrong key increments on the reused store and leaves it unlocked", async () => {
    const key = await enrolledVault();

    await engine.unlockWithKey(new Uint8Array(key));
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
    await expectVaultError(() => engine.enrollUnlockKey(), ErrorCode.UNLOCK_KEY_PASSWORD_REQUIRED);
    expect(rowsOf(engine, AuditEventType.VAULT_UNLOCK_KEY_ENROLL)).toEqual([
      expect.objectContaining({
        success: false,
        detail: { error: ErrorCode.UNLOCK_KEY_PASSWORD_REQUIRED },
      }),
      expect.objectContaining({ success: true, detail: { replaced: false } }),
    ]);

    const live = liveStore(engine);
    await expectVaultError(() => engine.unlockWithKey(wrongKey()), ErrorCode.INVALID_UNLOCK_KEY);
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
    expect(liveStore(engine) === live).toBe(true);
    expect(live.db.open).toBe(true);
    expect(readMeta("failed_attempts")).toBe("1");
  });
});

describe("the lockout the password path shares (Review Focus mode 3)", () => {
  it("a wrong key is INVALID_UNLOCK_KEY, counts one failed attempt and closes the store it opened", async () => {
    await enrolledVault();
    await engine.lock();
    const attempt = secondEngine();

    const close = vi.spyOn(SqliteStore.prototype, "close");
    await expectVaultError(() => attempt.unlockWithKey(wrongKey()), ErrorCode.INVALID_UNLOCK_KEY);
    expect(close).toHaveBeenCalledTimes(1);
    close.mockRestore();

    expect(attempt.getState()).toBe(VaultState.SEALED);
    expect(readMeta("failed_attempts")).toBe("1");
  });

  it("five wrong keys lock out the sixth attempt — the right key and the password alike", async () => {
    const key = await enrolledVault();
    await engine.lock();

    for (let i = 0; i < 5; i++) {
      await expectVaultError(
        () => secondEngine().unlockWithKey(wrongKey()),
        ErrorCode.INVALID_UNLOCK_KEY,
      );
    }
    await expectVaultError(() => secondEngine().unlockWithKey(key), ErrorCode.LOCKOUT_ACTIVE);
    await expectVaultError(() => secondEngine().unlock(PASSWORD), ErrorCode.LOCKOUT_ACTIVE);
    expect(readMeta("failed_attempts")).toBe("5");
  });

  it("five wrong passwords lock the key path out too", async () => {
    const key = await enrolledVault();
    await engine.lock();

    for (let i = 0; i < 5; i++) {
      await expectVaultError(
        () => secondEngine().unlock("wrong-pass1"),
        ErrorCode.INVALID_PASSWORD,
      );
    }
    await expectVaultError(() => secondEngine().unlockWithKey(key), ErrorCode.LOCKOUT_ACTIVE);
  });

  it("a successful key unlock resets the shared counter", async () => {
    const key = await enrolledVault();
    await engine.lock();

    for (let i = 0; i < 4; i++) {
      await expectVaultError(
        () => secondEngine().unlockWithKey(wrongKey()),
        ErrorCode.INVALID_UNLOCK_KEY,
      );
    }
    expect(readMeta("failed_attempts")).toBe("4");

    await secondEngine().unlockWithKey(key);
    expect(readMeta("failed_attempts")).toBe("0");
  });

  it("a key that is not 32 bytes is INVALID_UNLOCK_KEY before the vault opens — nothing counted, the buffer wiped", async () => {
    await enrolledVault();
    await engine.lock();
    const attempt = secondEngine();

    for (const length of [0, 31, 33]) {
      const malformed = new Uint8Array(length).fill(0x41);
      await expectVaultError(() => attempt.unlockWithKey(malformed), ErrorCode.INVALID_UNLOCK_KEY);
      expect(allZero(malformed)).toBe(true);
    }

    expect(liveStore(attempt)).toBeNull();
    expect(readMeta("failed_attempts")).toBeUndefined();
  });

  it("an unenrolled vault is UNLOCK_KEY_NOT_ENROLLED — no key tested, nothing counted, the store it opened closed", async () => {
    await engine.initVault(PASSWORD);
    await engine.lock();
    const attempt = secondEngine();
    const key = wrongKey();

    const close = vi.spyOn(SqliteStore.prototype, "close");
    await expectVaultError(() => attempt.unlockWithKey(key), ErrorCode.UNLOCK_KEY_NOT_ENROLLED);
    expect(close).toHaveBeenCalledTimes(1);
    close.mockRestore();

    expect(attempt.getState()).toBe(VaultState.SEALED);
    expect(readMeta("failed_attempts")).toBeUndefined();
    expect(allZero(key)).toBe(true);
  });

  it("after a revoke the key is UNLOCK_KEY_NOT_ENROLLED and the counter unchanged; the revoke wrote one row", async () => {
    const key = await enrolledVault();
    await engine.revokeUnlockKey();

    expect(SLOT_ROWS.map(readMeta)).toEqual([undefined, undefined, undefined, undefined]);
    expect(rowsOf(engine, AuditEventType.VAULT_UNLOCK_KEY_REVOKE)).toEqual([
      expect.objectContaining({
        success: true,
        secret_id: null,
        principal_type: null,
        detail: null,
      }),
    ]);

    await engine.lock();
    await expectVaultError(
      () => secondEngine().unlockWithKey(key),
      ErrorCode.UNLOCK_KEY_NOT_ENROLLED,
    );
    expect(readMeta("failed_attempts")).toBeUndefined();
  });

  it("revoking a vault with no slot is UNLOCK_KEY_NOT_ENROLLED with one failed revoke row", async () => {
    await engine.initVault(PASSWORD);

    await expectVaultError(() => engine.revokeUnlockKey(), ErrorCode.UNLOCK_KEY_NOT_ENROLLED);

    expect(rowsOf(engine, AuditEventType.VAULT_UNLOCK_KEY_REVOKE)).toEqual([
      expect.objectContaining({
        success: false,
        detail: { error: ErrorCode.UNLOCK_KEY_NOT_ENROLLED },
      }),
    ]);
  });
});

describe("one transaction per administration call (hard rule 7)", () => {
  it.each([
    { step: "the audit row", inject: () => failNextAuditInsert(engine) },
    { step: "the enrolment time", inject: () => failOnMetaKey("unlock_key_enrolled_at") },
  ])(
    "a failure at $step rolls the enrolment back — no slot row, no audit row, the drawn key wiped",
    async ({ inject }) => {
      await engine.initVault(PASSWORD);
      inject();

      let thrown: unknown;
      try {
        await engine.enrollUnlockKey();
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBe(INJECTED);
      vi.restoreAllMocks();

      expect(SLOT_ROWS.map(readMeta)).toEqual([undefined, undefined, undefined, undefined]);
      expect(rowsOf(engine, AuditEventType.VAULT_UNLOCK_KEY_ENROLL)).toHaveLength(0);
      expect(drawnKeys.length).toBe(1);
      expect(allZero(drawnKeys[0] as Uint8Array)).toBe(true);

      const retried = await engine.enrollUnlockKey();
      expect(allZero(retried)).toBe(false);
      expect(readMeta("wrapped_kek_uk")).toBeDefined();
    },
  );

  it("a failure at the audit row rolls the revocation back — the slot stays and still unlocks", async () => {
    const key = await enrolledVault();
    failNextAuditInsert(engine);

    await expect(engine.revokeUnlockKey()).rejects.toBe(INJECTED);
    vi.restoreAllMocks();

    expect(SLOT_ROWS.map(readMeta).every((value) => value !== undefined)).toBe(true);
    expect(rowsOf(engine, AuditEventType.VAULT_UNLOCK_KEY_REVOKE)).toHaveLength(0);
    await engine.lock();
    const viaKey = secondEngine();
    await viaKey.unlockWithKey(key);
    expect(viaKey.getState()).toBe(VaultState.UNLOCKED);
  });
});

describe("the key never leaves as data (hard rule 4)", () => {
  it("unlockWithKey wipes the key it is handed, after a success and after a wrong key", async () => {
    const key = await enrolledVault();
    await engine.lock();
    const wrong = wrongKey();

    await expectVaultError(() => secondEngine().unlockWithKey(wrong), ErrorCode.INVALID_UNLOCK_KEY);
    await secondEngine().unlockWithKey(key);

    expect(allZero(wrong)).toBe(true);
    expect(allZero(key)).toBe(true);
  });

  it("no thrown message, audit row, vault_meta value or session file carries the key", async () => {
    const key = await enrolledVault();
    const needles = ["hex", "base64", "base64url"].map((encoding) =>
      Buffer.from(key).toString(encoding as BufferEncoding),
    );
    const store = new SqliteStore(dbPath);
    let metaValues: string[];
    try {
      metaValues = (
        store.db.prepare("SELECT value FROM vault_meta").all() as {
          value: string;
        }[]
      ).map((row) => row.value);
    } finally {
      store.close();
    }

    const messages: string[] = [];
    const refused = async (run: () => Promise<unknown>): Promise<void> => {
      try {
        await run();
      } catch (err) {
        messages.push((err as Error).message);
      }
    };
    const loaded = secondEngine();
    await loaded.loadSession();
    await refused(() => loaded.enrollUnlockKey());
    await engine.lock();
    await refused(() => secondEngine().unlockWithKey(wrongKey()));
    await refused(() => secondEngine().unlockWithKey(new Uint8Array(31)));
    const viaKey = secondEngine();
    await viaKey.unlockWithKey(new Uint8Array(key));
    const session = readFileSync(sessionPath, "utf8");
    await viaKey.unlock(PASSWORD);
    await viaKey.revokeUnlockKey();
    await refused(() => viaKey.revokeUnlockKey());

    expect(messages.length).toBe(4);
    const haystack = [...messages, JSON.stringify(viaKey.queryAudit()), ...metaValues, session];
    for (const needle of needles) expect(haystack.join("\n").includes(needle)).toBe(false);
  });
});
