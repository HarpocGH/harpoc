import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext } from "@harpoc/shared";
import {
  AuditEventType,
  DEFAULT_SESSION_TTL_MS,
  ErrorCode,
  MAX_SESSION_TTL_MS,
  SESSION_CLEANUP_INTERVAL_MS,
  SESSION_SLIDE_INTERVAL_MS,
  VaultState,
} from "@harpoc/shared";
import type { SessionManager } from "./session/session-manager.js";
import { VaultEngine } from "./vault-engine.js";
import type { VaultEngineOptions } from "./vault-engine.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const PASSWORD = "memory-session-pass";

let tempDir: string;
let dbPath: string;
let sessionPath: string;
// The administrator's engine: file mode, as every attended command runs.
let admin: VaultEngine;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-ms-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  admin = new VaultEngine({ dbPath, sessionPath });
});

// Every engine a case opens beside `admin` is destroyed here, on the failure
// path too, before its directory is removed (an open store is EBUSY on win32).
const secondEngines: VaultEngine[] = [];
function secondEngine(options: Partial<VaultEngineOptions> = {}): VaultEngine {
  const opened = new VaultEngine({ dbPath, sessionPath, ...options });
  secondEngines.push(opened);
  return opened;
}
const memoryEngine = (): VaultEngine => secondEngine({ sessionMode: "memory" });

afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  for (const opened of secondEngines.splice(0)) await opened.destroy();
  await admin.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

type SessionInternals = {
  sessionId: string | null;
  sessionExpiresAt: number | null;
  sessionMonitorInterval: ReturnType<typeof setInterval> | null;
  sessionSlide: Promise<void> | null;
  sessionManager: SessionManager;
  sessionMonitorTick(): Promise<void>;
};
const internals = (e: VaultEngine): SessionInternals => e as unknown as SessionInternals;

const allZero = (buf: Uint8Array): boolean => buf.every((b) => b === 0);
function liveKeys(e: VaultEngine): Uint8Array[] {
  const keys = e as unknown as { kek: Uint8Array; jwtKey: Uint8Array; auditKey: Uint8Array };
  return [keys.kek, keys.jwtKey, keys.auditKey];
}

// The two fields a case compares — never the whole file, which holds the session key.
function storedSession(): { sessionId: string; expiresAt: number } {
  const file = JSON.parse(readFileSync(sessionPath, "utf8")) as {
    session_id: string;
    expires_at: number;
  };
  return { sessionId: file.session_id, expiresAt: file.expires_at };
}

/** An initialised vault whose session the administrator locked: what an unattended start finds. */
async function lockedVault(): Promise<void> {
  await admin.initVault(PASSWORD);
  await admin.lock();
}

/** As {@link lockedVault}, with an enrolled unlock key handed back for the daemon. */
async function lockedVaultWithKey(): Promise<Uint8Array> {
  await admin.initVault(PASSWORD);
  const key = await admin.enrollUnlockKey();
  await admin.lock();
  return key;
}

const OPENERS: readonly (readonly [string, (e: VaultEngine) => Promise<void>])[] = [
  [
    "initVault",
    async (e) => {
      await e.initVault(PASSWORD);
    },
  ],
  [
    "unlock",
    async (e) => {
      await lockedVault();
      await e.unlock(PASSWORD);
    },
  ],
  [
    "unlockWithKey",
    async (e) => {
      const key = await lockedVaultWithKey();
      await e.unlockWithKey(key);
    },
  ],
];

describe("no session file (RC-B5-1)", () => {
  it.each(OPENERS)("%s in memory mode writes no session.json and serves", async (_, open) => {
    const daemon = memoryEngine();
    await open(daemon);

    expect(existsSync(sessionPath)).toBe(false);
    expect(daemon.getState()).toBe(VaultState.UNLOCKED);
    expect(daemon.listSecrets()).toEqual([]);
  });

  it.each(OPENERS)(
    "control: %s in file mode, the default, writes session.json",
    async (_, open) => {
      const engine = secondEngine();
      await open(engine);

      expect(existsSync(sessionPath)).toBe(true);
      expect(storedSession().sessionId).toBe(internals(engine).sessionId);
    },
  );

  it("a memory-mode unlock's vault.unlock row has session_id null — the password row's detail null, the key row's method credential", async () => {
    const key = await lockedVaultWithKey();
    const viaPassword = memoryEngine();
    await viaPassword.unlock(PASSWORD);
    const viaKey = memoryEngine();
    await viaKey.unlockWithKey(key);

    const [keyRow, passwordRow, initRow] = viaKey.queryAudit({
      eventType: AuditEventType.VAULT_UNLOCK,
    });
    expect(keyRow).toMatchObject({ success: true, principal_type: null, session_id: null });
    expect(keyRow?.detail).toEqual({ method: "credential" });
    expect(passwordRow).toMatchObject({
      success: true,
      principal_type: null,
      session_id: null,
      detail: null,
    });
    // The administrator's file-mode init keeps its session's id.
    expect(initRow?.session_id).toEqual(expect.any(String));
  });

  it("changePassword in memory mode writes no session.json; the engine stays unlocked and the new password opens the vault", async () => {
    await lockedVault();
    const daemon = memoryEngine();
    await daemon.unlock(PASSWORD);
    expect(existsSync(sessionPath)).toBe(false);

    await daemon.changePassword(PASSWORD, "changed-pass1");

    expect(existsSync(sessionPath)).toBe(false);
    expect(daemon.getState()).toBe(VaultState.UNLOCKED);
    expect(daemon.listSecrets()).toEqual([]);
    const reopened = memoryEngine();
    await reopened.unlock("changed-pass1");
    expect(reopened.getState()).toBe(VaultState.UNLOCKED);
  });

  it("a re-unlock over a live memory-mode engine wipes the old keys and reinstalls — still no session.json", async () => {
    await lockedVault();
    const daemon = memoryEngine();
    await daemon.unlock(PASSWORD);
    const old = liveKeys(daemon);

    await daemon.unlock(PASSWORD);

    expect(old.map(allZero)).toEqual([true, true, true]);
    expect(existsSync(sessionPath)).toBe(false);
    expect(daemon.getState()).toBe(VaultState.UNLOCKED);
    expect(daemon.listSecrets()).toEqual([]);
  });
});

describe("no monitor, no slide, no idle seal (RC-B5-1)", () => {
  it("arms no monitor: no timer, and past the idle TTL and the 24 h ceiling it still serves (fake timers)", async () => {
    vi.useFakeTimers();
    const daemon = memoryEngine();
    await daemon.initVault(PASSWORD);

    expect(vi.getTimerCount()).toBe(0);
    expect(internals(daemon).sessionMonitorInterval).toBeNull();

    await vi.advanceTimersByTimeAsync(MAX_SESSION_TTL_MS + SESSION_CLEANUP_INTERVAL_MS);

    expect(daemon.listSecrets()).toEqual([]);
    expect(daemon.getState()).toBe(VaultState.UNLOCKED);
    expect(internals(daemon).sessionExpiresAt).toBeNull();
  });

  it("control: a file-mode engine arms the monitor and seals once its idle TTL has passed (fake timers)", async () => {
    vi.useFakeTimers();
    const engine = secondEngine();
    await engine.initVault(PASSWORD);

    expect(vi.getTimerCount()).toBe(1);

    vi.setSystemTime(Date.now() + DEFAULT_SESSION_TTL_MS + 1);
    await vi.advanceTimersByTimeAsync(SESSION_CLEANUP_INTERVAL_MS);
    await vi.waitFor(() => expect(engine.getState()).toBe(VaultState.SEALED));
  });

  it("serves on after a use finds no session file: no slide marks it expired (touchSession is a no-op)", async () => {
    const key = await lockedVaultWithKey();
    const daemon = memoryEngine();
    await daemon.unlockWithKey(key);

    daemon.listSecrets();
    await internals(daemon).sessionSlide;

    expect(daemon.listSecrets()).toEqual([]);
    expect(daemon.getState()).toBe(VaultState.UNLOCKED);
    expect(internals(daemon).sessionExpiresAt).toBeNull();
  });

  it("slides no session file: the administrator's session.json keeps its expiry while the memory-mode engine works", async () => {
    await admin.initVault(PASSWORD);
    const daemon = memoryEngine();
    expect(await daemon.loadSession()).toBe(true);
    const before = storedSession();
    const extend = vi.spyOn(internals(daemon).sessionManager, "extendSession");

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + SESSION_SLIDE_INTERVAL_MS + 5_000);
    daemon.listSecrets();
    await daemon.createSecret({ name: "worked", type: "api_key" });
    await internals(daemon).sessionSlide;

    expect(extend).not.toHaveBeenCalled();
    expect(storedSession()).toEqual(before);
  });
});

describe("loadSession detaches (RC-B5-1)", () => {
  it("takes the keys from the administrator's session.json and holds no session of its own: no id, no expiry, no monitor — and enrols nothing", async () => {
    await admin.initVault(PASSWORD);
    const daemon = memoryEngine();

    expect(await daemon.loadSession()).toBe(true);

    expect(internals(daemon).sessionId).toBeNull();
    expect(internals(daemon).sessionExpiresAt).toBeNull();
    expect(internals(daemon).sessionMonitorInterval).toBeNull();
    expect(daemon.listSecrets()).toEqual([]);
    await expectVaultError(() => daemon.enrollUnlockKey(), ErrorCode.UNLOCK_KEY_PASSWORD_REQUIRED);
  });

  it("an administrator's later unlock — a fresh session.json, a foreign session_id — leaves it serving, while a file-mode engine's monitor tick seals on it (D7)", async () => {
    await admin.initVault(PASSWORD);
    const daemon = memoryEngine();
    const fileDaemon = secondEngine();
    expect(await daemon.loadSession()).toBe(true);
    expect(await fileDaemon.loadSession()).toBe(true);

    await secondEngine().unlock(PASSWORD);

    await internals(fileDaemon).sessionMonitorTick();
    expect(fileDaemon.getState()).toBe(VaultState.SEALED);
    daemon.listSecrets();
    await internals(daemon).sessionSlide;
    expect(daemon.listSecrets()).toEqual([]);
    expect(daemon.getState()).toBe(VaultState.UNLOCKED);
  });
});

describe("lock() and destroy() in memory mode (RC-B5-2)", () => {
  it("lock() wipes the keys and refuses every later call VAULT_LOCKED — and leaves the administrator's session.json, which still loads", async () => {
    await admin.initVault(PASSWORD);
    const daemon = memoryEngine();
    expect(await daemon.loadSession()).toBe(true);
    const keys = liveKeys(daemon);
    expect(keys.map(allZero)).toEqual([false, false, false]);

    await daemon.lock();

    expect(keys.map(allZero)).toEqual([true, true, true]);
    expect(daemon.getState()).toBe(VaultState.SEALED);
    await expectVaultError(() => daemon.listSecrets(), ErrorCode.VAULT_LOCKED);
    expect(existsSync(sessionPath)).toBe(true);
    expect(admin.listSecrets()).toEqual([]);
    expect(await secondEngine().loadSession()).toBe(true);
  });

  it("the administrator's lock() erases session.json and the memory-mode engine serves on — no monitor tick, no slide, no expiry of that file seals it (fake timers)", async () => {
    vi.useFakeTimers();
    await admin.initVault(PASSWORD);
    const daemon = memoryEngine();
    expect(await daemon.loadSession()).toBe(true);

    await admin.lock();
    expect(existsSync(sessionPath)).toBe(false);

    daemon.listSecrets();
    await internals(daemon).sessionSlide;
    await vi.advanceTimersByTimeAsync(DEFAULT_SESSION_TTL_MS + SESSION_CLEANUP_INTERVAL_MS);

    expect(daemon.listSecrets()).toEqual([]);
    expect(daemon.getState()).toBe(VaultState.UNLOCKED);
  });

  it("its vault.lock row is the trusted row — no principal, detail null — with session_id null; a caller's lock is attributed as in file mode", async () => {
    const caller: CallerContext = {
      principal_type: "agent",
      principal_id: "agent-1",
      interface: "rest",
      remote_address: "127.0.0.1",
      admin_scope: true,
    };
    await lockedVault();
    const daemon = memoryEngine();
    await daemon.unlock(PASSWORD);
    await daemon.lock();
    const served = memoryEngine();
    await served.unlock(PASSWORD);
    await served.lock(caller);

    const reader = memoryEngine();
    await reader.unlock(PASSWORD);
    const [remoteRow, memoryRow, fileRow] = reader.queryAudit({
      eventType: AuditEventType.VAULT_LOCK,
    });
    const trusted = { success: true, principal_type: null, principal_id: null, ip_address: null };
    expect(memoryRow).toMatchObject({ ...trusted, detail: null, session_id: null });
    expect(fileRow).toMatchObject({ ...trusted, detail: null, session_id: expect.any(String) });
    expect(remoteRow).toMatchObject({
      success: true,
      principal_type: "agent",
      principal_id: "agent-1",
      ip_address: "127.0.0.1",
      session_id: null,
    });
    expect(remoteRow?.detail).toEqual({ interface: "rest" });
  });

  it("destroy() — the daemon's SIGTERM path — wipes the keys and closes the store", async () => {
    const key = await lockedVaultWithKey();
    const daemon = memoryEngine();
    await daemon.unlockWithKey(key);
    expect(existsSync(sessionPath)).toBe(false);
    const keys = liveKeys(daemon);

    await daemon.destroy();

    expect(keys.map(allZero)).toEqual([true, true, true]);
    expect((daemon as unknown as { store: unknown }).store).toBeNull();
    expect(daemon.getState()).toBe(VaultState.SEALED);
    await expectVaultError(() => daemon.listSecrets(), ErrorCode.VAULT_LOCKED);
  });
});
