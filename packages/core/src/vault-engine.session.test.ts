import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, VaultState } from "@harpoc/shared";
import { expectVaultError, protectorTimer, recordSeriesLine } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import { SqliteStore } from "./storage/sqlite-store.js";
import type { VaultEngineOptions } from "./vault-engine.js";
import { DpapiSessionKeyProtector } from "./session/session-key-protector.js";
import type { SessionKeyProtector } from "./session/session-key-protector.js";

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

describe("session TTL enforcement for long-lived engines", () => {
  // Fake timers freeze Date.now(), so the pre-expiry assertion cannot flake
  // under load (a real 300 ms TTL legitimately elapsed mid-test on slow CI
  // runners) and the expiry jump needs no real sleep — the synchronous
  // assertUnlocked seal path is what's under test, not the monitor.
  afterEach(() => {
    vi.useRealTimers();
  });

  it("seals an initVault() engine once its session TTL expires", async () => {
    vi.useFakeTimers();
    const eng = secondEngine({ dbPath, sessionPath, sessionTtlMs: 300 });
    await eng.initVault("password");

    // Works at unlock time (not sealed prematurely) — clock is frozen.
    expect(eng.listSecrets()).toEqual([]);

    vi.setSystemTime(Date.now() + 500);

    await expectVaultError(() => eng.listSecrets(), ErrorCode.VAULT_LOCKED);
    expect(eng.getState()).toBe(VaultState.SEALED);
    await eng.destroy();
  });

  it("seals an unlock() engine (not initVault) once its session TTL expires", async () => {
    await engine.initVault("password");
    await engine.lock();

    vi.useFakeTimers();
    const eng = secondEngine({ dbPath, sessionPath, sessionTtlMs: 300 });
    await eng.unlock("password");
    expect(eng.getState()).toBe(VaultState.UNLOCKED);

    vi.setSystemTime(Date.now() + 500);

    await expectVaultError(() => eng.listSecrets(), ErrorCode.VAULT_LOCKED);
    expect(eng.getState()).toBe(VaultState.SEALED);
    await eng.destroy();
  });
});

describe("session loading", () => {
  it("loads session after restart", async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "persist",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });

    // Simulate restart — destroy engine, create new one
    await engine.destroy();

    const engine2 = secondEngine({ dbPath, sessionPath });
    const loaded = await engine2.loadSession();
    expect(loaded).toBe(true);
    expect(engine2.getState()).toBe(VaultState.UNLOCKED);

    const list = engine2.listSecrets();
    expect(list.length).toBe(1);

    await engine2.destroy();
  });

  it("session restore preserves audit log decryptability", async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "audit-persist",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });

    // Verify audit entries exist before restart
    const beforeEvents = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(beforeEvents.length).toBe(1);
    expect(beforeEvents[0]?.detail?.handle).toBe("secret://audit-persist");

    // Simulate restart
    await engine.destroy();

    const engine2 = secondEngine({ dbPath, sessionPath });
    const loaded = await engine2.loadSession();
    expect(loaded).toBe(true);

    // After session restore, audit entries should still be decryptable
    const afterEvents = engine2.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(afterEvents.length).toBe(1);
    expect(afterEvents[0]?.detail?.handle).toBe("secret://audit-persist");

    // Create a new audit entry to verify audit key works for new writes too
    await engine2.createSecret({
      name: "post-restart",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val2")),
    });
    const newEvents = engine2.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(newEvents.length).toBe(2);

    await engine2.destroy();
  });
});

// ---------------------------------------------------------------------------
// L5 — loadSession enforces the vault-version guard
// ---------------------------------------------------------------------------

describe("L5 — session load honours the vault version", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("refuses a vault stamped newer than this binary supports", async () => {
    await engine.destroy();

    const store = new SqliteStore(dbPath);
    store.setMeta("vault_version", "99.0.0");
    store.close();

    const reloaded = new VaultEngine({ dbPath, sessionPath });
    try {
      await expectVaultError(() => reloaded.loadSession(), ErrorCode.VAULT_CORRUPTED);
    } finally {
      await reloaded.destroy();
    }

    // Re-created for the shared afterEach teardown.
    engine = new VaultEngine({ dbPath, sessionPath });
  });

  it("refuses a vault stamped below the v1.5 floor on the session path too (R2)", async () => {
    await engine.destroy();

    const store = new SqliteStore(dbPath);
    store.setMeta("vault_version", "1.0.0");
    store.close();

    const reloaded = new VaultEngine({ dbPath, sessionPath });
    try {
      const err = await expectVaultError(() => reloaded.loadSession(), ErrorCode.VAULT_CORRUPTED);
      expect(err.message).toContain("predates the supported minimum");
      expect(err.message).toContain("harpoc init");
    } finally {
      await reloaded.destroy();
    }

    engine = new VaultEngine({ dbPath, sessionPath });
  });

  it("control: a supported version still loads the session", async () => {
    const reloaded = new VaultEngine({ dbPath, sessionPath });
    try {
      expect(await reloaded.loadSession()).toBe(true);
    } finally {
      await reloaded.destroy();
    }
  });
});

describe("session TTL sliding (use-driven, thesis §5.4.7)", () => {
  type SlideInternals = {
    sessionSlide: Promise<void> | null;
    lastSessionSlideAt: number;
    sessionMonitorTick(): Promise<void>;
  };
  const internals = (e: VaultEngine): SlideInternals => e as unknown as SlideInternals;

  function readExpiry(): number {
    return (JSON.parse(readFileSync(sessionPath, "utf-8")) as { expires_at: number }).expires_at;
  }

  function tamperExpiry(expiresAt: number): void {
    const session = JSON.parse(readFileSync(sessionPath, "utf-8")) as Record<string, unknown>;
    session.expires_at = expiresAt;
    writeFileSync(sessionPath, JSON.stringify(session));
  }

  it("an authenticated operation slides the stored expiry", async () => {
    await engine.initVault("password");
    await internals(engine).sessionSlide;
    const tampered = Date.now() + 60_000;
    tamperExpiry(tampered);
    internals(engine).lastSessionSlideAt = 0;

    engine.listSecrets();
    await internals(engine).sessionSlide;

    expect(readExpiry()).toBeGreaterThan(tampered);
  });

  it("skips the slide when the last one is younger than the slide interval", async () => {
    await engine.initVault("password");
    await internals(engine).sessionSlide;
    internals(engine).lastSessionSlideAt = 0;
    engine.listSecrets(); // arms the throttle
    await internals(engine).sessionSlide;

    const tampered = Date.now() + 60_000;
    tamperExpiry(tampered);
    engine.listSecrets(); // within the interval — no slide starts

    expect(internals(engine).sessionSlide).toBeNull();
    expect(readExpiry()).toBe(tampered);
  });

  it("the monitor tick never extends a live session", async () => {
    await engine.initVault("password");
    await internals(engine).sessionSlide;
    const tampered = Date.now() + 60_000;
    tamperExpiry(tampered);

    await internals(engine).sessionMonitorTick();

    expect(engine.getState()).toBe(VaultState.UNLOCKED);
    expect(readExpiry()).toBe(tampered);
  });

  it("the monitor tick seals the vault once the session expires", async () => {
    await engine.initVault("password");
    await internals(engine).sessionSlide;
    tamperExpiry(Date.now() - 1);

    await internals(engine).sessionMonitorTick();

    expect(engine.getState()).toBe(VaultState.SEALED);
    await expectVaultError(() => engine.listSecrets(), ErrorCode.VAULT_LOCKED);
  });
});

describe("session keystore protection", () => {
  class FakeKeystoreProtector implements SessionKeyProtector {
    readonly scheme = "dpapi" as const;

    async protect(key: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(Buffer.concat([Buffer.from("WRAP:"), Buffer.from(key)]));
    }

    async unprotect(blob: Uint8Array): Promise<Uint8Array> {
      const buf = Buffer.from(blob);
      if (!buf.subarray(0, 5).equals(Buffer.from("WRAP:"))) throw new Error("not a wrapped blob");
      return new Uint8Array(buf.subarray(5));
    }
  }

  it("shares a wrapped session across engines with the same protector", async () => {
    const engineA = secondEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FakeKeystoreProtector(),
    });
    await engineA.initVault("password");

    const file = JSON.parse(readFileSync(sessionPath, "utf8")) as { key_protection?: string };
    expect(file.key_protection).toBe("dpapi");

    const engineB = secondEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FakeKeystoreProtector(),
    });
    expect(await engineB.loadSession()).toBe(true);
    expect(engineB.getState()).toBe(VaultState.UNLOCKED);
    await engineB.destroy();
    await engineA.destroy();
  });

  it("fails to load when the engine's protector cannot handle the stored scheme", async () => {
    const engineA = secondEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FakeKeystoreProtector(),
    });
    await engineA.initVault("password");

    // The default protector (none in tests) cannot unwrap the dpapi-tagged file.
    const engineB = secondEngine({ dbPath, sessionPath });
    expect(await engineB.loadSession()).toBe(false);
    expect(engineB.getState()).toBe(VaultState.SEALED);
    await engineB.destroy();
    await engineA.destroy();
  });

  it("fails to load when key_protection is stripped from a wrapped file", async () => {
    const engineA = secondEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FakeKeystoreProtector(),
    });
    await engineA.initVault("password");

    const file = JSON.parse(readFileSync(sessionPath, "utf8")) as Record<string, unknown>;
    file["key_protection"] = "none";
    writeFileSync(sessionPath, JSON.stringify(file), "utf8");

    // A none tag under a keystore protector is refused before any unwrap (R8/D54) — the file reads as no session.
    const engineB = secondEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FakeKeystoreProtector(),
    });
    expect(await engineB.loadSession()).toBe(false);
    await engineB.destroy();
    await engineA.destroy();
  });

  it("fails closed when the keystore cannot protect the session: SESSION_KEYSTORE_UNAVAILABLE, sealed, no file", async () => {
    class FailingProtector implements SessionKeyProtector {
      readonly scheme = "dpapi" as const;
      async protect(): Promise<Uint8Array> {
        throw new Error("helper timed out");
      }
      async unprotect(blob: Uint8Array): Promise<Uint8Array> {
        return blob;
      }
    }

    const failing = secondEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FailingProtector(),
    });
    const err = await expectVaultError(
      () => failing.initVault("password"),
      ErrorCode.SESSION_KEYSTORE_UNAVAILABLE,
    );
    expect(err.message).toContain("HARPOC_SESSION_KEYSTORE=off");
    expect(failing.getState()).toBe(VaultState.SEALED);
    expect(existsSync(sessionPath)).toBe(false);
    await expectVaultError(() => failing.listSecrets(), ErrorCode.VAULT_LOCKED);

    // The vault itself was initialised; the none protector (the vitest
    // HARPOC_SESSION_KEYSTORE=off environment) opens it.
    const plain = secondEngine({ dbPath, sessionPath });
    await plain.unlock("password");
    expect(plain.getState()).toBe(VaultState.UNLOCKED);
    await plain.lock();

    const again = secondEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FailingProtector(),
    });
    await expectVaultError(() => again.unlock("password"), ErrorCode.SESSION_KEYSTORE_UNAVAILABLE);
    expect(again.getState()).toBe(VaultState.SEALED);
    expect(existsSync(sessionPath)).toBe(false);

    await failing.destroy();
    await plain.destroy();
    await again.destroy();
  });

  // The product keeps its 15 s helper bound and fails closed past it (R8/D54:
  // a thrown SESSION_KEYSTORE_UNAVAILABLE out of initVault, never a silent
  // `none` file). Here the protector gets 90 s and the case 240 s — two
  // protector calls plus two Argon2id inits — so a loaded windows-latest runner
  // stretches the case instead of failing it; every call's duration is printed
  // for the CI log — and, on a runner, to the job summary with the 60 s trigger
  // judged on the slowest call — and extends the DPAPI series in decisions.md
  // (D3 and D4, 2026-09-08).
  const DPAPI_PROTECT_BUDGET_MS = 90_000;
  const DPAPI_CASE_BUDGET_MS = 240_000;

  describe.runIf(process.platform === "win32")("DPAPI end-to-end (Windows)", () => {
    it(
      "wraps the session key via DPAPI and shares it across engines",
      async () => {
        const timer = protectorTimer("vault-engine dpapi");
        try {
          const engineA = secondEngine({
            dbPath,
            sessionPath,
            sessionKeyProtector: timer.wrap(
              new DpapiSessionKeyProtector({ timeoutMs: DPAPI_PROTECT_BUDGET_MS }),
            ),
          });
          await engineA.initVault("password");

          const file = JSON.parse(readFileSync(sessionPath, "utf8")) as {
            key_protection?: string;
            session_key?: string;
          };
          expect(file.key_protection).toBe("dpapi");
          // A DPAPI blob is far larger than the 32-byte raw key (44 base64 chars).
          expect((file.session_key ?? "").length).toBeGreaterThan(100);

          const engineB = secondEngine({
            dbPath,
            sessionPath,
            sessionKeyProtector: timer.wrap(
              new DpapiSessionKeyProtector({ timeoutMs: DPAPI_PROTECT_BUDGET_MS }),
            ),
          });
          expect(await engineB.loadSession()).toBe(true);
          expect(engineB.getState()).toBe(VaultState.UNLOCKED);
          await engineB.destroy();
          await engineA.destroy();
        } finally {
          recordSeriesLine(timer.report(), { judgedMs: timer.slowestMs() });
        }
      },
      DPAPI_CASE_BUDGET_MS,
    );
  });
});
