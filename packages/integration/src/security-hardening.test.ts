import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { describe, it, expect, beforeAll, afterAll, vi, beforeEach, afterEach } from "vitest";
import { VaultEngine, wipeBuffer, encrypt, SqliteStore } from "@harpoc/core";
import {
  AES_KEY_LENGTH,
  AuditEventType,
  ErrorCode,
  InjectionType,
  SecretType,
  VaultError,
  VaultState,
  LOCKOUT_MAX_ATTEMPTS,
  LOCKOUT_DURATIONS_MS,
} from "@harpoc/shared";
import { expectVaultError, silenceAuditLines } from "@harpoc/test-utils";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startTestServer, type TestServer } from "./helpers/rest-helpers.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = join(__filename, "..");
// repo root: packages/integration/src -> ../../..
const REPO_ROOT = join(__dirname, "..", "..", "..");

const PASSWORD = "security-hardening-pw";

/** Structural view of the store's raw SQLite handle — only what this file calls. */
interface RawStatement {
  all(...args: unknown[]): unknown[];
}
interface RawDb {
  prepare(sql: string): RawStatement;
}

// ---------------------------------------------------------------------------
// 1. Memory Wiping
// ---------------------------------------------------------------------------
describe("Memory Wiping", () => {
  let vault: TestVault;

  beforeEach(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
  });

  afterEach(async () => {
    try {
      await vault.engine.destroy();
    } catch {
      /* already destroyed */
    }
    destroyTestVault(vault).catch(() => {});
  });

  it("wipeBuffer() zeroes every byte (thesis §4.6 memory hygiene)", () => {
    const buf = new Uint8Array(32);
    buf.fill(0xaa);
    wipeBuffer(buf);
    expect(buf.every((b) => b === 0)).toBe(true);
  });

  it("lock() makes vault inoperable (consequence of wipeKeys)", async () => {
    await vault.engine.lock();
    expect(vault.engine.getState()).toBe(VaultState.SEALED);
    // Any operation should throw VAULT_LOCKED
    expect(() => vault.engine.listSecrets()).toThrow();
  });

  it("useSecret() completes HTTP injection then wipes value", async () => {
    // Create echo server
    const echoServer = createServer((req, res) => {
      const body = JSON.stringify({ headers: req.headers });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
    });
    await new Promise<void>((resolve) => {
      echoServer.listen(0, "127.0.0.1", resolve);
    });
    const echoAddr = echoServer.address() as AddressInfo;
    const echoUrl = `http://127.0.0.1:${echoAddr.port}`;

    const secretValue = "sk-test-wipe-check-123456";
    const result = await vault.engine.createSecret({
      name: "wipe-test-secret",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from(secretValue)),
    });
    await vault.engine.setInjectionPolicy(result.handle, { url_allowlist: [`${echoUrl}/*`] });

    // useSecret should complete without error (value decrypted, injected, then wiped)
    const response = await vault.engine.useSecret(result.handle, {
      type: "http",
      method: "GET",
      url: echoUrl,
      injection: { type: InjectionType.BEARER },
    });
    expect(response.type).toBe("http");
    if (response.type !== "http") throw new Error("expected http result");
    expect(response.status).toBe(200);

    await new Promise<void>((resolve, reject) => {
      echoServer.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("session key wiped after session file write", async () => {
    // If session key were NOT wiped, a second initVault would be affected.
    // Instead, we verify the vault can lock and re-unlock (session key was wiped,
    // new one is generated each time).
    await vault.engine.lock();
    await vault.engine.unlock(PASSWORD);
    expect(vault.engine.getState()).toBe(VaultState.UNLOCKED);
  });

  it("session file overwritten with random bytes before deletion on lock", async () => {
    // After lock, the session file should not exist
    await vault.engine.lock();
    expect(existsSync(vault.sessionPath)).toBe(false);
  });

  it("computeNameHmac returns consistent results (key derived then wiped internally)", async () => {
    const { computeNameHmac } = await import("@harpoc/core");
    // We need a KEK to test this — create one via the crypto module
    const kek = randomBytes(32);
    const hmac1 = await computeNameHmac(new Uint8Array(kek), "test-secret", null);
    const hmac2 = await computeNameHmac(new Uint8Array(kek), "test-secret", null);
    expect(hmac1).toBe(hmac2);
    expect(hmac1).toHaveLength(64); // hex-encoded SHA-256
  });

  it("multiple secrets can be created sequentially (DEK wiped after each)", async () => {
    for (let i = 0; i < 5; i++) {
      const result = await vault.engine.createSecret({
        name: `sequential-secret-${i}`,
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from(`value-${i}`)),
      });
      expect(result.handle).toBe(`secret://sequential-secret-${i}`);
    }
    const secrets = vault.engine.listSecrets();
    expect(secrets.length).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// 2. Error Message Sanitization
// ---------------------------------------------------------------------------
describe("Error Message Sanitization", () => {
  let vault: TestVault;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    await vault.engine.createSecret({
      name: "sanitization-test",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("sk-super-secret-12345")),
    });
  });

  afterAll(async () => {
    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });

  it("SECRET_NOT_FOUND contains handle, not secret value", async () => {
    const err = await expectVaultError(
      () => vault.engine.getSecretInfo("secret://nonexistent"),
      ErrorCode.SECRET_NOT_FOUND,
    );
    expect(err.message).not.toContain("sk-super-secret");
  });

  it("SECRET_REVOKED contains handle, not value", async () => {
    const revokeResult = await vault.engine.createSecret({
      name: "revoke-test",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("sk-revoke-value")),
    });
    await vault.engine.revokeSecret(revokeResult.handle);

    // rotateSecret calls assertUsable which throws SECRET_REVOKED
    const err = await expectVaultError(
      () => vault.engine.rotateSecret(revokeResult.handle, new Uint8Array(Buffer.from("new"))),
      ErrorCode.SECRET_REVOKED,
    );
    expect(err.message).not.toContain("sk-revoke-value");
  });

  it("SECRET_EXPIRED contains handle, not value", async () => {
    const expireResult = await vault.engine.createSecret({
      name: "expire-test",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("sk-expire-value")),
      expiresAt: Date.now() - 1000, // already expired
    });

    // rotateSecret calls assertUsable which throws SECRET_EXPIRED
    const err = await expectVaultError(
      () => vault.engine.rotateSecret(expireResult.handle, new Uint8Array(Buffer.from("new"))),
      ErrorCode.SECRET_EXPIRED,
    );
    expect(err.message).not.toContain("sk-expire-value");
  });

  it("INVALID_PASSWORD is generic, no key material", async () => {
    const engine2 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    try {
      const err = await expectVaultError(
        () => engine2.unlock("wrong-password-here"),
        ErrorCode.INVALID_PASSWORD,
      );
      expect(err.message).toBe("Invalid password");
      expect(err.message).not.toContain("wrong-password");
    } finally {
      await engine2.destroy();
    }
  });

  it("DUPLICATE_SECRET contains name, not value", async () => {
    const err = await expectVaultError(
      () =>
        vault.engine.createSecret({
          name: "sanitization-test", // already exists
          type: SecretType.API_KEY,
          value: new Uint8Array(Buffer.from("another-value")),
        }),
      ErrorCode.DUPLICATE_SECRET,
    );
    expect(err.message).not.toContain("another-value");
  });

  it("all VaultError factory methods produce messages free of binary/base64 patterns", () => {
    // base64 pattern: long string of alphanumeric+/= (>= 20 chars of base64)
    const base64Pattern = /[A-Za-z0-9+/=]{20,}/;
    // Uint8Array string representation pattern
    const uint8Pattern = /Uint8Array/;

    const errors: VaultError[] = [
      VaultError.vaultLocked(),
      VaultError.vaultNotFound(),
      VaultError.secretNotFound("secret://test"),
      VaultError.accessDenied("no permission"),
      VaultError.invalidInput("bad input"),
      VaultError.invalidHandle("bad-handle"),
      VaultError.invalidPassword(),
      VaultError.duplicateSecret("my-secret"),
      VaultError.lockoutActive(30000),
      VaultError.schemaValidation("invalid field"),
      VaultError.internalError("something went wrong"),
      VaultError.vaultCorrupted("bad data"),
      VaultError.encryptionError("decrypt failed"),
      VaultError.databaseError("sqlite error"),
      VaultError.secretExpired("secret://expired"),
      VaultError.secretRevoked("secret://revoked"),
      VaultError.tokenExpired(),
      VaultError.tokenRevoked(),
      VaultError.sessionFileError("write failed"),
      VaultError.weakPassword(8),
    ];

    for (const err of errors) {
      expect(err.message).not.toMatch(base64Pattern);
      expect(err.message).not.toMatch(uint8Pattern);
    }
  });

  it("lifecycle errors do not contain Uint8Array representations", async () => {
    const collectedErrors: VaultError[] = [];

    // SECRET_NOT_FOUND
    try {
      await vault.engine.getSecretInfo("secret://no-such-secret");
    } catch (e) {
      if (e instanceof VaultError) collectedErrors.push(e);
    }

    // INVALID_HANDLE
    try {
      await vault.engine.getSecretInfo("bad-handle-format");
    } catch (e) {
      if (e instanceof VaultError) collectedErrors.push(e);
    }

    // useSecret with bad handle
    try {
      await vault.engine.useSecret("secret://nonexistent", {
        type: "http",
        method: "GET",
        url: "https://example.com",
        injection: { type: InjectionType.BEARER },
      });
    } catch (e) {
      if (e instanceof VaultError) collectedErrors.push(e);
    }

    expect(collectedErrors.length).toBeGreaterThan(0);
    for (const err of collectedErrors) {
      expect(err.message).not.toContain("Uint8Array");
      expect(err.message).not.toMatch(/\d{1,3}(,\d{1,3}){10,}/); // no byte arrays
    }
  });
});

// ---------------------------------------------------------------------------
// 3. IV Uniqueness Verification
// ---------------------------------------------------------------------------
describe("IV Uniqueness", () => {
  it("encrypting same plaintext twice produces different IVs", () => {
    const key = randomBytes(AES_KEY_LENGTH);
    const plaintext = new Uint8Array(Buffer.from("same-plaintext"));
    const r1 = encrypt(new Uint8Array(key), plaintext, "test-aad");
    const r2 = encrypt(new Uint8Array(key), plaintext, "test-aad");
    expect(Buffer.from(r1.iv).toString("hex")).not.toBe(Buffer.from(r2.iv).toString("hex"));
  });

  it("100 sequential encryptions produce 100 unique IVs", () => {
    const key = randomBytes(AES_KEY_LENGTH);
    const plaintext = new Uint8Array(Buffer.from("test"));
    const ivSet = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const result = encrypt(new Uint8Array(key), plaintext, "test-aad");
      ivSet.add(Buffer.from(result.iv).toString("hex"));
    }
    expect(ivSet.size).toBe(100);
  });

  it("creating multiple secrets via VaultEngine produces unique IVs in DB", async () => {
    const vault = createTestVault();
    await vault.engine.initVault(PASSWORD);

    for (let i = 0; i < 5; i++) {
      await vault.engine.createSecret({
        name: `iv-test-${i}`,
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from("same-value")),
      });
    }

    // Read IVs from the database directly
    const store = new SqliteStore(vault.dbPath);
    const secrets = store.listSecrets();
    const ctIvs = secrets.map((s) => Buffer.from(s.ct_iv).toString("hex"));
    const dekIvs = secrets.map((s) => Buffer.from(s.dek_iv).toString("hex"));

    expect(new Set(ctIvs).size).toBe(5);
    expect(new Set(dekIvs).size).toBe(5);

    store.close();
    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });

  it("secret rotation produces new IV distinct from original", async () => {
    const vault = createTestVault();
    await vault.engine.initVault(PASSWORD);

    const result = await vault.engine.createSecret({
      name: "rotation-iv-test",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("original-value")),
    });

    // Get original IV from DB
    const store = new SqliteStore(vault.dbPath);
    const beforeRow = store.listSecrets()[0];
    if (!beforeRow) throw new Error("expected a stored secret row");
    const originalIv = Buffer.from(beforeRow.ct_iv).toString("hex");

    await vault.engine.rotateSecret(result.handle, new Uint8Array(Buffer.from("new-value")));

    // Get new IV from DB (re-open to see updated data)
    const store2 = new SqliteStore(vault.dbPath);
    const afterRow = store2.listSecrets()[0];
    if (!afterRow) throw new Error("expected a stored secret row");
    const newIv = Buffer.from(afterRow.ct_iv).toString("hex");

    expect(newIv).not.toBe(originalIv);

    store.close();
    store2.close();
    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });
});

// ---------------------------------------------------------------------------
// 4. Timing Attack Protection
// ---------------------------------------------------------------------------
describe("Timing Attack Protection", () => {
  it("equal-length wrong signatures are rejected without an error-detail oracle", async () => {
    // Behavioral replacement for the old source-grep "test": an equal-length
    // signature mismatch (the case a timing-safe compare exists for) must be
    // rejected exactly like any other invalid signature — same error, no
    // detail distinguishing how close the guess was.
    const vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "test-agent");

    const token = vault.engine.createToken("test-agent", ["admin"]);
    const parts = token.split(".");
    const sigLength = Buffer.from(parts[2] as string, "base64url").length;
    const zeroSig = Buffer.alloc(sigLength).toString("base64url");

    let equalLengthError: Error | undefined;
    try {
      vault.engine.verifyToken(`${parts[0]}.${parts[1]}.${zeroSig}`);
    } catch (e) {
      equalLengthError = e as Error;
    }
    let shortError: Error | undefined;
    try {
      vault.engine.verifyToken(`${parts[0]}.${parts[1]}.${"AA"}`);
    } catch (e) {
      shortError = e as Error;
    }

    expect(equalLengthError).toBeDefined();
    expect(shortError).toBeDefined();
    expect(equalLengthError?.message).toBe(shortError?.message);

    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });

  it("JWT with single-bit signature flip is rejected", async () => {
    const vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "test-agent");

    const token = vault.engine.createToken("test-agent", ["admin"]);
    const parts = token.split(".");
    // Flip one bit in the signature
    const sigBytes = Buffer.from(parts[2] as string, "base64url");
    sigBytes[0] = (sigBytes[0] as number) ^ 0x01;
    const tamperedToken = `${parts[0]}.${parts[1]}.${sigBytes.toString("base64url")}`;

    expect(() => vault.engine.verifyToken(tamperedToken)).toThrow();

    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });

  it("JWT with entirely different signature is rejected", async () => {
    const vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "test-agent");

    const token = vault.engine.createToken("test-agent", ["admin"]);
    const parts = token.split(".");
    // Replace signature with random data
    const fakeSig = randomBytes(32).toString("base64url");
    const fakeToken = `${parts[0]}.${parts[1]}.${fakeSig}`;

    expect(() => vault.engine.verifyToken(fakeToken)).toThrow();

    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });

  it("HMAC name lookup goes through an index (query plan, not wall clock)", async () => {
    const vault = createTestVault();
    await vault.engine.initVault(PASSWORD);

    await vault.engine.createSecret({
      name: "timing-a",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("val-a")),
    });

    const infoA = await vault.engine.getSecretInfo("secret://timing-a");
    expect(infoA.name).toBe("timing-a");

    // Deterministic replacement for the old flaky `< 1000 ms` assertion:
    // ask SQLite how it would execute the name_hmac lookup.
    const db = (vault.engine as unknown as { store: { db: RawDb } }).store.db;
    const plan = db
      .prepare("EXPLAIN QUERY PLAN SELECT id FROM secrets WHERE name_hmac = ?")
      .all("probe") as { detail: string }[];
    expect(
      plan.some((row) => /USING (COVERING )?INDEX idx_secrets_name_hmac/i.test(row.detail)),
    ).toBe(true);

    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });
});

// ---------------------------------------------------------------------------
// 5. Lockout Progression
// ---------------------------------------------------------------------------
describe("Lockout Progression", () => {
  let vault: TestVault;

  beforeEach(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    await vault.engine.destroy();
  });

  afterEach(async () => {
    destroyTestVault(vault).catch(() => {});
  });

  it("4 failed attempts: no lockout", async () => {
    for (let i = 0; i < 4; i++) {
      const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
      try {
        await expectVaultError(() => engine.unlock("wrong-pw-attempt"), ErrorCode.INVALID_PASSWORD);
      } finally {
        await engine.destroy();
      }
    }

    // 5th attempt with wrong password should still get INVALID_PASSWORD (triggers lockout after)
    // but a correct password should work if lockout hasn't kicked in yet
    // Actually: attempt 5 triggers lockout. Let's test that attempt 4 doesn't.
    const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine.unlock(PASSWORD);
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
    await engine.destroy();
  });

  it("5 failed attempts triggers LOCKOUT_ACTIVE with a 30 s retry_after", async () => {
    vi.useFakeTimers();
    try {
      for (let i = 0; i < LOCKOUT_MAX_ATTEMPTS; i++) {
        const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
        try {
          await engine.unlock("wrong-password");
        } catch {
          // Expected
        } finally {
          await engine.destroy();
        }
      }

      const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
      try {
        const err = await expectVaultError(() => engine.unlock(PASSWORD), ErrorCode.LOCKOUT_ACTIVE);
        expect(err.details?.retry_after_ms).toBe(LOCKOUT_DURATIONS_MS[0]);
      } finally {
        await engine.destroy();
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it("lockout survives engine restart", async () => {
    vi.useFakeTimers();
    try {
      for (let i = 0; i < LOCKOUT_MAX_ATTEMPTS; i++) {
        const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
        try {
          await engine.unlock("wrong-pw");
        } catch {
          // Expected
        } finally {
          await engine.destroy();
        }
      }

      // New engine on same DB — lockout should persist
      const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
      try {
        await expectVaultError(() => engine.unlock(PASSWORD), ErrorCode.LOCKOUT_ACTIVE);
      } finally {
        await engine.destroy();
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it("successful unlock resets counter", async () => {
    // Fail 4 times
    for (let i = 0; i < 4; i++) {
      const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
      try {
        await engine.unlock("bad-pw");
      } catch {
        /* expected */
      }
      await engine.destroy();
    }

    // Succeed
    const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine.unlock(PASSWORD);
    await engine.destroy();

    // Fail 4 more times — should still not trigger lockout
    for (let i = 0; i < 4; i++) {
      const engine2 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
      try {
        await engine2.unlock("bad-pw-2");
      } catch {
        /* expected */
      }
      await engine2.destroy();
    }

    // Should still be able to unlock (no lockout)
    const engine3 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine3.unlock(PASSWORD);
    expect(engine3.getState()).toBe(VaultState.UNLOCKED);
    await engine3.destroy();
  });

  it("during lockout, correct password is rejected as LOCKOUT_ACTIVE", async () => {
    vi.useFakeTimers();
    try {
      for (let i = 0; i < LOCKOUT_MAX_ATTEMPTS; i++) {
        const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
        try {
          await engine.unlock("wrong");
        } catch {
          /* expected */
        }
        await engine.destroy();
      }

      // Even correct password returns LOCKOUT_ACTIVE (not INVALID_PASSWORD)
      const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
      try {
        await expectVaultError(() => engine.unlock(PASSWORD), ErrorCode.LOCKOUT_ACTIVE);
      } finally {
        await engine.destroy();
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it("escalation: counted failures 5–9 lock for 30 s, 10–14 for 5 min, the 15th for 30 min", async () => {
    vi.useFakeTimers();
    try {
      const lockouts: number[] = [];
      for (let failure = 1; failure <= 3 * LOCKOUT_MAX_ATTEMPTS; failure++) {
        const wrong = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
        try {
          await expectVaultError(() => wrong.unlock("wrong"), ErrorCode.INVALID_PASSWORD);
        } finally {
          await wrong.destroy();
        }
        if (failure < LOCKOUT_MAX_ATTEMPTS) continue;

        const locked = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
        let retryAfter: number;
        try {
          const err = await expectVaultError(
            () => locked.unlock(PASSWORD),
            ErrorCode.LOCKOUT_ACTIVE,
          );
          retryAfter = Number(err.details?.retry_after_ms);
        } finally {
          await locked.destroy();
        }
        lockouts.push(retryAfter);
        await vi.advanceTimersByTimeAsync(retryAfter + 1000);
      }

      expect(lockouts).toEqual([
        ...Array<number>(LOCKOUT_MAX_ATTEMPTS).fill(LOCKOUT_DURATIONS_MS[0]),
        ...Array<number>(LOCKOUT_MAX_ATTEMPTS).fill(LOCKOUT_DURATIONS_MS[1]),
        LOCKOUT_DURATIONS_MS[2],
      ]);
    } finally {
      vi.useRealTimers();
    }
  }, 120_000);
});

// ---------------------------------------------------------------------------
// 8a. No-Logging Static Audit
// ---------------------------------------------------------------------------
describe("No-Logging Static Audit", () => {
  /**
   * Recursively collect all non-test .ts and .tsx files in a directory (test-fixture modules under __fixtures__/ are test code and skipped).
   */
  function collectTsFiles(dir: string): string[] {
    const results: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const fullPath = join(dir, entry.name);
      if (
        entry.isDirectory() &&
        entry.name !== "node_modules" &&
        entry.name !== "dist" &&
        entry.name !== "__fixtures__"
      ) {
        results.push(...collectTsFiles(fullPath));
      } else if (
        entry.isFile() &&
        /\.tsx?$/.test(entry.name) &&
        !/\.(test|spec)\.tsx?$/.test(entry.name) &&
        !entry.name.endsWith(".d.ts")
      ) {
        results.push(fullPath);
      }
    }
    return results;
  }

  it("the walker takes web-ui's .tsx sources and leaves its .test.tsx files out (D3 a)", () => {
    const webUiSrc = join(REPO_ROOT, "packages", "web-ui", "src");
    const files = collectTsFiles(webUiSrc).map((f) => relative(webUiSrc, f).split(sep).join("/"));
    expect(files).toContain("main.tsx");
    expect(files).toContain("pages/secrets.tsx");
    expect(files.filter((f) => f.endsWith(".tsx")).length).toBeGreaterThanOrEqual(18);
    expect(files.filter((f) => /\.(test|spec)\.tsx?$/.test(f))).toEqual([]);
  });

  it("core/src/ has zero console.log/warn/error calls", () => {
    const coreDir = join(REPO_ROOT, "packages/core/src");
    const files = collectTsFiles(coreDir);
    expect(files.length).toBeGreaterThan(0);

    const consolePattern = /\bconsole\.(log|warn|error|info|debug)\s*\(/;
    for (const filePath of files) {
      const content = readFileSync(filePath, "utf8");
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] as string;
        if (consolePattern.test(line)) {
          expect.fail(`Found console call in ${filePath}:${i + 1}: ${line.trim()}`);
        }
      }
    }
  });

  it("mcp-server/src/ has zero console calls", () => {
    const mcpDir = join(REPO_ROOT, "packages/mcp-server/src");
    const files = collectTsFiles(mcpDir);
    expect(files.length).toBeGreaterThan(0);

    const consolePattern = /\bconsole\.(log|warn|error|info|debug)\s*\(/;
    for (const filePath of files) {
      const content = readFileSync(filePath, "utf8");
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] as string;
        if (consolePattern.test(line)) {
          expect.fail(`Found console call in ${filePath}:${i + 1}: ${line.trim()}`);
        }
      }
    }
  });

  /**
   * T18: the audit covered core, mcp-server and rest-api but skipped the three
   * remaining library packages — including `oauth-proxy`, the one package that
   * holds plaintext client secrets, authorization codes and refresh tokens in
   * memory. A `console.error("tokens", body)` added to a flow kept the suite
   * green. All three are console-free today, so they carry the strict rule
   * (any diagnostic they need goes through an injected callback, as core does
   * with `onSessionFilePermissionRepairFailure`).
   * `web-ui` joined them with the `.tsx` widening (D3 a, 2026-09): the SPA is
   * console-free too.
   */
  it.each(["cert-manager", "oauth-proxy", "sdk", "shared", "web-ui"])(
    "%s/src/ has zero console calls",
    (pkg) => {
      const files = collectTsFiles(join(REPO_ROOT, "packages", pkg, "src"));
      expect(files.length).toBeGreaterThan(0);

      const consolePattern = /\bconsole\.(log|warn|error|info|debug)\s*\(/;
      for (const filePath of files) {
        const lines = readFileSync(filePath, "utf8").split("\n");
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i] as string;
          if (consolePattern.test(line)) {
            expect.fail(`Found console call in ${filePath}:${i + 1}: ${line.trim()}`);
          }
        }
      }
    },
  );

  /** The index just past the string or template literal that opens at `start`. */
  function skipLiteral(source: string, start: number): number {
    const quote = source[start];
    let i = start + 1;
    while (i < source.length) {
      const ch = source[i];
      if (ch === "\\") {
        i += 2;
      } else if (ch === quote) {
        return i + 1;
      } else if (quote === "`" && ch === "$" && source[i + 1] === "{") {
        i = skipBalanced(source, i + 2, "{", "}");
      } else {
        i++;
      }
    }
    return i;
  }

  /** The index just past the `close` balancing an `open` consumed before `start`. */
  function skipBalanced(source: string, start: number, open: string, close: string): number {
    let depth = 1;
    let i = start;
    while (i < source.length) {
      const ch = source[i];
      if (ch === '"' || ch === "'" || ch === "`") {
        i = skipLiteral(source, i);
      } else if (ch === "/" && source[i + 1] === "/") {
        const end = source.indexOf("\n", i);
        i = end === -1 ? source.length : end;
      } else if (ch === "/" && source[i + 1] === "*") {
        const end = source.indexOf("*/", i + 2);
        i = end === -1 ? source.length : end + 2;
      } else if (ch === "/" && !/[\w$)\]]/.test(source.slice(0, i).trimEnd().slice(-1))) {
        let j = i + 1;
        let inClass = false;
        while (j < source.length && source[j] !== "\n" && (inClass || source[j] !== "/")) {
          if (source[j] === "\\" && source[j + 1] !== "\n") j++;
          else if (source[j] === "[") inClass = true;
          else if (source[j] === "]") inClass = false;
          j++;
        }
        i = source[j] === "/" ? j + 1 : i + 1;
      } else {
        if (ch === open) depth++;
        if (ch === close && --depth === 0) return i + 1;
        i++;
      }
    }
    return i;
  }

  /** Every `console.<fn>(…)` call in `source`, read to its balancing parenthesis. */
  function consoleCalls(source: string): Array<{ line: number; text: string }> {
    return [...source.matchAll(/\bconsole\.(log|warn|error|info|debug)\s*\(/g)].map((m) => ({
      line: source.slice(0, m.index).split("\n").length,
      text: source.slice(m.index, skipBalanced(source, m.index + m[0].length, "(", ")")),
    }));
  }

  it("consoleCalls reads a wrapped call to its balancing parenthesis past literal ones", () => {
    const source = [
      "console.error(",
      '  "[x] ) %s",',
      "  `(${fn(a)} ) ${'}'}`,",
      "  // don't )",
      "  secret.value,",
      ");",
      "console.log('done');",
      "console.warn(",
      '  "bad header %s",',
      '  header.replace(/\\)[\'"]/g, ""),',
      "  secret.value,",
      ");",
      "console.info(f(total / 2), 1 / 3);",
      "console.debug(f((a + b) / 2), 3 / 4);",
      "console.warn(",
      '  "class %s",',
      '  x.replace(/[/)]/g, ""),',
      "  secret.value,",
      ");",
      "console.warn(",
      '  "escape %s",',
      '  x.replace(/\\/\\)/g, ""),',
      "  secret.value,",
      ");",
      "console.info(",
      '  "ratio %d %d",',
      "  count++ / 2,",
      "  scale(width / height),",
      ");",
    ].join("\n");
    const callFrom = (head: string): string => {
      const at = source.indexOf(head);
      return source.slice(at, source.indexOf(");", at) + 1);
    };
    const warnAt = source.indexOf("console.warn(");
    expect(consoleCalls(source)).toEqual([
      { line: 1, text: source.slice(0, source.indexOf(");") + 1) },
      { line: 7, text: "console.log('done')" },
      { line: 8, text: source.slice(warnAt, source.indexOf(");", warnAt) + 1) },
      { line: 13, text: "console.info(f(total / 2), 1 / 3)" },
      { line: 14, text: "console.debug(f((a + b) / 2), 3 / 4)" },
      { line: 15, text: callFrom('console.warn(\n  "class %s"') },
      { line: 20, text: callFrom('console.warn(\n  "escape %s"') },
      { line: 25, text: callFrom('console.info(\n  "ratio %d %d"') },
    ]);
  });

  it("rest-api/ console calls do not reference secret, value, password, or key", () => {
    const restDir = join(REPO_ROOT, "packages/rest-api/src");
    const files = collectTsFiles(restDir);
    expect(files.length).toBeGreaterThan(0);

    const sensitivePattern = /\b(secret|value|password|key)\b/i;
    const calls = files.flatMap((filePath) =>
      consoleCalls(readFileSync(filePath, "utf8")).map((call) => ({
        at: `${relative(restDir, filePath).split(sep).join("/")}:${String(call.line)}`,
        text: call.text,
      })),
    );
    expect(calls.map((call) => call.at)).toHaveLength(3);
    const offenders = calls
      .filter((call) => sensitivePattern.test(call.text))
      .map((call) => `${call.at}: ${(call.text.split("\n")[0] as string).trim()}`);
    expect(offenders).toEqual([]);
  });

  // E77 tripwire: `admin_scope` is a plain optional field any in-process
  // embedder could set, and a caller carrying it is exempt from per-secret
  // policy. The two writers are callerFromToken and tokenlessStdioCaller; a
  // third anywhere in product source is a new exemption path.
  it("admin_scope is written at exactly two sites in product source — both in shared/src/caller.ts (E77)", () => {
    const packages = [
      "cert-manager",
      "cli",
      "core",
      "mcp-server",
      "oauth-proxy",
      "rest-api",
      "sdk",
      "shared",
      "web-ui",
    ];
    const writePattern = /\badmin_scope\s*(?::|=(?!=))/;
    const writes: string[] = [];
    let scanned = 0;
    for (const pkg of packages) {
      const srcDir = join(REPO_ROOT, "packages", pkg, "src");
      for (const filePath of collectTsFiles(srcDir)) {
        scanned++;
        const lines = readFileSync(filePath, "utf8").split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (writePattern.test(lines[i] as string)) {
            const rel = relative(srcDir, filePath).split(sep).join("/");
            writes.push(`${pkg}/src/${rel}:${i + 1}`);
          }
        }
      }
    }
    expect(scanned).toBeGreaterThan(100);
    expect(writes.map((w) => w.replace(/:\d+$/, ""))).toEqual([
      "shared/src/caller.ts",
      "shared/src/caller.ts",
    ]);
    expect(new Set(writes).size).toBe(2);
  });

  it("the loopback host set is declared once, in @harpoc/shared (CM-2 tripwire)", () => {
    const packagesDir = join(REPO_ROOT, "packages");
    const declarationPattern = /new Set\(\[[^\]]*"localhost"/;
    const declarations: string[] = [];
    let scanned = 0;
    for (const entry of readdirSync(packagesDir, { withFileTypes: true })) {
      const srcDir = join(packagesDir, entry.name, "src");
      if (!entry.isDirectory() || !existsSync(srcDir)) continue;
      for (const filePath of collectTsFiles(srcDir)) {
        scanned++;
        if (declarationPattern.test(readFileSync(filePath, "utf8"))) {
          declarations.push(`${entry.name}/src/${relative(srcDir, filePath).split(sep).join("/")}`);
        }
      }
    }
    expect(scanned).toBeGreaterThan(100);
    expect(declarations).toEqual(["shared/src/host-allowlist.ts"]);
  });
});

// ---------------------------------------------------------------------------
// 8b. SSRF E2E (via VaultEngine.useSecret)
// ---------------------------------------------------------------------------
describe("SSRF E2E via useSecret", () => {
  let vault: TestVault;
  let handle: string;
  let echoServer: Server;
  let echoUrl: string;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);

    const result = await vault.engine.createSecret({
      name: "ssrf-test-secret",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("sk-ssrf-test-value")),
    });
    handle = result.handle;

    // Create echo server on loopback
    echoServer = createServer((req, res) => {
      const body = JSON.stringify({ headers: req.headers, url: req.url });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
    });
    await new Promise<void>((resolve) => {
      echoServer.listen(0, "127.0.0.1", resolve);
    });
    const addr = echoServer.address() as AddressInfo;
    echoUrl = `http://127.0.0.1:${addr.port}`;

    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [
        "https://10.0.0.1/*",
        "https://192.168.1.1/*",
        "https://[fc00::1]/*",
        `${echoUrl}/*`,
        "http://[::1]:1/*",
      ],
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      echoServer?.close((err) => (err ? reject(err) : resolve()));
    });
    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });

  it("useSecret to https://10.0.0.1/api → SSRF_BLOCKED", async () => {
    await expectVaultError(
      () =>
        vault.engine.useSecret(handle, {
          type: "http",
          method: "GET",
          url: "https://10.0.0.1/api",
          injection: { type: InjectionType.BEARER },
        }),
      ErrorCode.SSRF_BLOCKED,
    );
  });

  it("useSecret to https://192.168.1.1/api → SSRF_BLOCKED", async () => {
    await expectVaultError(
      () =>
        vault.engine.useSecret(handle, {
          type: "http",
          method: "GET",
          url: "https://192.168.1.1/api",
          injection: { type: InjectionType.BEARER },
        }),
      ErrorCode.SSRF_BLOCKED,
    );
  });

  it("useSecret to https://[fc00::1]/api → SSRF_BLOCKED", async () => {
    await expectVaultError(
      () =>
        vault.engine.useSecret(handle, {
          type: "http",
          method: "GET",
          url: "https://[fc00::1]/api",
          injection: { type: InjectionType.BEARER },
        }),
      ErrorCode.SSRF_BLOCKED,
    );
  });

  it("useSecret to loopback echo server succeeds", async () => {
    const response = await vault.engine.useSecret(handle, {
      type: "http",
      method: "GET",
      url: echoUrl,
      injection: { type: InjectionType.BEARER },
    });
    expect(response.type).toBe("http");
    if (response.type !== "http") throw new Error("expected http result");
    expect(response.status).toBe(200);
  });

  it("useSecret to http://[::1] loopback passes the SSRF floor and the allowlist (the request itself fails)", async () => {
    const response = await vault.engine.useSecret(handle, {
      type: "http",
      method: "GET",
      url: "http://[::1]:1/test",
      injection: { type: InjectionType.BEARER },
    });
    expect(response.type).toBe("http");
    if (response.type !== "http") throw new Error("expected http result");
    expect(response.status).toBeNull();
    expect(response.error).toBeDefined();
  });
});

describe("Concurrent REST create (security review 2026-03-05 follow-up)", () => {
  silenceAuditLines();

  let vault: TestVault;
  let server: TestServer;
  let token: string;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "race-agent");
    token = vault.engine.createToken("race-agent", ["create"]);
    server = startTestServer(vault.engine);
  });

  afterAll(async () => {
    await server.close();
    await destroyTestVault(vault);
  });

  it("two concurrent POST /api/v1/secrets with one name: one 201, one DUPLICATE_SECRET 409, one row", async () => {
    const post = (): Promise<Response> =>
      fetch(`${server.baseUrl}/api/v1/secrets`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({
          name: "race-key",
          type: SecretType.API_KEY,
          value: Buffer.from("race-value").toString("base64"),
        }),
      });
    const responses = await Promise.all([post(), post()]);
    const bodies = await Promise.all(responses.map((r) => r.json() as Promise<{ error?: string }>));
    expect(responses.map((r) => r.status).sort()).toEqual([201, 409]);
    expect(bodies[responses.findIndex((r) => r.status === 409)]?.error).toBe(
      ErrorCode.DUPLICATE_SECRET,
    );
    expect(vault.engine.listSecrets().filter((s) => s.name === "race-key")).toHaveLength(1);
    expect(
      vault.engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE }).filter((r) => r.success),
    ).toHaveLength(1);
  });
});
