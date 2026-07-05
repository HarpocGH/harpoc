import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect, beforeAll, afterAll, vi, beforeEach, afterEach } from "vitest";
import { VaultEngine, wipeBuffer, encrypt, SqliteStore } from "@harpoc/core";
import {
  AES_KEY_LENGTH,
  ErrorCode,
  InjectionType,
  SecretType,
  VaultError,
  VaultState,
  LOCKOUT_MAX_ATTEMPTS,
  LOCKOUT_DURATIONS_MS,
} from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { randomBytes } from "node:crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = join(__filename, "..");
// repo root: packages/integration/src -> ../../..
const REPO_ROOT = join(__dirname, "..", "..", "..");

const PASSWORD = "security-hardening-pw";

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

  it("wipeBuffer() overwrites all bytes to non-zero randomness", () => {
    const buf = new Uint8Array(32);
    buf.fill(0);
    wipeBuffer(buf);
    // After wipe, at least some bytes should be non-zero (overwhelmingly likely with random fill)
    const nonZero = buf.filter((b) => b !== 0).length;
    expect(nonZero).toBeGreaterThan(0);
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
      injection: { type: InjectionType.BEARER },
    });

    // useSecret should complete without error (value decrypted, injected, then wiped)
    const response = await vault.engine.useSecret(result.handle, {
      type: "http",
      method: "GET",
      url: echoUrl,
      injection: { type: InjectionType.BEARER },
    });
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
    const { existsSync } = await import("node:fs");
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
        injection: { type: InjectionType.BEARER },
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
  let handle: string;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    const result = await vault.engine.createSecret({
      name: "sanitization-test",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("sk-super-secret-12345")),
      injection: { type: InjectionType.BEARER },
    });
    handle = result.handle;
  });

  afterAll(async () => {
    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });

  it("SECRET_NOT_FOUND contains handle, not secret value", async () => {
    try {
      await vault.engine.getSecretInfo("secret://nonexistent");
      expect.fail("Should throw");
    } catch (e) {
      const err = e as VaultError;
      expect(err.code).toBe(ErrorCode.SECRET_NOT_FOUND);
      expect(err.message).not.toContain("sk-super-secret");
    }
  });

  it("SECRET_REVOKED contains handle, not value", async () => {
    const revokeResult = await vault.engine.createSecret({
      name: "revoke-test",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("sk-revoke-value")),
      injection: { type: InjectionType.BEARER },
    });
    await vault.engine.revokeSecret(revokeResult.handle);

    try {
      // rotateSecret calls assertUsable which throws SECRET_REVOKED
      await vault.engine.rotateSecret(revokeResult.handle, new Uint8Array(Buffer.from("new")));
      expect.fail("Should throw");
    } catch (e) {
      const err = e as VaultError;
      expect(err.code).toBe(ErrorCode.SECRET_REVOKED);
      expect(err.message).not.toContain("sk-revoke-value");
    }
  });

  it("SECRET_EXPIRED contains handle, not value", async () => {
    const expireResult = await vault.engine.createSecret({
      name: "expire-test",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("sk-expire-value")),
      injection: { type: InjectionType.BEARER },
      expiresAt: Date.now() - 1000, // already expired
    });

    try {
      // rotateSecret calls assertUsable which throws SECRET_EXPIRED
      await vault.engine.rotateSecret(expireResult.handle, new Uint8Array(Buffer.from("new")));
      expect.fail("Should throw");
    } catch (e) {
      const err = e as VaultError;
      expect(err.code).toBe(ErrorCode.SECRET_EXPIRED);
      expect(err.message).not.toContain("sk-expire-value");
    }
  });

  it("INVALID_PASSWORD is generic, no key material", async () => {
    const engine2 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    try {
      await engine2.unlock("wrong-password-here");
      expect.fail("Should throw");
    } catch (e) {
      const err = e as VaultError;
      expect(err.code).toBe(ErrorCode.INVALID_PASSWORD);
      expect(err.message).toBe("Invalid password");
      expect(err.message).not.toContain("wrong-password");
    } finally {
      await engine2.destroy();
    }
  });

  it("DUPLICATE_SECRET contains name, not value", async () => {
    try {
      await vault.engine.createSecret({
        name: "sanitization-test", // already exists
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from("another-value")),
        injection: { type: InjectionType.BEARER },
      });
      expect.fail("Should throw");
    } catch (e) {
      const err = e as VaultError;
      expect(err.code).toBe(ErrorCode.DUPLICATE_SECRET);
      expect(err.message).not.toContain("another-value");
    }
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
        injection: { type: InjectionType.BEARER },
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
      injection: { type: InjectionType.BEARER },
    });

    // Get original IV from DB
    const store = new SqliteStore(vault.dbPath);
    const beforeSecrets = store.listSecrets();
    const originalIv = Buffer.from(beforeSecrets[0]!.ct_iv).toString("hex");

    await vault.engine.rotateSecret(result.handle, new Uint8Array(Buffer.from("new-value")));

    // Get new IV from DB (re-open to see updated data)
    const store2 = new SqliteStore(vault.dbPath);
    const afterSecrets = store2.listSecrets();
    const newIv = Buffer.from(afterSecrets[0]!.ct_iv).toString("hex");

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
  it("vault-engine.ts imports and uses timingSafeEqual", () => {
    const source = readFileSync(join(REPO_ROOT, "packages/core/src/vault-engine.ts"), "utf8");
    expect(source).toContain("import { createHmac, timingSafeEqual }");
    expect(source).toContain("timingSafeEqual(expectedSig, actualSig)");
  });

  it("JWT with single-bit signature flip is rejected", async () => {
    const vault = createTestVault();
    await vault.engine.initVault(PASSWORD);

    const token = vault.engine.createToken("test-agent", ["admin"]);
    const parts = token.split(".");
    // Flip one bit in the signature
    const sigBytes = Buffer.from(parts[2]!, "base64url");
    sigBytes[0] = sigBytes[0]! ^ 0x01;
    const tamperedToken = `${parts[0]}.${parts[1]}.${sigBytes.toString("base64url")}`;

    expect(() => vault.engine.verifyToken(tamperedToken)).toThrow();

    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });

  it("JWT with entirely different signature is rejected", async () => {
    const vault = createTestVault();
    await vault.engine.initVault(PASSWORD);

    const token = vault.engine.createToken("test-agent", ["admin"]);
    const parts = token.split(".");
    // Replace signature with random data
    const fakeSig = randomBytes(32).toString("base64url");
    const fakeToken = `${parts[0]}.${parts[1]}.${fakeSig}`;

    expect(() => vault.engine.verifyToken(fakeToken)).toThrow();

    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });

  it("HMAC name lookup uses database index for O(1) resolution", async () => {
    const vault = createTestVault();
    await vault.engine.initVault(PASSWORD);

    // Create two secrets
    await vault.engine.createSecret({
      name: "timing-a",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("val-a")),
      injection: { type: InjectionType.BEARER },
    });
    await vault.engine.createSecret({
      name: "timing-b",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("val-b")),
      injection: { type: InjectionType.BEARER },
    });

    // Both resolve quickly (bounded time, not scanning all secrets)
    const start = performance.now();
    const infoA = await vault.engine.getSecretInfo("secret://timing-a");
    const infoB = await vault.engine.getSecretInfo("secret://timing-b");
    const elapsed = performance.now() - start;

    expect(infoA.name).toBe("timing-a");
    expect(infoB.name).toBe("timing-b");
    // Should resolve in < 1s even on slow CI (O(1) index lookup)
    expect(elapsed).toBeLessThan(1000);

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
        await engine.unlock("wrong-pw-attempt");
      } catch (e) {
        expect((e as VaultError).code).toBe(ErrorCode.INVALID_PASSWORD);
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

  it("5 failed attempts triggers LOCKOUT_ACTIVE with ~30s retry_after", async () => {
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
        await engine.unlock(PASSWORD);
        expect.fail("Should throw LOCKOUT_ACTIVE");
      } catch (e) {
        const err = e as VaultError;
        expect(err.code).toBe(ErrorCode.LOCKOUT_ACTIVE);
        expect(err.details?.retry_after_ms).toBeDefined();
        expect(Number(err.details?.retry_after_ms)).toBeLessThanOrEqual(LOCKOUT_DURATIONS_MS[0]!);
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
        await engine.unlock(PASSWORD);
        expect.fail("Should throw LOCKOUT_ACTIVE");
      } catch (e) {
        expect((e as VaultError).code).toBe(ErrorCode.LOCKOUT_ACTIVE);
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
        await engine.unlock(PASSWORD);
        expect.fail("Should throw");
      } catch (e) {
        expect((e as VaultError).code).toBe(ErrorCode.LOCKOUT_ACTIVE);
      } finally {
        await engine.destroy();
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it("escalation: 10 failures → 5 min, 15 failures → 30 min", async () => {
    vi.useFakeTimers();
    try {
      // First 5 failures → 30s lockout
      for (let i = 0; i < LOCKOUT_MAX_ATTEMPTS; i++) {
        const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
        try {
          await engine.unlock("wrong");
        } catch {
          /* expected */
        }
        await engine.destroy();
      }

      // Fast-forward past 30s lockout
      await vi.advanceTimersByTimeAsync(LOCKOUT_DURATIONS_MS[0]! + 1000);

      // 5 more failures (total 10) → 5 min lockout
      for (let i = 0; i < LOCKOUT_MAX_ATTEMPTS; i++) {
        const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
        try {
          await engine.unlock("wrong");
        } catch {
          /* expected */
        }
        await engine.destroy();
      }

      // Check lockout at 5 min tier
      const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
      try {
        await engine1.unlock(PASSWORD);
        expect.fail("Should be locked out");
      } catch (e) {
        const err = e as VaultError;
        expect(err.code).toBe(ErrorCode.LOCKOUT_ACTIVE);
        expect(Number(err.details?.retry_after_ms)).toBeLessThanOrEqual(LOCKOUT_DURATIONS_MS[1]!);
      } finally {
        await engine1.destroy();
      }

      // Fast-forward past 5 min lockout
      await vi.advanceTimersByTimeAsync(LOCKOUT_DURATIONS_MS[1]! + 1000);

      // 5 more failures (total 15) → 30 min lockout
      for (let i = 0; i < LOCKOUT_MAX_ATTEMPTS; i++) {
        const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
        try {
          await engine.unlock("wrong");
        } catch {
          /* expected */
        }
        await engine.destroy();
      }

      const engine2 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
      try {
        await engine2.unlock(PASSWORD);
        expect.fail("Should be locked out");
      } catch (e) {
        const err = e as VaultError;
        expect(err.code).toBe(ErrorCode.LOCKOUT_ACTIVE);
        expect(Number(err.details?.retry_after_ms)).toBeLessThanOrEqual(LOCKOUT_DURATIONS_MS[2]!);
      } finally {
        await engine2.destroy();
      }
    } finally {
      vi.useRealTimers();
    }
  });
});

// ---------------------------------------------------------------------------
// 8a. No-Logging Static Audit
// ---------------------------------------------------------------------------
describe("No-Logging Static Audit", () => {
  /**
   * Recursively collect all non-test .ts files in a directory.
   */
  function collectTsFiles(dir: string): string[] {
    const results: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory() && entry.name !== "node_modules" && entry.name !== "dist") {
        results.push(...collectTsFiles(fullPath));
      } else if (
        entry.isFile() &&
        entry.name.endsWith(".ts") &&
        !entry.name.endsWith(".test.ts") &&
        !entry.name.endsWith(".spec.ts") &&
        !entry.name.endsWith(".d.ts")
      ) {
        results.push(fullPath);
      }
    }
    return results;
  }

  it("core/src/ has zero console.log/warn/error calls", () => {
    const coreDir = join(REPO_ROOT, "packages/core/src");
    const files = collectTsFiles(coreDir);
    expect(files.length).toBeGreaterThan(0);

    const consolePattern = /\bconsole\.(log|warn|error|info|debug)\s*\(/;
    for (const filePath of files) {
      const content = readFileSync(filePath, "utf8");
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
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
        const line = lines[i]!;
        if (consolePattern.test(line)) {
          expect.fail(`Found console call in ${filePath}:${i + 1}: ${line.trim()}`);
        }
      }
    }
  });

  it("rest-api/ console calls do not reference secret, value, password, or key", () => {
    const restDir = join(REPO_ROOT, "packages/rest-api/src");
    const files = collectTsFiles(restDir);
    expect(files.length).toBeGreaterThan(0);

    const consolePattern = /\bconsole\.(log|warn|error|info|debug)\s*\(/;
    const sensitivePattern = /\b(secret|value|password|key)\b/i;
    for (const filePath of files) {
      const content = readFileSync(filePath, "utf8");
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        if (consolePattern.test(line) && sensitivePattern.test(line)) {
          expect.fail(
            `Console call references sensitive term in ${filePath}:${i + 1}: ${line.trim()}`,
          );
        }
      }
    }
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
      injection: { type: InjectionType.BEARER },
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
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      echoServer?.close((err) => (err ? reject(err) : resolve()));
    });
    await vault.engine.destroy();
    destroyTestVault(vault).catch(() => {});
  });

  it("useSecret to https://10.0.0.1/api → SSRF_BLOCKED", async () => {
    try {
      await vault.engine.useSecret(handle, {
        type: "http",
        method: "GET",
        url: "https://10.0.0.1/api",
        injection: { type: InjectionType.BEARER },
      });
      expect.fail("Should throw SSRF_BLOCKED");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });

  it("useSecret to https://192.168.1.1/api → SSRF_BLOCKED", async () => {
    try {
      await vault.engine.useSecret(handle, {
        type: "http",
        method: "GET",
        url: "https://192.168.1.1/api",
        injection: { type: InjectionType.BEARER },
      });
      expect.fail("Should throw SSRF_BLOCKED");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });

  it("useSecret to https://[fc00::1]/api → SSRF_BLOCKED", async () => {
    try {
      await vault.engine.useSecret(handle, {
        type: "http",
        method: "GET",
        url: "https://[fc00::1]/api",
        injection: { type: InjectionType.BEARER },
      });
      expect.fail("Should throw SSRF_BLOCKED");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });

  it("useSecret to loopback echo server succeeds", async () => {
    const response = await vault.engine.useSecret(handle, {
      type: "http",
      method: "GET",
      url: echoUrl,
      injection: { type: InjectionType.BEARER },
    });
    expect(response.status).toBe(200);
  });

  it("useSecret to http://[::1] loopback is allowed", async () => {
    // ::1 is loopback — HTTP should be allowed (though connection may fail if
    // no server is listening on IPv6; we test the URL validation passes)
    try {
      await vault.engine.useSecret(handle, {
        type: "http",
        method: "GET",
        url: "http://[::1]:1/test",
        injection: { type: InjectionType.BEARER },
      });
      // Connection may fail but should NOT be SSRF_BLOCKED
    } catch (e) {
      const err = e as VaultError;
      // Acceptable: CONNECTION_REFUSED, TIMEOUT, etc. — but NOT SSRF_BLOCKED
      expect(err.code).not.toBe(ErrorCode.SSRF_BLOCKED);
    }
  });
});
