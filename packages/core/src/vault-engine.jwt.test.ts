import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import type { VaultEngineOptions } from "./vault-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";

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

describe("JWT tokens", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    registerAgents(engine, "user-1");
  });

  it("creates and verifies a token", () => {
    const token = engine.createToken("user-1", ["read", "use"]);
    const decoded = engine.verifyToken(token);

    expect(decoded.sub).toBe("user-1");
    expect(decoded.scope).toEqual(["read", "use"]);
  });

  it("always mints the principal_type claim, defaulting to agent", () => {
    const token = engine.createToken("user-1", ["read"]);
    expect(engine.verifyToken(token).principal_type).toBe("agent");
  });

  it("refuses a signed payload without a principal_type claim (N13 claim-shape check)", async () => {
    const internals = engine as unknown as {
      signJwt(payload: Record<string, unknown>): string;
      vaultId: string;
    };
    const now = Math.floor(Date.now() / 1000);
    const base = {
      sub: "user-1",
      vault_id: internals.vaultId,
      scope: ["read"],
      iat: now,
      exp: now + 60,
    };
    const claimless = internals.signJwt({ ...base, jti: "jti-claimless" });
    await expectVaultError(() => engine.verifyToken(claimless), ErrorCode.INVALID_TOKEN);

    const bogus = internals.signJwt({ ...base, jti: "jti-bogus", principal_type: "root" });
    await expectVaultError(() => engine.verifyToken(bogus), ErrorCode.INVALID_TOKEN);
  });

  it("carries secret-name patterns in the secrets claim (thesis §4.7)", () => {
    const token = engine.createToken("user-1", ["use"], 60_000, {
      secrets: ["db-*", "api-key"],
    });
    const decoded = engine.verifyToken(token);
    expect(decoded.secrets).toEqual(["db-*", "api-key"]);
  });

  it("rejects an invalid secret-name pattern at creation", async () => {
    for (const pattern of ["db/*", "db prod", "", "[a]"]) {
      await expectVaultError(
        () => engine.createToken("user-1", ["use"], 60_000, { secrets: [pattern] }),
        ErrorCode.INVALID_SECRET_NAME,
      );
    }
  });

  it("rejects invalid token", async () => {
    await expectVaultError(() => engine.verifyToken("bad.token.here"), ErrorCode.INVALID_TOKEN);
  });

  it("revokes a token", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const decoded = engine.verifyToken(token);

    engine.revokeToken(decoded.jti);

    await expectVaultError(() => engine.verifyToken(token), ErrorCode.TOKEN_REVOKED);
  });

  it("revoked token persists across engine restart", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const decoded = engine.verifyToken(token);
    engine.revokeToken(decoded.jti);
    await engine.lock();

    // Re-open engine, same DB
    const engine2 = secondEngine({ dbPath, sessionPath });
    await engine2.unlock("password");

    await expectVaultError(() => engine2.verifyToken(token), ErrorCode.TOKEN_REVOKED);
    await engine2.destroy();
  });

  it("rejects token from different vault (vault_id mismatch)", async () => {
    const token = engine.createToken("user-1", ["read"]);
    await engine.destroy();

    // Create a second vault
    const tempDir2 = join(tempDir, "vault2");
    mkdirSync(tempDir2, { recursive: true });
    const engine2 = secondEngine({
      dbPath: join(tempDir2, "test.vault.db"),
      sessionPath: join(tempDir2, "session.json"),
    });
    await engine2.initVault("password");

    await expectVaultError(() => engine2.verifyToken(token), ErrorCode.INVALID_TOKEN);
    await engine2.destroy();
  });

  it("rejects expired token", async () => {
    // Create token with 0 TTL (immediately expired)
    const token = engine.createToken("user-1", ["read"], 0);

    await expectVaultError(() => engine.verifyToken(token), ErrorCode.TOKEN_EXPIRED);
  });

  it("caps token TTL at MAX_TOKEN_TTL_MS", () => {
    // Request 7 days — should be capped to 24h
    const token = engine.createToken("user-1", ["read"], 7 * 24 * 60 * 60 * 1000);
    const decoded = engine.verifyToken(token);
    const ttlSeconds = decoded.exp - decoded.iat;
    expect(ttlSeconds).toBeLessThanOrEqual(24 * 60 * 60);
  });

  // The verifier recomputes HMAC-SHA256 and ignores the header entirely —
  // these pin that property so a future alg-honoring JWT library cannot
  // silently reintroduce alg:none / algorithm-confusion acceptance.
  it("rejects an alg:none header substitution, with and without a signature", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const [, payload, sig] = token.split(".");
    const noneHeader = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString(
      "base64url",
    );

    await expectVaultError(
      () => engine.verifyToken(`${noneHeader}.${payload}.`),
      ErrorCode.INVALID_TOKEN,
    );
    await expectVaultError(
      () => engine.verifyToken(`${noneHeader}.${payload}.${sig}`),
      ErrorCode.INVALID_TOKEN,
    );
  });

  it("rejects an alg:RS256 header substitution (algorithm confusion)", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const [, payload, sig] = token.split(".");
    const rsHeader = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString(
      "base64url",
    );

    await expectVaultError(
      () => engine.verifyToken(`${rsHeader}.${payload}.${sig}`),
      ErrorCode.INVALID_TOKEN,
    );
  });

  it("rejects a garbage header segment on an otherwise valid token", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const [, payload, sig] = token.split(".");

    await expectVaultError(
      () => engine.verifyToken(`not-base64url!.${payload}.${sig}`),
      ErrorCode.INVALID_TOKEN,
    );
    await expectVaultError(
      () => engine.verifyToken(`${Buffer.from("[]").toString("base64url")}.${payload}.${sig}`),
      ErrorCode.INVALID_TOKEN,
    );
  });

  // R9/C33-A: the issued-token registry supplies the expiry, so the denylist
  // entry lives exactly as long as the token it names. verifyToken prunes
  // entries whose expires_at has passed before consulting them, and the
  // argument that no still-valid token is ever un-revoked rests on
  // createToken's `expires_at = exp × 1000` against the `exp <= ⌊now/1000⌋`
  // expiry check — pinned below at the last valid millisecond.
  it("stores the registry expiry on the denylist entry, in milliseconds", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const decoded = engine.verifyToken(token);

    engine.revokeToken(decoded.jti);

    const db = new Database(dbPath, { readonly: true });
    const row = db
      .prepare("SELECT expires_at FROM revoked_tokens WHERE jti = ?")
      .get(decoded.jti) as { expires_at: number } | undefined;
    db.close();
    expect(row?.expires_at).toBe(decoded.exp * 1000);
    await expectVaultError(() => engine.verifyToken(token), ErrorCode.TOKEN_REVOKED);
  });

  it("a revoked token stays revoked through its last valid millisecond", async () => {
    vi.useFakeTimers();
    try {
      const token = engine.createToken("user-1", ["read"], 60_000);
      const decoded = engine.verifyToken(token);
      engine.revokeToken(decoded.jti);

      vi.setSystemTime(decoded.exp * 1000 - 1);
      await expectVaultError(() => engine.verifyToken(token), ErrorCode.TOKEN_REVOKED);

      vi.setSystemTime(decoded.exp * 1000);
      await expectVaultError(() => engine.verifyToken(token), ErrorCode.TOKEN_REVOKED);
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses an unknown jti with INVALID_INPUT and writes nothing", async () => {
    const err = await expectVaultError(
      () => Promise.resolve().then(() => engine.revokeToken("manual-jti")),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe("Unknown token jti: manual-jti");

    const db = new Database(dbPath, { readonly: true });
    const row = db.prepare("SELECT jti FROM revoked_tokens WHERE jti = ?").get("manual-jti");
    const audit = db
      .prepare("SELECT COUNT(*) AS c FROM audit_log WHERE event_type = ?")
      .get(AuditEventType.TOKEN_REVOKE) as { c: number };
    db.close();
    expect(row).toBeUndefined();
    expect(audit.c).toBe(0);
  });

  it("accepts an already-expired token: the mirror stamps and the entry prunes", async () => {
    vi.useFakeTimers();
    try {
      const token = engine.createToken("user-1", ["read"], 1_000);
      const decoded = engine.verifyToken(token);

      vi.setSystemTime(decoded.exp * 1000 + 1);
      engine.revokeToken(decoded.jti);

      expect(engine.listIssuedTokens({ status: "revoked" })[0]?.jti).toBe(decoded.jti);
      await expectVaultError(() => engine.verifyToken(token), ErrorCode.TOKEN_EXPIRED);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("JWT edge cases", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    registerAgents(engine, "user-1");
  });

  it("rejects token with tampered signature", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const parts = token.split(".");
    // Flip the FIRST signature character — all six of its bits are
    // significant. The last character is not a safe tamper target: it carries
    // only four significant bits (43 base64url chars for 32 bytes), so a
    // canonical trailing "A" tampered to "B" decodes to the same signature.
    const sig = parts[2] as string;
    const tampered = `${parts[0]}.${parts[1]}.${sig.startsWith("A") ? "B" : "A"}${sig.slice(1)}`;

    await expectVaultError(() => engine.verifyToken(tampered), ErrorCode.INVALID_TOKEN);
  });

  it("rejects token with tampered payload", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const parts = token.split(".");
    // Replace payload with a different one
    const fakePayload = Buffer.from(JSON.stringify({ sub: "hacker" })).toString("base64url");
    const tampered = `${parts[0]}.${fakePayload}.${parts[2]}`;

    await expectVaultError(() => engine.verifyToken(tampered), ErrorCode.INVALID_TOKEN);
  });

  it("rejects 2-part token", async () => {
    await expectVaultError(() => engine.verifyToken("header.body"), ErrorCode.INVALID_TOKEN);
  });

  it("rejects 4-part token", async () => {
    await expectVaultError(() => engine.verifyToken("a.b.c.d"), ErrorCode.INVALID_TOKEN);
  });

  it("rejects empty-segment token", async () => {
    await expectVaultError(() => engine.verifyToken(".."), ErrorCode.INVALID_TOKEN);
  });
});
