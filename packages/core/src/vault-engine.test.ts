import { createServer } from "node:http";
import type { Server } from "node:http";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, VaultError, VaultState } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array) => {
      const { createHash } = await import("node:crypto");
      return new Uint8Array(
        createHash("sha256").update(password).update(salt).digest(),
      );
    },
  };
});

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

// Test HTTP server
let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    const auth = req.headers["authorization"] ?? "none";
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ authorization: auth, path: req.url }));
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as { port: number };
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(() => {
  server.close();
});

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-ve-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
});

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
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

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock("my-pass1");
    expect(engine2.getState()).toBe(VaultState.UNLOCKED);
    await engine2.destroy();
  });

  it("rejects wrong password on unlock", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await expect(engine2.unlock("wrong123")).rejects.toThrow(VaultError);

    try {
      await engine2.unlock("wrong123");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_PASSWORD);
    }
    await engine2.destroy();
  });

  it("rejects operations when sealed", async () => {
    expect(() => engine.listSecrets()).toThrow(VaultError);

    try {
      engine.listSecrets();
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.VAULT_LOCKED);
    }
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

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    const result = await engine2.loadSession();
    expect(result).toBe(false);
    expect(engine2.getState()).toBe(VaultState.SEALED);
    // engine2 should not have a store to close — no leaked handle
    await engine2.destroy();
  });

  it("rejects weak password on initVault", async () => {
    try {
      await engine.initVault("short");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.WEAK_PASSWORD);
    }
  });
});

describe("secrets", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("creates and lists secrets", async () => {
    await engine.createSecret({
      name: "test-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("secret-value")),
    });

    const list = engine.listSecrets();
    expect(list.length).toBe(1);
    expect(list[0]?.name).toBe("test-key");
  });

  it("creates and retrieves secret info", async () => {
    await engine.createSecret({
      name: "info-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });

    const info = await engine.getSecretInfo("secret://info-key");
    expect(info.name).toBe("info-key");
    expect(info.status).toBe("active");
  });

  it("creates and retrieves secret value", async () => {
    await engine.createSecret({
      name: "get-val",
      type: "api_key",
      value: new Uint8Array(Buffer.from("the-secret")),
    });

    const value = await engine.getSecretValue("secret://get-val");
    expect(Buffer.from(value).toString()).toBe("the-secret");
  });

  it("handles pending → set value flow", async () => {
    await engine.createSecret({ name: "pending", type: "api_key" });
    await engine.setSecretValue("secret://pending", new Uint8Array(Buffer.from("now-set")));

    const info = await engine.getSecretInfo("secret://pending");
    expect(info.status).toBe("active");
  });

  it("rotates a secret", async () => {
    await engine.createSecret({
      name: "rotate-me",
      type: "api_key",
      value: new Uint8Array(Buffer.from("old")),
    });

    await engine.rotateSecret("secret://rotate-me", new Uint8Array(Buffer.from("new")));

    const info = await engine.getSecretInfo("secret://rotate-me");
    expect(info.version).toBe(2);

    const value = await engine.getSecretValue("secret://rotate-me");
    expect(Buffer.from(value).toString()).toBe("new");
  });

  it("revokes a secret", async () => {
    await engine.createSecret({
      name: "rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await engine.revokeSecret("secret://rev");

    const info = await engine.getSecretInfo("secret://rev");
    expect(info.status).toBe("revoked");
  });
});

describe("error propagation through VaultEngine", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("getSecretInfo throws SECRET_NOT_FOUND for non-existent handle", async () => {
    try {
      await engine.getSecretInfo("secret://nonexistent");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_NOT_FOUND);
    }
  });

  it("getSecretValue throws SECRET_NOT_FOUND for non-existent handle", async () => {
    try {
      await engine.getSecretValue("secret://nonexistent");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_NOT_FOUND);
    }
  });

  it("getSecretInfo throws INVALID_HANDLE for malformed handle", async () => {
    try {
      await engine.getSecretInfo("not-a-handle");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_HANDLE);
    }
  });

  it("getSecretValue throws SECRET_REVOKED for revoked secret", async () => {
    await engine.createSecret({
      name: "rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await engine.revokeSecret("secret://rev");

    try {
      await engine.getSecretValue("secret://rev");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_REVOKED);
    }
  });

  it("getSecretValue throws SECRET_VALUE_REQUIRED for pending secret", async () => {
    await engine.createSecret({ name: "pend", type: "api_key" });

    try {
      await engine.getSecretValue("secret://pend");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_VALUE_REQUIRED);
    }
  });

  it("createSecret throws DUPLICATE_SECRET for duplicate name", async () => {
    await engine.createSecret({
      name: "dup",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    try {
      await engine.createSecret({
        name: "dup",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v2")),
      });
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.DUPLICATE_SECRET);
    }
  });

  it("rotateSecret throws SECRET_REVOKED for revoked secret", async () => {
    await engine.createSecret({
      name: "rot-rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await engine.revokeSecret("secret://rot-rev");

    try {
      await engine.rotateSecret("secret://rot-rev", new Uint8Array(Buffer.from("new")));
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_REVOKED);
    }
  });

  it("useSecret throws SECRET_NOT_FOUND for non-existent handle", async () => {
    try {
      await engine.useSecret(
        "secret://nonexistent",
        { method: "GET", url: `${baseUrl}/test` },
        { type: "bearer" },
      );
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_NOT_FOUND);
    }
  });

  it("useSecret throws SECRET_REVOKED for revoked secret", async () => {
    await engine.createSecret({
      name: "use-rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await engine.revokeSecret("secret://use-rev");

    try {
      await engine.useSecret(
        "secret://use-rev",
        { method: "GET", url: `${baseUrl}/test` },
        { type: "bearer" },
      );
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_REVOKED);
    }
  });

  it("useSecret throws URL_INVALID for invalid URL", async () => {
    await engine.createSecret({
      name: "url-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    try {
      await engine.useSecret(
        "secret://url-test",
        { method: "GET", url: "not-a-url" },
        { type: "bearer" },
      );
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_INVALID);
    }
  });

  it("useSecret throws SSRF_BLOCKED for private IP", async () => {
    await engine.createSecret({
      name: "ssrf-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    try {
      await engine.useSecret(
        "secret://ssrf-test",
        { method: "GET", url: "https://10.0.0.1/api" },
        { type: "bearer" },
      );
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });
});

describe("useSecret (HTTP injection)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("injects bearer token and returns response", async () => {
    await engine.createSecret({
      name: "api-token",
      type: "api_key",
      value: new Uint8Array(Buffer.from("my-bearer-token")),
    });

    const response = await engine.useSecret(
      "secret://api-token",
      { method: "GET", url: `${baseUrl}/test` },
      { type: "bearer" },
    );

    expect(response.status).toBe(200);
    const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
    // Exact-match redaction scrubs the secret value from reflected responses
    expect(body.authorization).toBe("Bearer [REDACTED]");
  });
});

describe("policies", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "policy-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
  });

  it("grants and lists policies", async () => {
    const secretId = await engine.resolveSecretId("secret://policy-test");

    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: "agent",
        principalId: "agent-1",
        permissions: ["read", "use"],
      },
      "admin",
    );

    expect(policy.id).toBeTruthy();

    const policies = engine.listPolicies(secretId);
    expect(policies.length).toBe(1);
  });

  it("revokes a policy", async () => {
    const secretId = await engine.resolveSecretId("secret://policy-test");

    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: "agent",
        principalId: "agent-1",
        permissions: ["read"],
      },
      "admin",
    );

    engine.revokePolicy(policy.id);
    expect(engine.listPolicies(secretId).length).toBe(0);
  });
});

describe("JWT tokens", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("creates and verifies a token", () => {
    const token = engine.createToken("user-1", ["read", "use"]);
    const decoded = engine.verifyToken(token);

    expect(decoded.sub).toBe("user-1");
    expect(decoded.scope).toEqual(["read", "use"]);
  });

  it("rejects invalid token", () => {
    expect(() => engine.verifyToken("bad.token.here")).toThrow(VaultError);
  });

  it("revokes a token", () => {
    const token = engine.createToken("user-1", ["read"]);
    const decoded = engine.verifyToken(token);

    engine.revokeToken(decoded.jti);

    expect(() => engine.verifyToken(token)).toThrow("revoked");
  });

  it("revoked token persists across engine restart", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const decoded = engine.verifyToken(token);
    engine.revokeToken(decoded.jti);
    await engine.lock();

    // Re-open engine, same DB
    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock("password");

    expect(() => engine2.verifyToken(token)).toThrow("revoked");
    await engine2.destroy();
  });

  it("rejects token from different vault (vault_id mismatch)", async () => {
    const token = engine.createToken("user-1", ["read"]);
    await engine.destroy();

    // Create a second vault
    const tempDir2 = join(tempDir, "vault2");
    mkdirSync(tempDir2, { recursive: true });
    const engine2 = new VaultEngine({
      dbPath: join(tempDir2, "test.vault.db"),
      sessionPath: join(tempDir2, "session.json"),
    });
    await engine2.initVault("password");

    try {
      engine2.verifyToken(token);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
    await engine2.destroy();
  });

  it("rejects expired token", () => {
    // Create token with 0 TTL (immediately expired)
    const token = engine.createToken("user-1", ["read"], 0);

    try {
      engine.verifyToken(token);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.TOKEN_EXPIRED);
    }
  });

  it("caps token TTL at MAX_TOKEN_TTL_MS", () => {
    // Request 7 days — should be capped to 24h
    const token = engine.createToken("user-1", ["read"], 7 * 24 * 60 * 60 * 1000);
    const decoded = engine.verifyToken(token);
    const ttlSeconds = decoded.exp - decoded.iat;
    expect(ttlSeconds).toBeLessThanOrEqual(24 * 60 * 60);
  });

  it("revocation with explicit expiresAt uses that value", () => {
    const token = engine.createToken("user-1", ["read"]);
    const decoded = engine.verifyToken(token);

    engine.revokeToken(decoded.jti, decoded.exp);
    expect(() => engine.verifyToken(token)).toThrow("revoked");
  });
});

describe("JWT edge cases", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("rejects token with tampered signature", () => {
    const token = engine.createToken("user-1", ["read"]);
    const parts = token.split(".");
    // Flip last character of signature
    const sig = parts[2] as string;
    const tampered = `${parts[0]}.${parts[1]}.${sig.slice(0, -1)}${sig.endsWith("A") ? "B" : "A"}`;

    try {
      engine.verifyToken(tampered);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects token with tampered payload", () => {
    const token = engine.createToken("user-1", ["read"]);
    const parts = token.split(".");
    // Replace payload with a different one
    const fakePayload = Buffer.from(JSON.stringify({ sub: "hacker" })).toString("base64url");
    const tampered = `${parts[0]}.${fakePayload}.${parts[2]}`;

    try {
      engine.verifyToken(tampered);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects 2-part token", () => {
    try {
      engine.verifyToken("header.body");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects 4-part token", () => {
    try {
      engine.verifyToken("a.b.c.d");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects empty-segment token", () => {
    try {
      engine.verifyToken("..");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });
});

describe("audit trail", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("logs vault unlock event", () => {
    const events = engine.queryAudit({ eventType: AuditEventType.VAULT_UNLOCK });
    expect(events.length).toBeGreaterThanOrEqual(1);
  });

  it("logs secret creation", async () => {
    await engine.createSecret({
      name: "audit-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.handle).toBe("secret://audit-test");
  });

  it("logs getSecretValue with action: get_value", async () => {
    await engine.createSecret({
      name: "audit-getval",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await engine.getSecretValue("secret://audit-getval");

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_READ });
    const getValEvents = events.filter((e) => e.detail?.action === "get_value");
    expect(getValEvents.length).toBe(1);
    expect(getValEvents[0]?.detail?.handle).toBe("secret://audit-getval");
  });
});

describe("audit trail for failed useSecret", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "audit-use",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });
  });

  it("logs DNS failure with success=false", async () => {
    await engine.useSecret(
      "secret://audit-use",
      { method: "GET", url: "https://this-host-does-not-exist-xyz123.invalid/api" },
      { type: "bearer" },
    );

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[0];
    expect(last?.detail?.error).toBe("DNS_RESOLUTION_FAILED");
  });

  it("logs successful request with success=true", async () => {
    await engine.useSecret(
      "secret://audit-use",
      { method: "GET", url: `${baseUrl}/test` },
      { type: "bearer" },
    );

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[0];
    expect(last?.detail?.method).toBe("GET");
    expect(last?.detail?.status).toBe(200);
  });

  it("logs connection refused with success=false", async () => {
    await engine.useSecret(
      "secret://audit-use",
      { method: "GET", url: "http://127.0.0.1:2/api", timeoutMs: 5000 },
      { type: "bearer" },
    );

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[0];
    expect(last?.detail?.error).toBeDefined();
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

    const engine2 = new VaultEngine({ dbPath, sessionPath });
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

    const engine2 = new VaultEngine({ dbPath, sessionPath });
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

    try {
      engine.listSecrets();
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.VAULT_LOCKED);
    }
  });

  it("rejects createSecret after destroy", async () => {
    await engine.initVault("password");
    await engine.destroy();

    try {
      await engine.createSecret({
        name: "fail",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v")),
      });
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.VAULT_LOCKED);
    }
  });
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

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock("new-pass1");

    const value = await engine2.getSecretValue("secret://keep");
    expect(Buffer.from(value).toString()).toBe("secret-val");

    await engine2.destroy();
  });

  it("rejects change with wrong old password", async () => {
    await engine.initVault("correct-pass");

    try {
      await engine.changePassword("wrong-pass", "new-pass1");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.ENCRYPTION_ERROR);
    }
  });

  it("old password no longer works after change", async () => {
    await engine.initVault("old-pass1");
    await engine.changePassword("old-pass1", "new-pass1");
    await engine.lock();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    try {
      await engine2.unlock("old-pass1");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_PASSWORD);
    }
    await engine2.destroy();
  });

  it("rejects weak new password on changePassword", async () => {
    await engine.initVault("password");

    try {
      await engine.changePassword("password", "short");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.WEAK_PASSWORD);
    }
  });
});

describe("lockout mechanism", () => {
  it("triggers lockout after 5 failed unlock attempts", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    for (let i = 0; i < 5; i++) {
      const eng = new VaultEngine({ dbPath, sessionPath });
      try {
        await eng.unlock("wrong123");
      } catch {
        // Expected INVALID_PASSWORD
      }
      await eng.destroy();
    }

    // 6th attempt should hit lockout
    const eng = new VaultEngine({ dbPath, sessionPath });
    try {
      await eng.unlock("wrong123");
      expect.fail("Should throw lockout");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.LOCKOUT_ACTIVE);
    }
    await eng.destroy();
  });

  it("lockout rejects even the correct password", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    for (let i = 0; i < 5; i++) {
      const eng = new VaultEngine({ dbPath, sessionPath });
      try {
        await eng.unlock("wrong123");
      } catch {
        // Expected
      }
      await eng.destroy();
    }

    // Correct password during lockout should also fail
    const eng = new VaultEngine({ dbPath, sessionPath });
    try {
      await eng.unlock("correct1");
      expect.fail("Should throw lockout");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.LOCKOUT_ACTIVE);
    }
    await eng.destroy();
  });

  it("resets failed attempt counter on successful unlock", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    // 4 failed attempts (just below threshold)
    for (let i = 0; i < 4; i++) {
      const eng = new VaultEngine({ dbPath, sessionPath });
      try {
        await eng.unlock("wrong123");
      } catch {
        // Expected
      }
      await eng.destroy();
    }

    // Successful unlock resets counter
    const eng = new VaultEngine({ dbPath, sessionPath });
    await eng.unlock("correct1");
    await eng.lock();

    // 4 more failed attempts should NOT trigger lockout (counter was reset)
    for (let i = 0; i < 4; i++) {
      const eng2 = new VaultEngine({ dbPath, sessionPath });
      try {
        await eng2.unlock("wrong123");
      } catch {
        // Expected
      }
      await eng2.destroy();
    }

    // 5th attempt should still succeed (total 4 since reset)
    const eng3 = new VaultEngine({ dbPath, sessionPath });
    try {
      await eng3.unlock("correct1");
      expect(eng3.getState()).toBe(VaultState.UNLOCKED);
    } finally {
      await eng3.destroy();
    }
  });
});

describe("audit trail completeness", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("logs secret rotation", async () => {
    await engine.createSecret({
      name: "rot-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("old")),
    });

    await engine.rotateSecret("secret://rot-audit", new Uint8Array(Buffer.from("new")));

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_ROTATE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.handle).toBe("secret://rot-audit");
  });

  it("logs secret revocation", async () => {
    await engine.createSecret({
      name: "rev-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await engine.revokeSecret("secret://rev-audit");

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_REVOKE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.handle).toBe("secret://rev-audit");
  });

  it("logs set_value on pending secret", async () => {
    await engine.createSecret({ name: "pending-audit", type: "api_key" });
    await engine.setSecretValue("secret://pending-audit", new Uint8Array(Buffer.from("val")));

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    const setValueEvents = events.filter((e) => e.detail?.action === "set_value");
    expect(setValueEvents.length).toBe(1);
    expect(setValueEvents[0]?.detail?.handle).toBe("secret://pending-audit");
  });

  it("logs vault lock", async () => {
    await engine.lock();

    // Need a new engine to query audit (current engine is sealed)
    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock("password");

    const events = engine2.queryAudit({ eventType: AuditEventType.VAULT_LOCK });
    expect(events.length).toBe(1);

    await engine2.destroy();
  });

  it("logs password change", async () => {
    await engine.changePassword("password", "new-password");

    const events = engine.queryAudit({ eventType: AuditEventType.VAULT_PASSWORD_CHANGE });
    expect(events.length).toBe(1);
  });

  it("logs policy grant", async () => {
    await engine.createSecret({
      name: "pol-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const secretId = await engine.resolveSecretId("secret://pol-audit");

    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "agent-1", permissions: ["read"] },
      "admin",
    );

    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.principal).toBe("agent:agent-1");
  });

  it("logs policy revocation", async () => {
    await engine.createSecret({
      name: "pol-rev-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const secretId = await engine.resolveSecretId("secret://pol-rev-audit");

    const policy = engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "agent-1", permissions: ["read"] },
      "admin",
    );

    engine.revokePolicy(policy.id);

    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_REVOKE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.policy_id).toBe(policy.id);
  });
});

describe("secrets through VaultEngine — additional coverage", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("creates a secret with injection config", async () => {
    const result = await engine.createSecret({
      name: "injected-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      injection: { type: "header", header_name: "X-Api-Key" },
    });

    expect(result.handle).toBe("secret://injected-key");
    expect(result.status).toBe("created");
  });

  it("lists secrets filtered by project", async () => {
    await engine.createSecret({
      name: "a",
      type: "api_key",
      project: "proj-a",
      value: new Uint8Array(Buffer.from("va")),
    });
    await engine.createSecret({
      name: "b",
      type: "api_key",
      project: "proj-b",
      value: new Uint8Array(Buffer.from("vb")),
    });
    await engine.createSecret({
      name: "c",
      type: "api_key",
      value: new Uint8Array(Buffer.from("vc")),
    });

    const projA = engine.listSecrets("proj-a");
    expect(projA.length).toBe(1);
    expect(projA[0]?.name).toBe("a");

    const all = engine.listSecrets();
    expect(all.length).toBe(3);
  });

  it("creates a pending secret and sets its value", async () => {
    await engine.createSecret({ name: "deferred", type: "api_key" });

    const infoBefore = await engine.getSecretInfo("secret://deferred");
    expect(infoBefore.status).toBe("pending");

    await engine.setSecretValue("secret://deferred", new Uint8Array(Buffer.from("set-later")));

    const infoAfter = await engine.getSecretInfo("secret://deferred");
    expect(infoAfter.status).toBe("active");

    const value = await engine.getSecretValue("secret://deferred");
    expect(Buffer.from(value).toString()).toBe("set-later");
  });
});

describe("lazy expiry in info/list", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("getSecretInfo returns expired status for past-expiry secret", async () => {
    await engine.createSecret({
      name: "exp-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      expiresAt: Date.now() - 1000, // Already expired
    });

    const info = await engine.getSecretInfo("secret://exp-test");
    expect(info.status).toBe("expired");
  });

  it("listSecrets returns expired status for past-expiry secret", async () => {
    await engine.createSecret({
      name: "exp-list",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      expiresAt: Date.now() - 1000,
    });

    const list = engine.listSecrets();
    const found = list.find((s) => s.name === "exp-list");
    expect(found?.status).toBe("expired");
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
