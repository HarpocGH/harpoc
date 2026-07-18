import { createServer } from "node:http";
import type { Server } from "node:http";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, SecretStatus } from "@harpoc/shared";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";
import type { SqliteStore } from "./storage/sqlite-store.js";

vi.mock("./crypto/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array) => {
      const { createHash } = await import("node:crypto");
      return new Uint8Array(createHash("sha256").update(password).update(salt).digest());
    },
  };
});

// NM3 fail-closed audit: every durable-state mutation commits in the same
// SQLite transaction as its audit row. These tests force the audit INSERT to
// fail and assert the paired state write rolled back — and that the vault
// stays healthy for a retry once the audit log is writable again.

let tempDir: string;
let engine: VaultEngine;

// Loopback token endpoint for the OAuth refresh fault-injection test.
let tokenServer: Server;
let tokenServerUrl: string;

beforeAll(async () => {
  tokenServer = createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        access_token: "refreshed-access-token",
        refresh_token: "refreshed-refresh-token",
        expires_in: 3600,
      }),
    );
  });
  await new Promise<void>((resolve) => {
    tokenServer.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = tokenServer.address() as { port: number };
  tokenServerUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(() => {
  tokenServer.close();
});

function providerConfig(overrides?: Partial<OAuthProviderConfig>): OAuthProviderConfig {
  return {
    provider: "github",
    grant_type: "authorization_code",
    token_endpoint: "https://github.com/login/oauth/access_token",
    auth_endpoint: "https://github.com/login/oauth/authorize",
    client_id: "client-id",
    client_secret: "client-secret",
    ...overrides,
  };
}

function liveStore(): SqliteStore {
  return (engine as unknown as { store: SqliteStore }).store;
}

function failNextAuditInsert(): void {
  vi.spyOn(liveStore(), "insertAuditEvent").mockImplementationOnce(() => {
    throw new Error("audit unavailable");
  });
}

function auditCount(eventType: AuditEventType): number {
  return engine.queryAudit({ eventType }).length;
}

function rawStatus(secretId: string): string | undefined {
  return liveStore().getSecret(secretId)?.status;
}

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-atom-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
});

afterEach(async () => {
  vi.restoreAllMocks();
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("fail-closed audit: secret CRUD", () => {
  it("createSecret rolls back the insert when the audit write fails", async () => {
    failNextAuditInsert();

    await expect(engine.createSecret({ name: "atomic-key", type: "api_key" })).rejects.toThrow(
      "audit unavailable",
    );

    expect(engine.listSecrets()).toHaveLength(0);
    expect(auditCount(AuditEventType.SECRET_CREATE)).toBe(0);

    // The name is reusable — nothing was written.
    const result = await engine.createSecret({ name: "atomic-key", type: "api_key" });
    expect(result.status).toBe("pending");
    expect(auditCount(AuditEventType.SECRET_CREATE)).toBe(1);
  });

  it("setSecretValue rolls back the ACTIVE transition when the audit write fails", async () => {
    await engine.createSecret({ name: "pending-key", type: "api_key" });
    failNextAuditInsert();

    await expect(
      engine.setSecretValue("secret://pending-key", new Uint8Array(Buffer.from("v1"))),
    ).rejects.toThrow("audit unavailable");

    expect((await engine.getSecretInfo("secret://pending-key")).status).toBe(SecretStatus.PENDING);
    expect(auditCount(AuditEventType.SECRET_CREATE)).toBe(1); // the create only

    await engine.setSecretValue("secret://pending-key", new Uint8Array(Buffer.from("v1")));
    expect((await engine.getSecretInfo("secret://pending-key")).status).toBe(SecretStatus.ACTIVE);
    expect(auditCount(AuditEventType.SECRET_CREATE)).toBe(2);
  });

  it("rotateSecret rolls back value and version when the audit write fails", async () => {
    await engine.createSecret({
      name: "rotate-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("old-value")),
    });
    failNextAuditInsert();

    await expect(
      engine.rotateSecret("secret://rotate-key", new Uint8Array(Buffer.from("new-value"))),
    ).rejects.toThrow("audit unavailable");

    expect((await engine.getSecretInfo("secret://rotate-key")).version).toBe(1);
    expect(Buffer.from(await engine.getSecretValue("secret://rotate-key")).toString()).toBe(
      "old-value",
    );
    expect(auditCount(AuditEventType.SECRET_ROTATE)).toBe(0);

    await engine.rotateSecret("secret://rotate-key", new Uint8Array(Buffer.from("new-value")));
    expect((await engine.getSecretInfo("secret://rotate-key")).version).toBe(2);
    expect(auditCount(AuditEventType.SECRET_ROTATE)).toBe(1);
  });

  it("revokeSecret rolls back the status change when the audit write fails", async () => {
    await engine.createSecret({
      name: "revoke-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    failNextAuditInsert();

    await expect(engine.revokeSecret("secret://revoke-key")).rejects.toThrow("audit unavailable");

    expect((await engine.getSecretInfo("secret://revoke-key")).status).toBe(SecretStatus.ACTIVE);
    expect(auditCount(AuditEventType.SECRET_REVOKE)).toBe(0);

    await engine.revokeSecret("secret://revoke-key");
    expect(auditCount(AuditEventType.SECRET_REVOKE)).toBe(1);
  });
});

describe("fail-closed audit: lazy expiry", () => {
  it("assertUsable rolls back the EXPIRED transition when the audit write fails", async () => {
    await engine.createSecret({
      name: "expiring-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      expiresAt: Date.now() - 1000,
    });
    const secretId = await engine.resolveSecretId("secret://expiring-key");
    failNextAuditInsert();

    await expect(engine.getSecretValue("secret://expiring-key")).rejects.toThrow(
      "audit unavailable",
    );

    expect(rawStatus(secretId)).toBe(SecretStatus.ACTIVE);
    expect(auditCount(AuditEventType.SECRET_EXPIRE)).toBe(0);

    // Audit writable again: the transition commits exactly once, access denied.
    await expect(engine.getSecretValue("secret://expiring-key")).rejects.toMatchObject({
      code: ErrorCode.SECRET_EXPIRED,
    });
    expect(rawStatus(secretId)).toBe(SecretStatus.EXPIRED);
    expect(auditCount(AuditEventType.SECRET_EXPIRE)).toBe(1);
  });

  it("OAuth access-token path rolls back the EXPIRED transition when the audit write fails", async () => {
    const { secretId } = await engine.createOAuthSecret("oauth-expiring", providerConfig());
    liveStore().updateSecret(secretId, { expires_at: Date.now() - 1000 });
    failNextAuditInsert();

    await expect(engine.getOAuthAccessToken(secretId)).rejects.toThrow("audit unavailable");

    expect(rawStatus(secretId)).toBe(SecretStatus.PENDING);
    expect(auditCount(AuditEventType.SECRET_EXPIRE)).toBe(0);

    await expect(engine.getOAuthAccessToken(secretId)).rejects.toMatchObject({
      code: ErrorCode.SECRET_EXPIRED,
    });
    expect(rawStatus(secretId)).toBe(SecretStatus.EXPIRED);
    expect(auditCount(AuditEventType.SECRET_EXPIRE)).toBe(1);
  });
});

describe("chain integrity across transactional audit writes", () => {
  it("keeps the HMAC chain linear and anchorable through a mixed lifecycle", async () => {
    await engine.createSecret({
      name: "life-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v1")),
    });
    await engine.setInjectionPolicy(
      "secret://life-key",
      { command_allowlist: [process.execPath] },
      { acknowledge_interpreters: true },
    );
    await engine.rotateSecret("secret://life-key", new Uint8Array(Buffer.from("v2")));
    // A denied read (single-insert path) interleaved with transactional rows.
    await expect(engine.getSecretValue("secret://missing")).rejects.toThrow();
    await engine.revokeSecret("secret://life-key");
    await engine.changePassword("password", "newpassword1");

    const report = engine.verifyAuditChain();
    expect(report.valid).toBe(true);

    // Anchor round-trip: the tail moved past the multi-row transactions.
    const anchor = engine.getAuditChainTail();
    expect(anchor).not.toBeNull();
    const anchored = engine.verifyAuditChain({ anchor: anchor as NonNullable<typeof anchor> });
    expect(anchored.valid).toBe(true);

    // Every event's detail still decrypts (row-bound AAD unaffected).
    const unreadable = engine.queryAudit().filter((e) => e.detail_unreadable);
    expect(unreadable).toHaveLength(0);
  });
});

describe("fail-closed audit: policy and config writes", () => {
  it("setInjectionPolicy rolls back the policy (and acknowledged-interpreter row) when the audit write fails", async () => {
    await engine.createSecret({ name: "policy-key", type: "api_key" });
    failNextAuditInsert();

    await expect(
      engine.setInjectionPolicy(
        "secret://policy-key",
        { command_allowlist: [process.execPath] },
        { acknowledge_interpreters: true },
      ),
    ).rejects.toThrow("audit unavailable");

    expect((await engine.getInjectionPolicy("secret://policy-key")).command_allowlist).toEqual([]);
    expect(auditCount(AuditEventType.POLICY_GRANT)).toBe(0);
    expect(auditCount(AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED)).toBe(0);

    // Grant + acknowledgement commit together and the chain stays linear.
    await engine.setInjectionPolicy(
      "secret://policy-key",
      { command_allowlist: [process.execPath] },
      { acknowledge_interpreters: true },
    );
    expect(auditCount(AuditEventType.POLICY_GRANT)).toBe(1);
    expect(auditCount(AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED)).toBe(1);
    expect(engine.verifyAuditChain().valid).toBe(true);
  });

  it("setMcpServerConfig rolls back the config when the audit write fails", async () => {
    await engine.createSecret({ name: "mcp-key", type: "api_key" });
    failNextAuditInsert();

    await expect(
      engine.setMcpServerConfig("secret://mcp-key", {
        server_name: "test-mcp",
        transport: "http",
        url: "https://mcp.example.com/mcp",
      }),
    ).rejects.toThrow("audit unavailable");

    expect(await engine.getMcpServerConfig("secret://mcp-key")).toBeUndefined();
    expect(auditCount(AuditEventType.POLICY_GRANT)).toBe(0);
  });

  it("deleteMcpServerConfig rolls back the delete when the audit write fails", async () => {
    await engine.createSecret({ name: "mcp-del", type: "api_key" });
    await engine.setMcpServerConfig("secret://mcp-del", {
      server_name: "test-mcp",
      transport: "http",
      url: "https://mcp.example.com/mcp",
    });
    failNextAuditInsert();

    await expect(engine.deleteMcpServerConfig("secret://mcp-del")).rejects.toThrow(
      "audit unavailable",
    );

    expect(await engine.getMcpServerConfig("secret://mcp-del")).toBeDefined();
    expect(auditCount(AuditEventType.POLICY_REVOKE)).toBe(0);

    expect(await engine.deleteMcpServerConfig("secret://mcp-del")).toBe(true);
    expect(auditCount(AuditEventType.POLICY_REVOKE)).toBe(1);
  });

  it("setConnectionConfig rolls back the config when the audit write fails", async () => {
    await engine.createSecret({ name: "conn-key", type: "api_key" });
    failNextAuditInsert();

    await expect(
      engine.setConnectionConfig("secret://conn-key", { database: { tls_mode: "require" } }),
    ).rejects.toThrow("audit unavailable");

    expect(await engine.getConnectionConfig("secret://conn-key")).toBeUndefined();
    expect(auditCount(AuditEventType.POLICY_GRANT)).toBe(0);
  });

  it("deleteConnectionConfig rolls back the delete when the audit write fails", async () => {
    await engine.createSecret({ name: "conn-del", type: "api_key" });
    await engine.setConnectionConfig("secret://conn-del", { database: { tls_mode: "require" } });
    failNextAuditInsert();

    await expect(engine.deleteConnectionConfig("secret://conn-del")).rejects.toThrow(
      "audit unavailable",
    );

    expect(await engine.getConnectionConfig("secret://conn-del")).toBeDefined();
    expect(auditCount(AuditEventType.POLICY_REVOKE)).toBe(0);
  });

  it("grantPolicy rolls back the access policy when the audit write fails", async () => {
    await engine.createSecret({ name: "acl-key", type: "api_key" });
    const secretId = await engine.resolveSecretId("secret://acl-key");
    failNextAuditInsert();

    expect(() =>
      engine.grantPolicy(
        { secretId, principalType: "agent", principalId: "agent-1", permissions: ["read"] },
        "admin",
      ),
    ).toThrow("audit unavailable");

    expect(engine.listPolicies(secretId)).toHaveLength(0);
    expect(auditCount(AuditEventType.POLICY_GRANT)).toBe(0);
  });

  it("revokePolicy rolls back the revocation when the audit write fails", async () => {
    await engine.createSecret({ name: "acl-rev", type: "api_key" });
    const secretId = await engine.resolveSecretId("secret://acl-rev");
    const policy = engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "agent-1", permissions: ["read"] },
      "admin",
    );
    failNextAuditInsert();

    expect(() => engine.revokePolicy(policy.id)).toThrow("audit unavailable");

    expect(engine.listPolicies(secretId)).toHaveLength(1);
    expect(auditCount(AuditEventType.POLICY_REVOKE)).toBe(0);
  });
});

describe("fail-closed audit: tokens, OAuth flow, password change", () => {
  it("revokeToken rolls back the revocation when the audit write fails", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const jti = engine.verifyToken(token).jti;
    failNextAuditInsert();

    expect(() => engine.revokeToken(jti)).toThrow("audit unavailable");

    expect(() => engine.verifyToken(token)).not.toThrow();
    expect(auditCount(AuditEventType.TOKEN_REVOKE)).toBe(0);

    engine.revokeToken(jti);
    expect(() => engine.verifyToken(token)).toThrow();
    expect(auditCount(AuditEventType.TOKEN_REVOKE)).toBe(1);
  });

  it("createOAuthSecret rolls back the OAuth row when the audit write fails, and resume recovers", async () => {
    failNextAuditInsert();

    await expect(engine.createOAuthSecret("oauth-atomic", providerConfig())).rejects.toThrow(
      "audit unavailable",
    );

    // The D4 window made real: the base secret row committed (PENDING), the
    // OAuth row + audit rolled back together — a visibly incomplete operation.
    expect(auditCount(AuditEventType.OAUTH_AUTHORIZE)).toBe(0);
    const secretId = await engine.resolveSecretId("secret://oauth-atomic");
    expect(liveStore().getOAuthToken(secretId)).toBeUndefined();

    // Re-running connect resumes the PENDING secret.
    const second = await engine.createOAuthSecret("oauth-atomic", providerConfig());
    expect(second.secretId).toBe(secretId);
    expect(liveStore().getOAuthToken(secretId)).toBeDefined();
    expect(auditCount(AuditEventType.OAUTH_AUTHORIZE)).toBe(1);
  });

  it("completeOAuthFlow rolls back tokens and ACTIVE transition when the audit write fails", async () => {
    const { secretId } = await engine.createOAuthSecret("oauth-flow", providerConfig());
    failNextAuditInsert();

    await expect(
      engine.completeOAuthFlow(secretId, "access-token", "refresh-token", Date.now() + 3600_000),
    ).rejects.toThrow("audit unavailable");

    expect(rawStatus(secretId)).toBe(SecretStatus.PENDING);
    expect(liveStore().getOAuthToken(secretId)?.access_token_encrypted).toBeNull();
    expect(auditCount(AuditEventType.OAUTH_CALLBACK)).toBe(0);

    await engine.completeOAuthFlow(secretId, "access-token", "refresh-token");
    expect(rawStatus(secretId)).toBe(SecretStatus.ACTIVE);
    expect(auditCount(AuditEventType.OAUTH_CALLBACK)).toBe(1);
  });

  it("refreshOAuthToken rolls back the rotated tokens when the audit write fails", async () => {
    const { secretId } = await engine.createOAuthSecret(
      "oauth-refresh",
      providerConfig({ token_endpoint: tokenServerUrl }),
    );
    await engine.completeOAuthFlow(secretId, "old-access", "old-refresh");
    const before = liveStore().getOAuthToken(secretId);
    failNextAuditInsert();

    await expect(engine.refreshOAuthToken(secretId)).rejects.toThrow("audit unavailable");

    const after = liveStore().getOAuthToken(secretId);
    expect(Buffer.from(after?.access_token_encrypted ?? new Uint8Array())).toEqual(
      Buffer.from(before?.access_token_encrypted ?? new Uint8Array()),
    );
    expect(auditCount(AuditEventType.OAUTH_REFRESH)).toBe(0);

    await engine.refreshOAuthToken(secretId);
    const rotated = liveStore().getOAuthToken(secretId);
    expect(Buffer.from(rotated?.access_token_encrypted ?? new Uint8Array())).not.toEqual(
      Buffer.from(before?.access_token_encrypted ?? new Uint8Array()),
    );
    expect(auditCount(AuditEventType.OAUTH_REFRESH)).toBe(1);
  });

  it("changePassword rolls back all key metas when the audit write fails (torn-KEK pin)", async () => {
    await engine.createSecret({
      name: "kept-secret",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    failNextAuditInsert();

    await expect(engine.changePassword("password", "newpassword1")).rejects.toThrow(
      "audit unavailable",
    );

    expect(auditCount(AuditEventType.VAULT_PASSWORD_CHANGE)).toBe(0);

    // Salt and wrapped KEK rolled back as one generation: the old password
    // still unlocks a fresh engine against the same database.
    const engine2 = new VaultEngine({
      dbPath: join(tempDir, "test.vault.db"),
      sessionPath: join(tempDir, "session2.json"),
    });
    try {
      await engine2.unlock("password");
      expect(Buffer.from(await engine2.getSecretValue("secret://kept-secret")).toString()).toBe(
        "v",
      );
    } finally {
      await engine2.destroy();
    }

    // Audit writable again: the change commits, old password stops working.
    await engine.changePassword("password", "newpassword1");
    expect(auditCount(AuditEventType.VAULT_PASSWORD_CHANGE)).toBe(1);
    const engine3 = new VaultEngine({
      dbPath: join(tempDir, "test.vault.db"),
      sessionPath: join(tempDir, "session3.json"),
    });
    try {
      await engine3.unlock("newpassword1");
      expect(Buffer.from(await engine3.getSecretValue("secret://kept-secret")).toString()).toBe(
        "v",
      );
    } finally {
      await engine3.destroy();
    }
  });
});
