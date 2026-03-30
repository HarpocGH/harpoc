import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AccessPolicy, Secret } from "@harpoc/shared";
import { AuditEventType, SecretStatus, SecretType } from "@harpoc/shared";
import type { CertificateRow, OAuthTokenRow } from "./sqlite-store.js";
import { SqliteStore } from "./sqlite-store.js";

let store: SqliteStore;

function makeSecret(overrides: Partial<Secret> = {}): Secret {
  const now = Date.now();
  return {
    id: `secret-${Math.random().toString(36).slice(2)}`,
    name_encrypted: new Uint8Array([1, 2, 3]),
    name_iv: new Uint8Array(12),
    name_tag: new Uint8Array(16),
    type: SecretType.API_KEY,
    project: null,
    wrapped_dek: new Uint8Array([4, 5, 6]),
    dek_iv: new Uint8Array(12),
    dek_tag: new Uint8Array(16),
    ciphertext: new Uint8Array([7, 8, 9]),
    ct_iv: new Uint8Array(12),
    ct_tag: new Uint8Array(16),
    metadata_encrypted: null,
    metadata_iv: null,
    metadata_tag: null,
    created_at: now,
    updated_at: now,
    expires_at: null,
    rotated_at: null,
    version: 1,
    status: SecretStatus.ACTIVE,
    sync_version: 0,
    ...overrides,
  };
}

function makePolicy(secretId: string, overrides: Partial<AccessPolicy> = {}): AccessPolicy {
  return {
    id: `policy-${Math.random().toString(36).slice(2)}`,
    secret_id: secretId,
    principal_type: "agent" as const,
    principal_id: "agent-1",
    permissions: ["read" as const, "use" as const],
    created_at: Date.now(),
    expires_at: null,
    created_by: "user",
    ...overrides,
  };
}

beforeEach(() => {
  store = new SqliteStore(":memory:");
});

afterEach(() => {
  store.close();
});

describe("schema creation", () => {
  it("creates all four tables", () => {
    const tables = store.db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all() as { name: string }[];
    const names = tables.map((t) => t.name);

    expect(names).toContain("vault_meta");
    expect(names).toContain("secrets");
    expect(names).toContain("access_policies");
    expect(names).toContain("audit_log");
  });

  it("creates oauth_tokens table", () => {
    const row = store.db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth_tokens'")
      .get() as { name: string } | undefined;
    expect(row?.name).toBe("oauth_tokens");
  });

  it("creates certificates table", () => {
    const row = store.db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'")
      .get() as { name: string } | undefined;
    expect(row?.name).toBe("certificates");
  });

  it("sets schema_version to 5", () => {
    expect(store.getMeta("schema_version")).toBe("5");
  });
});

describe("PRAGMAs", () => {
  it("sets WAL journal mode (returns 'memory' for :memory: DBs)", () => {
    // WAL is set via PRAGMA but :memory: databases always report "memory"
    const result = store.db.pragma("journal_mode") as { journal_mode: string }[];
    expect(["wal", "memory"]).toContain(result[0]?.journal_mode);
  });

  it("enables foreign keys", () => {
    const result = store.db.pragma("foreign_keys") as { foreign_keys: number }[];
    expect(result[0]?.foreign_keys).toBe(1);
  });

  it("sets synchronous to FULL (2)", () => {
    const result = store.db.pragma("synchronous") as { synchronous: number }[];
    expect(result[0]?.synchronous).toBe(2);
  });

  it("sets busy_timeout", () => {
    const result = store.db.pragma("busy_timeout") as { timeout: number }[];
    expect(result[0]?.timeout).toBe(5000);
  });
});

describe("vault_meta", () => {
  it("gets and sets key-value pairs", () => {
    store.setMeta("test_key", "test_value");
    expect(store.getMeta("test_key")).toBe("test_value");
  });

  it("returns undefined for missing key", () => {
    expect(store.getMeta("nonexistent")).toBeUndefined();
  });

  it("overwrites existing values", () => {
    store.setMeta("key", "value1");
    store.setMeta("key", "value2");
    expect(store.getMeta("key")).toBe("value2");
  });
});

describe("secrets CRUD", () => {
  it("inserts and retrieves a secret", () => {
    const secret = makeSecret();
    store.insertSecret(secret);

    const retrieved = store.getSecret(secret.id);
    expect(retrieved).toBeDefined();
    expect(retrieved?.id).toBe(secret.id);
    expect(retrieved?.type).toBe(SecretType.API_KEY);
    expect(retrieved?.status).toBe(SecretStatus.ACTIVE);
    expect(retrieved?.version).toBe(1);
    expect(Buffer.from(retrieved?.ciphertext ?? []).equals(Buffer.from(secret.ciphertext))).toBe(
      true,
    );
  });

  it("returns undefined for missing secret", () => {
    expect(store.getSecret("nonexistent")).toBeUndefined();
  });

  it("lists secrets with no filter", () => {
    store.insertSecret(makeSecret());
    store.insertSecret(makeSecret());

    const secrets = store.listSecrets();
    expect(secrets.length).toBe(2);
  });

  it("filters by project", () => {
    store.insertSecret(makeSecret({ project: "proj-a" }));
    store.insertSecret(makeSecret({ project: "proj-b" }));

    const result = store.listSecrets({ project: "proj-a" });
    expect(result.length).toBe(1);
    expect(result[0]?.project).toBe("proj-a");
  });

  it("filters by type", () => {
    store.insertSecret(makeSecret({ type: SecretType.API_KEY }));
    store.insertSecret(makeSecret({ type: SecretType.CERTIFICATE }));

    const result = store.listSecrets({ type: SecretType.CERTIFICATE });
    expect(result.length).toBe(1);
    expect(result[0]?.type).toBe("certificate");
  });

  it("filters by status", () => {
    store.insertSecret(makeSecret({ status: SecretStatus.ACTIVE }));
    store.insertSecret(makeSecret({ status: SecretStatus.REVOKED }));

    const result = store.listSecrets({ status: SecretStatus.ACTIVE });
    expect(result.length).toBe(1);
  });

  it("updates secret fields", () => {
    const secret = makeSecret();
    store.insertSecret(secret);

    const newCiphertext = new Uint8Array([10, 11, 12]);
    store.updateSecret(secret.id, {
      ciphertext: newCiphertext,
      version: 2,
      status: SecretStatus.ACTIVE,
      updated_at: Date.now(),
    });

    const updated = store.getSecret(secret.id);
    expect(updated?.version).toBe(2);
    expect(Buffer.from(updated?.ciphertext ?? []).equals(Buffer.from(newCiphertext))).toBe(true);
  });

  it("rejects update with invalid column name", () => {
    const secret = makeSecret();
    store.insertSecret(secret);

    expect(() => store.updateSecret(secret.id, { "DROP TABLE secrets; --": "x" } as never)).toThrow(
      "Invalid column name",
    );
  });

  it("deletes a secret", () => {
    const secret = makeSecret();
    store.insertSecret(secret);

    const deleted = store.deleteSecret(secret.id);
    expect(deleted).toBe(true);
    expect(store.getSecret(secret.id)).toBeUndefined();
  });

  it("returns false when deleting nonexistent secret", () => {
    expect(store.deleteSecret("nonexistent")).toBe(false);
  });

  it("handles metadata fields as nullable blobs", () => {
    const secret = makeSecret({
      metadata_encrypted: new Uint8Array([42]),
      metadata_iv: new Uint8Array(12).fill(1),
      metadata_tag: new Uint8Array(16).fill(2),
    });
    store.insertSecret(secret);

    const retrieved = store.getSecret(secret.id);
    expect(retrieved?.metadata_encrypted).toBeInstanceOf(Uint8Array);
    expect(retrieved?.metadata_encrypted?.length).toBe(1);
  });
});

describe("access_policies CRUD", () => {
  it("inserts and retrieves a policy", () => {
    const secret = makeSecret();
    store.insertSecret(secret);

    const policy = makePolicy(secret.id);
    store.insertPolicy(policy);

    const retrieved = store.getPolicy(policy.id);
    expect(retrieved).toBeDefined();
    expect(retrieved?.secret_id).toBe(secret.id);
    expect(retrieved?.permissions).toEqual(["read", "use"]);
  });

  it("lists policies by secret_id", () => {
    const s1 = makeSecret();
    const s2 = makeSecret();
    store.insertSecret(s1);
    store.insertSecret(s2);

    store.insertPolicy(makePolicy(s1.id));
    store.insertPolicy(makePolicy(s1.id));
    store.insertPolicy(makePolicy(s2.id));

    expect(store.listPolicies(s1.id).length).toBe(2);
    expect(store.listPolicies(s2.id).length).toBe(1);
  });

  it("lists policies by principal", () => {
    const secret = makeSecret();
    store.insertSecret(secret);

    store.insertPolicy(makePolicy(secret.id, { principal_type: "agent", principal_id: "agent-x" }));

    const result = store.listPoliciesByPrincipal("agent", "agent-x");
    expect(result.length).toBe(1);
  });

  it("deletes a policy", () => {
    const secret = makeSecret();
    store.insertSecret(secret);
    const policy = makePolicy(secret.id);
    store.insertPolicy(policy);

    expect(store.deletePolicy(policy.id)).toBe(true);
    expect(store.getPolicy(policy.id)).toBeUndefined();
  });

  it("cascades on secret delete", () => {
    const secret = makeSecret();
    store.insertSecret(secret);
    store.insertPolicy(makePolicy(secret.id));

    store.deleteSecret(secret.id);
    expect(store.listPolicies(secret.id).length).toBe(0);
  });
});

describe("audit_log", () => {
  it("inserts and queries audit events", () => {
    const eventId = store.insertAuditEvent({
      timestamp: Date.now(),
      event_type: AuditEventType.SECRET_CREATE,
      secret_id: "s1",
      principal_type: "user",
      principal_id: "user-1",
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: "sess-1",
      success: true,
    });

    expect(eventId).toBeGreaterThan(0);

    const events = store.queryAuditLog();
    expect(events.length).toBe(1);
    expect(events[0]?.event_type).toBe("secret.create");
    expect(events[0]?.success).toBe(true);
  });

  it("filters by secretId", () => {
    store.insertAuditEvent({
      timestamp: Date.now(),
      event_type: AuditEventType.SECRET_READ,
      secret_id: "s1",
      principal_type: null,
      principal_id: null,
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: null,
      success: true,
    });
    store.insertAuditEvent({
      timestamp: Date.now(),
      event_type: AuditEventType.SECRET_READ,
      secret_id: "s2",
      principal_type: null,
      principal_id: null,
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: null,
      success: true,
    });

    expect(store.queryAuditLog({ secretId: "s1" }).length).toBe(1);
  });

  it("filters by event type", () => {
    store.insertAuditEvent({
      timestamp: Date.now(),
      event_type: AuditEventType.VAULT_UNLOCK,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: null,
      success: true,
    });
    store.insertAuditEvent({
      timestamp: Date.now(),
      event_type: AuditEventType.SECRET_CREATE,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: null,
      success: true,
    });

    expect(store.queryAuditLog({ eventType: AuditEventType.VAULT_UNLOCK }).length).toBe(1);
  });

  it("filters by time range", () => {
    store.insertAuditEvent({
      timestamp: 1000,
      event_type: AuditEventType.SECRET_USE,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: null,
      success: true,
    });
    store.insertAuditEvent({
      timestamp: 2000,
      event_type: AuditEventType.SECRET_USE,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: null,
      success: true,
    });
    store.insertAuditEvent({
      timestamp: 3000,
      event_type: AuditEventType.SECRET_USE,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: null,
      success: true,
    });

    expect(store.queryAuditLog({ since: 1500, until: 2500 }).length).toBe(1);
  });

  it("respects limit", () => {
    for (let i = 0; i < 5; i++) {
      store.insertAuditEvent({
        timestamp: Date.now() + i,
        event_type: AuditEventType.SECRET_READ,
        secret_id: null,
        principal_type: null,
        principal_id: null,
        detail_encrypted: null,
        detail_iv: null,
        detail_tag: null,
        ip_address: null,
        session_id: null,
        success: true,
      });
    }

    expect(store.queryAuditLog({ limit: 3 }).length).toBe(3);
  });

  it("stores encrypted detail blobs", () => {
    const detail = new Uint8Array([42, 43, 44]);
    const iv = new Uint8Array(12).fill(1);
    const tag = new Uint8Array(16).fill(2);

    store.insertAuditEvent({
      timestamp: Date.now(),
      event_type: AuditEventType.SECRET_USE,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      detail_encrypted: detail,
      detail_iv: iv,
      detail_tag: tag,
      ip_address: null,
      session_id: null,
      success: true,
    });

    const events = store.queryAuditLog();
    expect(events[0]?.detail_encrypted).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(events[0]?.detail_encrypted ?? []).equals(Buffer.from(detail))).toBe(true);
  });

  it("stores success=false", () => {
    store.insertAuditEvent({
      timestamp: Date.now(),
      event_type: AuditEventType.ACCESS_DENIED,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: null,
      success: false,
    });

    const events = store.queryAuditLog();
    expect(events[0]?.success).toBe(false);
  });

  it("orders by timestamp DESC", () => {
    store.insertAuditEvent({
      timestamp: 1000,
      event_type: AuditEventType.SECRET_READ,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: null,
      success: true,
    });
    store.insertAuditEvent({
      timestamp: 3000,
      event_type: AuditEventType.SECRET_CREATE,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: null,
      success: true,
    });

    const events = store.queryAuditLog();
    expect(events[0]?.timestamp).toBe(3000);
    expect(events[1]?.timestamp).toBe(1000);
  });
});

describe("transaction", () => {
  it("commits on success", () => {
    store.transaction(() => {
      store.setMeta("tx-key", "tx-value");
    });
    expect(store.getMeta("tx-key")).toBe("tx-value");
  });

  it("rolls back on error", () => {
    try {
      store.transaction(() => {
        store.setMeta("rollback-key", "value");
        throw new Error("abort");
      });
    } catch {
      // expected
    }
    expect(store.getMeta("rollback-key")).toBeUndefined();
  });
});

describe("revoked_tokens", () => {
  it("inserts and queries a revoked token", () => {
    store.insertRevokedToken("jti-abc", Math.floor(Date.now() / 1000) + 3600);
    expect(store.isTokenRevoked("jti-abc")).toBe(true);
    expect(store.isTokenRevoked("jti-unknown")).toBe(false);
  });

  it("INSERT OR IGNORE on duplicate jti", () => {
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;
    store.insertRevokedToken("jti-dup", expiresAt);
    store.insertRevokedToken("jti-dup", expiresAt + 100); // should not throw
    expect(store.isTokenRevoked("jti-dup")).toBe(true);
  });

  it("prunes expired tokens", () => {
    const past = Math.floor(Date.now() / 1000) - 100;
    const future = Math.floor(Date.now() / 1000) + 3600;
    store.insertRevokedToken("jti-expired", past);
    store.insertRevokedToken("jti-active", future);

    const pruned = store.pruneExpiredTokens();
    expect(pruned).toBe(1);
    expect(store.isTokenRevoked("jti-expired")).toBe(false);
    expect(store.isTokenRevoked("jti-active")).toBe(true);
  });

  it("migration creates revoked_tokens table", () => {
    const row = store.db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='revoked_tokens'")
      .get() as { name: string } | undefined;
    expect(row?.name).toBe("revoked_tokens");
  });
});

// ---------------------------------------------------------------------------
// OAuth token helpers
// ---------------------------------------------------------------------------

function makeOAuthToken(secretId: string, overrides: Partial<OAuthTokenRow> = {}): OAuthTokenRow {
  return {
    secret_id: secretId,
    provider: "github",
    grant_type: "authorization_code",
    token_endpoint: "https://github.com/login/oauth/access_token",
    auth_endpoint: "https://github.com/login/oauth/authorize",
    client_id_encrypted: new Uint8Array([10, 20, 30]),
    client_id_iv: new Uint8Array(12).fill(1),
    client_id_tag: new Uint8Array(16).fill(2),
    client_secret_encrypted: null,
    client_secret_iv: null,
    client_secret_tag: null,
    scopes: null,
    refresh_token_encrypted: null,
    refresh_token_iv: null,
    refresh_token_tag: null,
    access_token_encrypted: null,
    access_token_iv: null,
    access_token_tag: null,
    access_token_expires_at: null,
    redirect_uri: null,
    pkce_method: "S256",
    ...overrides,
  };
}

function makeCertificate(
  secretId: string,
  overrides: Partial<CertificateRow> = {},
): CertificateRow {
  return {
    secret_id: secretId,
    subject: "CN=example.com",
    issuer: null,
    serial_number: null,
    not_before: null,
    not_after: null,
    private_key_encrypted: new Uint8Array([40, 50, 60]),
    private_key_iv: new Uint8Array(12).fill(3),
    private_key_tag: new Uint8Array(16).fill(4),
    certificate_pem: null,
    chain_pem: null,
    csr_pem: null,
    auto_renew: false,
    renew_before_days: 30,
    acme_account_encrypted: null,
    acme_account_iv: null,
    acme_account_tag: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// oauth_tokens CRUD
// ---------------------------------------------------------------------------

describe("oauth_tokens CRUD", () => {
  it("inserts and retrieves an OAuth token record", () => {
    const secret = makeSecret({ type: SecretType.OAUTH_TOKEN });
    store.insertSecret(secret);

    const oauthRow = makeOAuthToken(secret.id);
    store.insertOAuthToken(oauthRow);

    const retrieved = store.getOAuthToken(secret.id);
    expect(retrieved).toBeDefined();
    expect(retrieved?.secret_id).toBe(secret.id);
    expect(retrieved?.provider).toBe("github");
    expect(retrieved?.grant_type).toBe("authorization_code");
    expect(retrieved?.token_endpoint).toBe("https://github.com/login/oauth/access_token");
    expect(retrieved?.pkce_method).toBe("S256");
  });

  it("returns undefined for missing OAuth token", () => {
    expect(store.getOAuthToken("nonexistent")).toBeUndefined();
  });

  it("stores and retrieves encrypted client_id blob", () => {
    const secret = makeSecret({ type: SecretType.OAUTH_TOKEN });
    store.insertSecret(secret);

    const oauthRow = makeOAuthToken(secret.id);
    store.insertOAuthToken(oauthRow);

    const retrieved = store.getOAuthToken(secret.id);
    expect(retrieved?.client_id_encrypted).toBeInstanceOf(Uint8Array);
    expect(
      Buffer.from(retrieved?.client_id_encrypted ?? []).equals(
        Buffer.from(oauthRow.client_id_encrypted),
      ),
    ).toBe(true);
  });

  it("stores nullable encrypted fields as null", () => {
    const secret = makeSecret({ type: SecretType.OAUTH_TOKEN });
    store.insertSecret(secret);

    store.insertOAuthToken(makeOAuthToken(secret.id));

    const retrieved = store.getOAuthToken(secret.id);
    expect(retrieved?.client_secret_encrypted).toBeNull();
    expect(retrieved?.refresh_token_encrypted).toBeNull();
    expect(retrieved?.access_token_encrypted).toBeNull();
  });

  it("stores and retrieves all encrypted optional fields", () => {
    const secret = makeSecret({ type: SecretType.OAUTH_TOKEN });
    store.insertSecret(secret);

    const oauthRow = makeOAuthToken(secret.id, {
      client_secret_encrypted: new Uint8Array([11, 22]),
      client_secret_iv: new Uint8Array(12).fill(5),
      client_secret_tag: new Uint8Array(16).fill(6),
      refresh_token_encrypted: new Uint8Array([33, 44]),
      refresh_token_iv: new Uint8Array(12).fill(7),
      refresh_token_tag: new Uint8Array(16).fill(8),
      access_token_encrypted: new Uint8Array([55, 66]),
      access_token_iv: new Uint8Array(12).fill(9),
      access_token_tag: new Uint8Array(16).fill(10),
      access_token_expires_at: Date.now() + 3600_000,
      scopes: '["repo","user"]',
      redirect_uri: "http://localhost:19876/oauth/callback",
    });
    store.insertOAuthToken(oauthRow);

    const retrieved = store.getOAuthToken(secret.id);
    expect(retrieved?.client_secret_encrypted).toBeInstanceOf(Uint8Array);
    expect(retrieved?.refresh_token_encrypted).toBeInstanceOf(Uint8Array);
    expect(retrieved?.access_token_encrypted).toBeInstanceOf(Uint8Array);
    expect(retrieved?.scopes).toBe('["repo","user"]');
    expect(retrieved?.redirect_uri).toBe("http://localhost:19876/oauth/callback");
    expect(retrieved?.access_token_expires_at).toBe(oauthRow.access_token_expires_at);
  });

  it("updates token fields", () => {
    const secret = makeSecret({ type: SecretType.OAUTH_TOKEN });
    store.insertSecret(secret);
    store.insertOAuthToken(makeOAuthToken(secret.id));

    const newAccessToken = new Uint8Array([99, 88, 77]);
    const newIv = new Uint8Array(12).fill(11);
    const newTag = new Uint8Array(16).fill(12);
    const expiresAt = Date.now() + 7200_000;

    store.updateOAuthToken(secret.id, {
      access_token_encrypted: newAccessToken,
      access_token_iv: newIv,
      access_token_tag: newTag,
      access_token_expires_at: expiresAt,
    });

    const retrieved = store.getOAuthToken(secret.id);
    expect(
      Buffer.from(retrieved?.access_token_encrypted ?? []).equals(Buffer.from(newAccessToken)),
    ).toBe(true);
    expect(retrieved?.access_token_expires_at).toBe(expiresAt);
  });

  it("rejects update with invalid column name", () => {
    const secret = makeSecret({ type: SecretType.OAUTH_TOKEN });
    store.insertSecret(secret);
    store.insertOAuthToken(makeOAuthToken(secret.id));

    expect(() =>
      store.updateOAuthToken(secret.id, { "DROP TABLE; --": "x" } as never),
    ).toThrow("Invalid column name");
  });

  it("cascades delete when secret is deleted", () => {
    const secret = makeSecret({ type: SecretType.OAUTH_TOKEN });
    store.insertSecret(secret);
    store.insertOAuthToken(makeOAuthToken(secret.id));

    store.deleteSecret(secret.id);
    expect(store.getOAuthToken(secret.id)).toBeUndefined();
  });

  it("getExpiringOAuthTokens returns tokens expiring within window", () => {
    const s1 = makeSecret({ type: SecretType.OAUTH_TOKEN, status: SecretStatus.ACTIVE });
    const s2 = makeSecret({ type: SecretType.OAUTH_TOKEN, status: SecretStatus.ACTIVE });
    const s3 = makeSecret({ type: SecretType.OAUTH_TOKEN, status: SecretStatus.ACTIVE });
    store.insertSecret(s1);
    store.insertSecret(s2);
    store.insertSecret(s3);

    // Expiring in 2 minutes
    store.insertOAuthToken(
      makeOAuthToken(s1.id, { access_token_expires_at: Date.now() + 2 * 60 * 1000 }),
    );
    // Expiring in 10 minutes
    store.insertOAuthToken(
      makeOAuthToken(s2.id, { access_token_expires_at: Date.now() + 10 * 60 * 1000 }),
    );
    // No expiry set
    store.insertOAuthToken(makeOAuthToken(s3.id, { access_token_expires_at: null }));

    // Query for tokens expiring within 5 minutes
    const expiring = store.getExpiringOAuthTokens(5 * 60 * 1000);
    expect(expiring).toHaveLength(1);
    expect(expiring[0]?.secret_id).toBe(s1.id);
  });

  it("getExpiringOAuthTokens excludes revoked secrets", () => {
    const secret = makeSecret({ type: SecretType.OAUTH_TOKEN, status: SecretStatus.REVOKED });
    store.insertSecret(secret);
    store.insertOAuthToken(
      makeOAuthToken(secret.id, { access_token_expires_at: Date.now() + 60_000 }),
    );

    const expiring = store.getExpiringOAuthTokens(5 * 60 * 1000);
    expect(expiring).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// certificates CRUD
// ---------------------------------------------------------------------------

describe("certificates CRUD", () => {
  it("inserts and retrieves a certificate record", () => {
    const secret = makeSecret({ type: SecretType.CERTIFICATE });
    store.insertSecret(secret);

    const certRow = makeCertificate(secret.id);
    store.insertCertificate(certRow);

    const retrieved = store.getCertificate(secret.id);
    expect(retrieved).toBeDefined();
    expect(retrieved?.secret_id).toBe(secret.id);
    expect(retrieved?.subject).toBe("CN=example.com");
    expect(retrieved?.auto_renew).toBe(false);
    expect(retrieved?.renew_before_days).toBe(30);
  });

  it("returns undefined for missing certificate", () => {
    expect(store.getCertificate("nonexistent")).toBeUndefined();
  });

  it("stores and retrieves encrypted private key blob", () => {
    const secret = makeSecret({ type: SecretType.CERTIFICATE });
    store.insertSecret(secret);

    const certRow = makeCertificate(secret.id);
    store.insertCertificate(certRow);

    const retrieved = store.getCertificate(secret.id);
    expect(retrieved?.private_key_encrypted).toBeInstanceOf(Uint8Array);
    expect(
      Buffer.from(retrieved?.private_key_encrypted ?? []).equals(
        Buffer.from(certRow.private_key_encrypted),
      ),
    ).toBe(true);
  });

  it("stores all optional fields", () => {
    const secret = makeSecret({ type: SecretType.CERTIFICATE });
    store.insertSecret(secret);

    const now = Date.now();
    const certRow = makeCertificate(secret.id, {
      issuer: "CN=Let's Encrypt",
      serial_number: "0123456789abcdef",
      not_before: now - 86_400_000,
      not_after: now + 90 * 86_400_000,
      certificate_pem: "-----BEGIN CERTIFICATE-----\nMII...",
      chain_pem: "-----BEGIN CERTIFICATE-----\nMII...",
      csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nMII...",
      auto_renew: true,
      renew_before_days: 14,
      acme_account_encrypted: new Uint8Array([70, 80]),
      acme_account_iv: new Uint8Array(12).fill(11),
      acme_account_tag: new Uint8Array(16).fill(12),
    });
    store.insertCertificate(certRow);

    const retrieved = store.getCertificate(secret.id);
    expect(retrieved?.issuer).toBe("CN=Let's Encrypt");
    expect(retrieved?.serial_number).toBe("0123456789abcdef");
    expect(retrieved?.not_before).toBe(certRow.not_before);
    expect(retrieved?.not_after).toBe(certRow.not_after);
    expect(retrieved?.certificate_pem).toBe(certRow.certificate_pem);
    expect(retrieved?.chain_pem).toBe(certRow.chain_pem);
    expect(retrieved?.csr_pem).toBe(certRow.csr_pem);
    expect(retrieved?.auto_renew).toBe(true);
    expect(retrieved?.renew_before_days).toBe(14);
    expect(retrieved?.acme_account_encrypted).toBeInstanceOf(Uint8Array);
  });

  it("updates certificate fields", () => {
    const secret = makeSecret({ type: SecretType.CERTIFICATE });
    store.insertSecret(secret);
    store.insertCertificate(makeCertificate(secret.id));

    const newExpiry = Date.now() + 365 * 86_400_000;
    store.updateCertificate(secret.id, {
      issuer: "CN=Updated Issuer",
      not_after: newExpiry,
      certificate_pem: "-----BEGIN CERTIFICATE-----\nUpdated...",
      auto_renew: true,
    });

    const retrieved = store.getCertificate(secret.id);
    expect(retrieved?.issuer).toBe("CN=Updated Issuer");
    expect(retrieved?.not_after).toBe(newExpiry);
    expect(retrieved?.certificate_pem).toBe("-----BEGIN CERTIFICATE-----\nUpdated...");
    expect(retrieved?.auto_renew).toBe(true);
  });

  it("rejects update with invalid column name", () => {
    const secret = makeSecret({ type: SecretType.CERTIFICATE });
    store.insertSecret(secret);
    store.insertCertificate(makeCertificate(secret.id));

    expect(() =>
      store.updateCertificate(secret.id, { "DROP TABLE; --": "x" } as never),
    ).toThrow("Invalid column name");
  });

  it("cascades delete when secret is deleted", () => {
    const secret = makeSecret({ type: SecretType.CERTIFICATE });
    store.insertSecret(secret);
    store.insertCertificate(makeCertificate(secret.id));

    store.deleteSecret(secret.id);
    expect(store.getCertificate(secret.id)).toBeUndefined();
  });

  it("getExpiringCertificates returns certs expiring within window", () => {
    const s1 = makeSecret({ type: SecretType.CERTIFICATE, status: SecretStatus.ACTIVE });
    const s2 = makeSecret({ type: SecretType.CERTIFICATE, status: SecretStatus.ACTIVE });
    const s3 = makeSecret({ type: SecretType.CERTIFICATE, status: SecretStatus.ACTIVE });
    store.insertSecret(s1);
    store.insertSecret(s2);
    store.insertSecret(s3);

    const dayMs = 86_400_000;
    // Expiring in 10 days
    store.insertCertificate(
      makeCertificate(s1.id, { not_after: Date.now() + 10 * dayMs }),
    );
    // Expiring in 60 days
    store.insertCertificate(
      makeCertificate(s2.id, { not_after: Date.now() + 60 * dayMs }),
    );
    // No expiry
    store.insertCertificate(makeCertificate(s3.id, { not_after: null }));

    // Query for certs expiring within 30 days
    const expiring = store.getExpiringCertificates(30);
    expect(expiring).toHaveLength(1);
    expect(expiring[0]?.secret_id).toBe(s1.id);
  });

  it("getExpiringCertificates excludes revoked secrets", () => {
    const secret = makeSecret({ type: SecretType.CERTIFICATE, status: SecretStatus.REVOKED });
    store.insertSecret(secret);
    store.insertCertificate(
      makeCertificate(secret.id, { not_after: Date.now() + 86_400_000 }),
    );

    const expiring = store.getExpiringCertificates(30);
    expect(expiring).toHaveLength(0);
  });

  it("certificates table has indexes", () => {
    const indexes = store.db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='certificates' ORDER BY name",
      )
      .all() as { name: string }[];
    const names = indexes.map((i) => i.name);
    expect(names).toContain("idx_certs_expiry");
    expect(names).toContain("idx_certs_subject");
  });
});

describe("concurrent access", () => {
  it("two in-memory stores are independent", () => {
    const store2 = new SqliteStore(":memory:");

    store.setMeta("store1-key", "value");
    expect(store2.getMeta("store1-key")).toBeUndefined();

    store2.close();
  });
});

describe("concurrent file-based WAL access", () => {
  let fileDir: string;
  let filePath: string;
  let fileStore1: SqliteStore;
  let fileStore2: SqliteStore;

  beforeEach(() => {
    fileDir = join(tmpdir(), `harpoc-wal-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(fileDir, { recursive: true });
    filePath = join(fileDir, "test.vault.db");
    fileStore1 = new SqliteStore(filePath);
    fileStore2 = new SqliteStore(filePath);
  });

  afterEach(() => {
    fileStore1.close();
    fileStore2.close();
    try {
      rmSync(fileDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("two stores share data via same file", () => {
    fileStore1.setMeta("shared-key", "shared-value");
    expect(fileStore2.getMeta("shared-key")).toBe("shared-value");
  });

  it("WAL mode is set for file-based DB", () => {
    const result = fileStore1.db.pragma("journal_mode") as { journal_mode: string }[];
    expect(result[0]?.journal_mode).toBe("wal");
  });

  it("concurrent reader sees writer's inserts", () => {
    const secret = makeSecret();
    fileStore1.insertSecret(secret);

    const retrieved = fileStore2.getSecret(secret.id);
    expect(retrieved).toBeDefined();
    expect(retrieved?.id).toBe(secret.id);
  });
});
