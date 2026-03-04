import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AccessPolicy, Secret } from "@harpoc/shared";
import { AuditEventType, SecretStatus, SecretType } from "@harpoc/shared";
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

  it("sets schema_version to 3", () => {
    expect(store.getMeta("schema_version")).toBe("3");
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

    expect(() =>
      store.updateSecret(secret.id, { "DROP TABLE secrets; --": "x" } as never),
    ).toThrow("Invalid column name");
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

    store.insertPolicy(
      makePolicy(secret.id, { principal_type: "agent", principal_id: "agent-x" }),
    );

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
