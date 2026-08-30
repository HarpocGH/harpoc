import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import { SqliteStore } from "./sqlite-store.js";
import { LATEST_SCHEMA_VERSION } from "./schema.js";

let store: SqliteStore;

beforeEach(() => {
  store = new SqliteStore(":memory:");
});

afterEach(() => {
  store.close();
});

function objectNames(type: "table" | "index"): string[] {
  return (
    store.db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = ? AND name NOT LIKE 'sqlite_%' ORDER BY name",
      )
      .all(type) as { name: string }[]
  ).map((row) => row.name);
}

function tableInfo(table: string): { name: string; notnull: number; dflt_value: string | null }[] {
  return store.db.prepare(`PRAGMA table_info(${table})`).all() as {
    name: string;
    notnull: number;
    dflt_value: string | null;
  }[];
}

function sqliteCode(run: () => void): string | undefined {
  let caught: unknown;
  try {
    run();
  } catch (err) {
    caught = err;
  }
  return (caught as { code?: string } | undefined)?.code;
}

function insertBareSecret(id: string, nameHmac: string | null): void {
  const blob = Buffer.alloc(16, 1);
  store.db
    .prepare(
      `INSERT INTO secrets (
        id, name_encrypted, name_iv, name_tag, type,
        wrapped_dek, dek_iv, dek_tag, ciphertext, ct_iv, ct_tag,
        created_at, updated_at, name_hmac
      ) VALUES (?, ?, ?, ?, 'api_key', ?, ?, ?, ?, ?, ?, 1, 1, ?)`,
    )
    .run(id, blob, blob, blob, blob, blob, blob, blob, blob, blob, nameHmac);
}

function insertBareOAuthRow(secretId: string, authMethodClause: string): void {
  const blob = Buffer.alloc(16, 1);
  const columns = authMethodClause === "" ? "" : ", token_endpoint_auth_method";
  const values = authMethodClause === "" ? "" : `, ${authMethodClause}`;
  store.db
    .prepare(
      `INSERT INTO oauth_tokens (
        secret_id, provider, grant_type, token_endpoint,
        client_id_encrypted, client_id_iv, client_id_tag${columns}
      ) VALUES (?, 'github', 'authorization_code', 'https://example.com/token', ?, ?, ?${values})`,
    )
    .run(secretId, blob, blob, blob);
}

describe("v1.5 baseline DDL (R2)", () => {
  it("creates the twelve tables and stamps schema_version 12", () => {
    expect(store.getMeta("schema_version")).toBe(String(LATEST_SCHEMA_VERSION));
    expect(objectNames("table")).toEqual([
      "access_policies",
      "agents",
      "audit_log",
      "certificates",
      "connection_configs",
      "injection_policies",
      "issued_tokens",
      "mcp_servers",
      "oauth_tokens",
      "revoked_tokens",
      "secrets",
      "vault_meta",
    ]);
  });

  it("creates the sixteen indexes, the live-name partial unique index included", () => {
    expect(objectNames("index")).toEqual([
      "idx_audit_principal",
      "idx_audit_secret_id",
      "idx_audit_timestamp",
      "idx_certs_expiry",
      "idx_certs_subject",
      "idx_issued_tokens_agent",
      "idx_issued_tokens_expires",
      "idx_policies_principal",
      "idx_policies_secret_id",
      "idx_revoked_tokens_expires_at",
      "idx_secrets_expires_at",
      "idx_secrets_name_hmac",
      "idx_secrets_name_hmac_live",
      "idx_secrets_project",
      "idx_secrets_status",
      "idx_secrets_type",
    ]);
    const live = store.db
      .prepare("SELECT sql FROM sqlite_master WHERE name = 'idx_secrets_name_hmac_live'")
      .get() as { sql: string };
    expect(live.sql).toContain("WHERE status != 'revoked'");
  });

  it("secrets has no sync_version and name_hmac is NOT NULL", () => {
    const columns = tableInfo("secrets");
    expect(columns.map((c) => c.name)).not.toContain("sync_version");
    expect(columns.find((c) => c.name === "name_hmac")?.notnull).toBe(1);
    expect(sqliteCode(() => insertBareSecret("s-null", null))).toBe("SQLITE_CONSTRAINT_NOTNULL");
    insertBareSecret("s-ok", "hmac-ok");
    expect(store.db.prepare("SELECT COUNT(*) AS c FROM secrets").get()).toEqual({ c: 1 });
  });

  it("audit_log.row_hmac is NOT NULL — a link-less INSERT and a nulled link are refused", () => {
    expect(tableInfo("audit_log").find((c) => c.name === "row_hmac")?.notnull).toBe(1);
    expect(
      sqliteCode(() =>
        store.db
          .prepare("INSERT INTO audit_log (timestamp, event_type, success) VALUES (1, 'x', 1)")
          .run(),
      ),
    ).toBe("SQLITE_CONSTRAINT_NOTNULL");

    const id = store.insertAuditEvent(
      {
        timestamp: 1,
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
      },
      new Uint8Array(32).fill(7),
    );
    expect(
      sqliteCode(() =>
        store.db.prepare("UPDATE audit_log SET row_hmac = NULL WHERE id = ?").run(id),
      ),
    ).toBe("SQLITE_CONSTRAINT_NOTNULL");
  });

  it("oauth_tokens.token_endpoint_auth_method defaults to client_secret_post and is checked", () => {
    insertBareSecret("s-oauth-a", "hmac-a");
    insertBareSecret("s-oauth-b", "hmac-b");
    insertBareSecret("s-oauth-c", "hmac-c");
    const column = tableInfo("oauth_tokens").find((c) => c.name === "token_endpoint_auth_method");
    expect(column?.notnull).toBe(1);
    expect(column?.dflt_value).toBe("'client_secret_post'");

    insertBareOAuthRow("s-oauth-a", "");
    expect(store.getOAuthToken("s-oauth-a")?.token_endpoint_auth_method).toBe("client_secret_post");
    expect(sqliteCode(() => insertBareOAuthRow("s-oauth-b", "NULL"))).toBe(
      "SQLITE_CONSTRAINT_NOTNULL",
    );
    expect(sqliteCode(() => insertBareOAuthRow("s-oauth-c", "'private_key_jwt'"))).toBe(
      "SQLITE_CONSTRAINT_CHECK",
    );
    expect(
      sqliteCode(() =>
        store.db
          .prepare("UPDATE oauth_tokens SET token_endpoint_auth_method = NULL WHERE secret_id = ?")
          .run("s-oauth-a"),
      ),
    ).toBe("SQLITE_CONSTRAINT_NOTNULL");
  });

  it("agents and issued_tokens carry the v1.4 columns, indexes and the SET NULL reference", () => {
    expect(tableInfo("agents").map((c) => c.name)).toEqual([
      "id",
      "name",
      "description",
      "owner",
      "status",
      "created_at",
      "updated_at",
      "deactivated_at",
    ]);
    expect(tableInfo("issued_tokens").map((c) => c.name)).toEqual([
      "jti",
      "subject",
      "principal_type",
      "agent_id",
      "scope",
      "project",
      "secrets",
      "label",
      "issued_at",
      "expires_at",
      "revoked_at",
    ]);
    const auditIndexColumns = (
      store.db.prepare("PRAGMA index_info(idx_audit_principal)").all() as { name: string }[]
    ).map((c) => c.name);
    expect(auditIndexColumns).toEqual(["principal_type", "principal_id", "timestamp"]);

    const fks = store.db.prepare("PRAGMA foreign_key_list(issued_tokens)").all() as {
      table: string;
      from: string;
      to: string;
      on_delete: string;
    }[];
    expect(fks).toEqual([
      expect.objectContaining({
        table: "agents",
        from: "agent_id",
        to: "id",
        on_delete: "SET NULL",
      }),
    ]);

    const now = Date.now();
    store.db
      .prepare(
        `INSERT INTO agents (id, name, description, owner, status, created_at, updated_at, deactivated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run("agent-id-1", "alpha", null, null, "active", now, now, null);
    store.db
      .prepare(
        `INSERT INTO issued_tokens (
          jti, subject, principal_type, agent_id, scope, project, secrets, label,
          issued_at, expires_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        "jti-1",
        "alpha",
        "agent",
        "agent-id-1",
        JSON.stringify(["read"]),
        null,
        null,
        null,
        now,
        now + 60_000,
        null,
      );
    store.db.prepare("DELETE FROM agents WHERE id = ?").run("agent-id-1");
    expect(
      store.db.prepare("SELECT agent_id FROM issued_tokens WHERE jti = 'jti-1'").get(),
    ).toEqual({ agent_id: null });
  });
});
