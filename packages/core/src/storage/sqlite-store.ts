import Database from "better-sqlite3";
import type {
  AccessPolicy,
  AuditEvent,
  AuditEventType,
  PrincipalType,
  Secret,
  SecretStatus,
  SecretType,
} from "@harpoc/shared";
import { SQLITE_PRAGMAS, VaultError } from "@harpoc/shared";
import { migration001 } from "./migrations/001-initial.js";
import { migration002 } from "./migrations/002-revoked-tokens.js";
import { migration003 } from "./migrations/003-name-hmac.js";
import { migration004 } from "./migrations/004-oauth-tokens.js";
import { migration005 } from "./migrations/005-certificates.js";
import { migration006 } from "./migrations/006-injection-policies.js";
import { migration007 } from "./migrations/007-mcp-servers.js";
import { migration008 } from "./migrations/008-connection-configs.js";
import { migration009 } from "./migrations/009-name-hmac-unique.js";
import { migration010 } from "./migrations/010-audit-row-hmac.js";
import { migration011 } from "./migrations/011-oauth-auth-method.js";

/** True for a better-sqlite3 UNIQUE/PRIMARY-KEY constraint violation. */
export function isUniqueConstraintError(err: unknown): boolean {
  return (
    err instanceof Error &&
    "code" in err &&
    (err.code === "SQLITE_CONSTRAINT_UNIQUE" || err.code === "SQLITE_CONSTRAINT_PRIMARYKEY")
  );
}

/** Filters for querying secrets. */
export interface SecretFilter {
  project?: string;
  type?: SecretType;
  status?: SecretStatus;
}

/** Filters for querying audit log. */
export interface AuditFilter {
  secretId?: string;
  eventType?: AuditEventType;
  since?: number;
  until?: number;
  limit?: number;
}

/** Raw audit row plus its chain link, for tamper-evidence verification. */
export interface AuditChainRow {
  id: number;
  timestamp: number;
  event_type: string;
  secret_id: string | null;
  principal_type: string | null;
  principal_id: string | null;
  detail_encrypted: Uint8Array | null;
  detail_iv: Uint8Array | null;
  detail_tag: Uint8Array | null;
  ip_address: string | null;
  session_id: string | null;
  success: boolean;
  row_hmac: Uint8Array | null;
}

/** OAuth token record for DB storage (encrypted fields as Buffer/Uint8Array). */
export interface OAuthTokenRow {
  secret_id: string;
  provider: string;
  grant_type: string;
  token_endpoint: string;
  auth_endpoint: string | null;
  client_id_encrypted: Uint8Array;
  client_id_iv: Uint8Array;
  client_id_tag: Uint8Array;
  client_secret_encrypted: Uint8Array | null;
  client_secret_iv: Uint8Array | null;
  client_secret_tag: Uint8Array | null;
  scopes: string | null;
  refresh_token_encrypted: Uint8Array | null;
  refresh_token_iv: Uint8Array | null;
  refresh_token_tag: Uint8Array | null;
  access_token_encrypted: Uint8Array | null;
  access_token_iv: Uint8Array | null;
  access_token_tag: Uint8Array | null;
  access_token_expires_at: number | null;
  redirect_uri: string | null;
  pkce_method: string;
  token_endpoint_auth_method: string | null;
}

/** Certificate record for DB storage (encrypted fields as Buffer/Uint8Array). */
export interface CertificateRow {
  secret_id: string;
  subject: string;
  issuer: string | null;
  serial_number: string | null;
  not_before: number | null;
  not_after: number | null;
  private_key_encrypted: Uint8Array;
  private_key_iv: Uint8Array;
  private_key_tag: Uint8Array;
  certificate_pem: string | null;
  chain_pem: string | null;
  csr_pem: string | null;
  auto_renew: boolean;
  renew_before_days: number;
  acme_account_encrypted: Uint8Array | null;
  acme_account_iv: Uint8Array | null;
  acme_account_tag: Uint8Array | null;
}

/**
 * Per-secret injection policy for DB storage. The policy JSON (URL, command and
 * env allowlists) is encrypted as a single blob before it reaches the store.
 */
export interface InjectionPolicyRow {
  secret_id: string;
  policy_encrypted: Uint8Array;
  policy_iv: Uint8Array;
  policy_tag: Uint8Array;
  created_at: number;
  updated_at: number;
}

/**
 * Per-secret downstream MCP server configuration for DB storage. The config
 * JSON (transport, launch command / endpoint URL) is encrypted as a single
 * blob before it reaches the store.
 */
export interface McpServerRow {
  secret_id: string;
  config_encrypted: Uint8Array;
  config_iv: Uint8Array;
  config_tag: Uint8Array;
  created_at: number;
  updated_at: number;
}

/**
 * Per-secret endpoint-authentication config for DB storage. The config JSON
 * (database TLS policy / SSH pinned host keys) is encrypted as a single blob
 * before it reaches the store.
 */
export interface ConnectionConfigRow {
  secret_id: string;
  config_encrypted: Uint8Array;
  config_iv: Uint8Array;
  config_tag: Uint8Array;
  created_at: number;
  updated_at: number;
}

export class SqliteStore {
  private static readonly UPDATABLE_COLUMNS = new Set([
    "ciphertext",
    "ct_iv",
    "ct_tag",
    "wrapped_dek",
    "dek_iv",
    "dek_tag",
    "updated_at",
    "rotated_at",
    "version",
    "status",
    "expires_at",
    "sync_version",
    "name_hmac",
  ]);

  readonly db: Database.Database;

  constructor(path: string) {
    try {
      this.db = new Database(path);
    } catch (err) {
      throw VaultError.databaseError(
        `Failed to open database: ${err instanceof Error ? err.message : "unknown"}`,
      );
    }

    this.setPragmas();
    try {
      this.runMigrations();
    } catch (err) {
      // A failed migration (e.g. the 009 duplicate-name abort) must not leak
      // the open handle, which would lock the file on Windows.
      this.db.close();
      throw err;
    }
  }

  private setPragmas(): void {
    for (const [key, value] of Object.entries(SQLITE_PRAGMAS)) {
      this.db.pragma(`${key} = ${value}`);
    }
  }

  private runMigrations(): void {
    const currentVersion = this.getMigrationVersion();
    if (currentVersion < 1) {
      this.db.transaction(() => {
        this.db.exec(migration001.up);
        this.setMeta("schema_version", "1");
      })();
    }
    if (currentVersion < 2) {
      this.db.transaction(() => {
        this.db.exec(migration002.up);
        this.setMeta("schema_version", "2");
      })();
    }
    if (currentVersion < 3) {
      this.db.transaction(() => {
        this.db.exec(migration003.up);
        this.setMeta("schema_version", "3");
      })();
    }
    if (currentVersion < 4) {
      this.db.transaction(() => {
        this.db.exec(migration004.up);
        this.setMeta("schema_version", "4");
      })();
    }
    if (currentVersion < 5) {
      this.db.transaction(() => {
        this.db.exec(migration005.up);
        this.setMeta("schema_version", "5");
      })();
    }
    if (currentVersion < 6) {
      this.db.transaction(() => {
        this.db.exec(migration006.up);
        this.setMeta("schema_version", "6");
      })();
    }
    if (currentVersion < 7) {
      this.db.transaction(() => {
        this.db.exec(migration007.up);
        this.setMeta("schema_version", "7");
      })();
    }
    if (currentVersion < 8) {
      this.db.transaction(() => {
        this.db.exec(migration008.up);
        this.setMeta("schema_version", "8");
      })();
    }
    if (currentVersion < 9) {
      this.db.transaction(() => {
        // The unique index cannot be built while live duplicates exist (a
        // pre-fix TOCTOU-race artifact). Surface a clear, actionable error
        // instead of a raw "UNIQUE constraint failed" from the index build.
        this.assertNoLiveDuplicateNames();
        this.db.exec(migration009.up);
        this.setMeta("schema_version", "9");
      })();
    }
    if (currentVersion < 10) {
      this.db.transaction(() => {
        this.db.exec(migration010.up);
        this.setMeta("schema_version", "10");
      })();
    }
    if (currentVersion < 11) {
      this.db.transaction(() => {
        this.db.exec(migration011.up);
        this.setMeta("schema_version", "11");
      })();
    }
  }

  /** Reject an upgrade when two non-revoked secrets share a name_hmac. */
  private assertNoLiveDuplicateNames(): void {
    const duplicates = this.db
      .prepare(
        `SELECT COUNT(*) AS c FROM (
           SELECT name_hmac FROM secrets
           WHERE status != 'revoked' AND name_hmac IS NOT NULL
           GROUP BY name_hmac HAVING COUNT(*) > 1
         )`,
      )
      .get() as { c: number };
    if (duplicates.c > 0) {
      throw VaultError.vaultCorrupted(
        `Cannot upgrade vault: ${duplicates.c} secret name(s) have multiple active entries. ` +
          `Revoke the duplicate secret(s) and retry.`,
      );
    }
  }

  private getMigrationVersion(): number {
    try {
      // Check if vault_meta table exists
      const row = this.db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='vault_meta'")
        .get() as { name: string } | undefined;

      if (!row) return 0;

      const version = this.getMeta("schema_version");
      return version ? parseInt(version, 10) : 0;
    } catch {
      return 0;
    }
  }

  // ---------------------------------------------------------------------------
  // vault_meta
  // ---------------------------------------------------------------------------

  getMeta(key: string): string | undefined {
    const row = this.db.prepare("SELECT value FROM vault_meta WHERE key = ?").get(key) as
      | { value: string }
      | undefined;
    return row?.value;
  }

  setMeta(key: string, value: string): void {
    this.db.prepare("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)").run(key, value);
  }

  // ---------------------------------------------------------------------------
  // secrets
  // ---------------------------------------------------------------------------

  insertSecret(secret: Secret): void {
    try {
      this.db
        .prepare(
          `INSERT INTO secrets (
            id, name_encrypted, name_iv, name_tag, type, project,
            wrapped_dek, dek_iv, dek_tag,
            ciphertext, ct_iv, ct_tag,
            metadata_encrypted, metadata_iv, metadata_tag,
            created_at, updated_at, expires_at, rotated_at,
            version, status, sync_version, name_hmac
          ) VALUES (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?
          )`,
        )
        .run(
          secret.id,
          Buffer.from(secret.name_encrypted),
          Buffer.from(secret.name_iv),
          Buffer.from(secret.name_tag),
          secret.type,
          secret.project,
          Buffer.from(secret.wrapped_dek),
          Buffer.from(secret.dek_iv),
          Buffer.from(secret.dek_tag),
          Buffer.from(secret.ciphertext),
          Buffer.from(secret.ct_iv),
          Buffer.from(secret.ct_tag),
          secret.metadata_encrypted ? Buffer.from(secret.metadata_encrypted) : null,
          secret.metadata_iv ? Buffer.from(secret.metadata_iv) : null,
          secret.metadata_tag ? Buffer.from(secret.metadata_tag) : null,
          secret.created_at,
          secret.updated_at,
          secret.expires_at,
          secret.rotated_at,
          secret.version,
          secret.status,
          secret.sync_version,
          secret.name_hmac,
        );
    } catch (err) {
      // Preserve a UNIQUE-constraint violation so the caller can map it to
      // DUPLICATE_SECRET (it knows the plaintext name); other failures wrap.
      if (isUniqueConstraintError(err)) throw err;
      throw VaultError.databaseError(
        `Failed to insert secret: ${err instanceof Error ? err.message : "unknown"}`,
      );
    }
  }

  getSecret(id: string): Secret | undefined {
    const row = this.db.prepare("SELECT * FROM secrets WHERE id = ?").get(id) as
      | Record<string, unknown>
      | undefined;
    return row ? this.rowToSecret(row) : undefined;
  }

  listSecrets(filter?: SecretFilter): Secret[] {
    let sql = "SELECT * FROM secrets WHERE 1=1";
    const params: unknown[] = [];

    if (filter?.project !== undefined) {
      sql += " AND project = ?";
      params.push(filter.project);
    }
    if (filter?.type !== undefined) {
      sql += " AND type = ?";
      params.push(filter.type);
    }
    if (filter?.status !== undefined) {
      sql += " AND status = ?";
      params.push(filter.status);
    }

    sql += " ORDER BY created_at DESC";

    const rows = this.db.prepare(sql).all(...params) as Record<string, unknown>[];
    return rows.map((row) => this.rowToSecret(row));
  }

  updateSecret(
    id: string,
    updates: Partial<
      Pick<
        Secret,
        | "ciphertext"
        | "ct_iv"
        | "ct_tag"
        | "wrapped_dek"
        | "dek_iv"
        | "dek_tag"
        | "updated_at"
        | "rotated_at"
        | "version"
        | "status"
        | "expires_at"
        | "sync_version"
        | "name_hmac"
      >
    >,
  ): void {
    const setClauses: string[] = [];
    const params: unknown[] = [];

    for (const [key, value] of Object.entries(updates)) {
      if (!SqliteStore.UPDATABLE_COLUMNS.has(key)) {
        throw VaultError.internalError(`Invalid column name for update: ${key}`);
      }
      setClauses.push(`${key} = ?`);
      params.push(value instanceof Uint8Array ? Buffer.from(value) : value);
    }

    if (setClauses.length === 0) return;

    params.push(id);
    this.db.prepare(`UPDATE secrets SET ${setClauses.join(", ")} WHERE id = ?`).run(...params);
  }

  getSecretsByNameHmac(nameHmac: string): Secret[] {
    const rows = this.db
      .prepare("SELECT * FROM secrets WHERE name_hmac = ? ORDER BY created_at DESC")
      .all(nameHmac) as Record<string, unknown>[];
    return rows.map((row) => this.rowToSecret(row));
  }

  updateSecretNameHmac(id: string, nameHmac: string): void {
    this.db.prepare("UPDATE secrets SET name_hmac = ? WHERE id = ?").run(nameHmac, id);
  }

  deleteSecret(id: string): boolean {
    const result = this.db.prepare("DELETE FROM secrets WHERE id = ?").run(id);
    return result.changes > 0;
  }

  // ---------------------------------------------------------------------------
  // access_policies
  // ---------------------------------------------------------------------------

  insertPolicy(policy: AccessPolicy): void {
    this.db
      .prepare(
        `INSERT INTO access_policies (
          id, secret_id, principal_type, principal_id, permissions,
          created_at, expires_at, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        policy.id,
        policy.secret_id,
        policy.principal_type,
        policy.principal_id,
        JSON.stringify(policy.permissions),
        policy.created_at,
        policy.expires_at,
        policy.created_by,
      );
  }

  getPolicy(id: string): AccessPolicy | undefined {
    const row = this.db.prepare("SELECT * FROM access_policies WHERE id = ?").get(id) as
      | Record<string, unknown>
      | undefined;
    return row ? this.rowToPolicy(row) : undefined;
  }

  listPolicies(secretId?: string): AccessPolicy[] {
    let sql = "SELECT * FROM access_policies";
    const params: unknown[] = [];

    if (secretId) {
      sql += " WHERE secret_id = ?";
      params.push(secretId);
    }

    sql += " ORDER BY created_at DESC";

    const rows = this.db.prepare(sql).all(...params) as Record<string, unknown>[];
    return rows.map((row) => this.rowToPolicy(row));
  }

  listPoliciesByPrincipal(principalType: PrincipalType, principalId: string): AccessPolicy[] {
    const rows = this.db
      .prepare(
        "SELECT * FROM access_policies WHERE principal_type = ? AND principal_id = ? ORDER BY created_at DESC",
      )
      .all(principalType, principalId) as Record<string, unknown>[];
    return rows.map((row) => this.rowToPolicy(row));
  }

  deletePolicy(id: string): boolean {
    const result = this.db.prepare("DELETE FROM access_policies WHERE id = ?").run(id);
    return result.changes > 0;
  }

  // ---------------------------------------------------------------------------
  // audit_log
  // ---------------------------------------------------------------------------

  insertAuditEvent(event: Omit<AuditEvent, "id">, rowHmac: Uint8Array | null = null): number {
    const result = this.db
      .prepare(
        `INSERT INTO audit_log (
          timestamp, event_type, secret_id,
          principal_type, principal_id,
          detail_encrypted, detail_iv, detail_tag,
          ip_address, session_id, success, row_hmac
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        event.timestamp,
        event.event_type,
        event.secret_id,
        event.principal_type,
        event.principal_id,
        event.detail_encrypted ? Buffer.from(event.detail_encrypted) : null,
        event.detail_iv ? Buffer.from(event.detail_iv) : null,
        event.detail_tag ? Buffer.from(event.detail_tag) : null,
        event.ip_address,
        event.session_id,
        event.success ? 1 : 0,
        rowHmac ? Buffer.from(rowHmac) : null,
      );
    return Number(result.lastInsertRowid);
  }

  /** The most recent row's chain link, or null if none / the last row is legacy. */
  getLastAuditRowHmac(): Uint8Array | null {
    const row = this.db.prepare("SELECT row_hmac FROM audit_log ORDER BY id DESC LIMIT 1").get() as
      | { row_hmac: Buffer | null }
      | undefined;
    return row?.row_hmac ? new Uint8Array(row.row_hmac) : null;
  }

  /**
   * The newest chained audit row (the anchorable chain tail), skipping trailing
   * legacy rows. Distinct from getLastAuditRowHmac, which intentionally looks
   * only at the very last row (insert-time chain semantics).
   */
  getLastChainedAuditRow(): { id: number; timestamp: number; row_hmac: Uint8Array } | null {
    const row = this.db
      .prepare(
        "SELECT id, timestamp, row_hmac FROM audit_log WHERE row_hmac IS NOT NULL ORDER BY id DESC LIMIT 1",
      )
      .get() as { id: number; timestamp: number; row_hmac: Buffer } | undefined;
    if (!row) return null;
    return { id: row.id, timestamp: row.timestamp, row_hmac: new Uint8Array(row.row_hmac) };
  }

  /** All audit rows in insertion order, with the fields the chain HMAC covers. */
  getAuditChainRows(): AuditChainRow[] {
    const rows = this.db
      .prepare(
        `SELECT id, timestamp, event_type, secret_id, principal_type, principal_id,
                detail_encrypted, detail_iv, detail_tag, ip_address, session_id,
                success, row_hmac
         FROM audit_log ORDER BY id ASC`,
      )
      .all() as Record<string, unknown>[];
    return rows.map((row) => ({
      id: row.id as number,
      timestamp: row.timestamp as number,
      event_type: row.event_type as string,
      secret_id: (row.secret_id as string) ?? null,
      principal_type: (row.principal_type as string) ?? null,
      principal_id: (row.principal_id as string) ?? null,
      detail_encrypted: row.detail_encrypted
        ? new Uint8Array(row.detail_encrypted as Buffer)
        : null,
      detail_iv: row.detail_iv ? new Uint8Array(row.detail_iv as Buffer) : null,
      detail_tag: row.detail_tag ? new Uint8Array(row.detail_tag as Buffer) : null,
      ip_address: (row.ip_address as string) ?? null,
      session_id: (row.session_id as string) ?? null,
      success: row.success === 1,
      row_hmac: row.row_hmac ? new Uint8Array(row.row_hmac as Buffer) : null,
    }));
  }

  queryAuditLog(filter?: AuditFilter): AuditEvent[] {
    let sql = "SELECT * FROM audit_log WHERE 1=1";
    const params: unknown[] = [];

    if (filter?.secretId) {
      sql += " AND secret_id = ?";
      params.push(filter.secretId);
    }
    if (filter?.eventType) {
      sql += " AND event_type = ?";
      params.push(filter.eventType);
    }
    if (filter?.since) {
      sql += " AND timestamp >= ?";
      params.push(filter.since);
    }
    if (filter?.until) {
      sql += " AND timestamp <= ?";
      params.push(filter.until);
    }

    sql += " ORDER BY timestamp DESC";

    if (filter?.limit) {
      sql += " LIMIT ?";
      params.push(filter.limit);
    }

    const rows = this.db.prepare(sql).all(...params) as Record<string, unknown>[];
    return rows.map((row) => this.rowToAuditEvent(row));
  }

  // ---------------------------------------------------------------------------
  // revoked_tokens
  // ---------------------------------------------------------------------------

  insertRevokedToken(jti: string, expiresAt: number): void {
    this.db
      .prepare(
        "INSERT OR IGNORE INTO revoked_tokens (jti, expires_at, revoked_at) VALUES (?, ?, ?)",
      )
      .run(jti, expiresAt, Date.now());
  }

  isTokenRevoked(jti: string): boolean {
    const row = this.db.prepare("SELECT jti FROM revoked_tokens WHERE jti = ?").get(jti) as
      | { jti: string }
      | undefined;
    return row !== undefined;
  }

  pruneExpiredTokens(): number {
    const result = this.db
      .prepare("DELETE FROM revoked_tokens WHERE expires_at < ?")
      .run(Math.floor(Date.now() / 1000));
    return result.changes;
  }

  // ---------------------------------------------------------------------------
  // oauth_tokens
  // ---------------------------------------------------------------------------

  insertOAuthToken(record: OAuthTokenRow): void {
    try {
      this.db
        .prepare(
          `INSERT INTO oauth_tokens (
            secret_id, provider, grant_type, token_endpoint, auth_endpoint,
            client_id_encrypted, client_id_iv, client_id_tag,
            client_secret_encrypted, client_secret_iv, client_secret_tag,
            scopes,
            refresh_token_encrypted, refresh_token_iv, refresh_token_tag,
            access_token_encrypted, access_token_iv, access_token_tag,
            access_token_expires_at, redirect_uri, pkce_method,
            token_endpoint_auth_method
          ) VALUES (
            ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?
          )`,
        )
        .run(
          record.secret_id,
          record.provider,
          record.grant_type,
          record.token_endpoint,
          record.auth_endpoint,
          Buffer.from(record.client_id_encrypted),
          Buffer.from(record.client_id_iv),
          Buffer.from(record.client_id_tag),
          record.client_secret_encrypted ? Buffer.from(record.client_secret_encrypted) : null,
          record.client_secret_iv ? Buffer.from(record.client_secret_iv) : null,
          record.client_secret_tag ? Buffer.from(record.client_secret_tag) : null,
          record.scopes,
          record.refresh_token_encrypted ? Buffer.from(record.refresh_token_encrypted) : null,
          record.refresh_token_iv ? Buffer.from(record.refresh_token_iv) : null,
          record.refresh_token_tag ? Buffer.from(record.refresh_token_tag) : null,
          record.access_token_encrypted ? Buffer.from(record.access_token_encrypted) : null,
          record.access_token_iv ? Buffer.from(record.access_token_iv) : null,
          record.access_token_tag ? Buffer.from(record.access_token_tag) : null,
          record.access_token_expires_at,
          record.redirect_uri,
          record.pkce_method,
          record.token_endpoint_auth_method,
        );
    } catch (err) {
      throw VaultError.databaseError(
        `Failed to insert OAuth token: ${err instanceof Error ? err.message : "unknown"}`,
      );
    }
  }

  getOAuthToken(secretId: string): OAuthTokenRow | undefined {
    const row = this.db.prepare("SELECT * FROM oauth_tokens WHERE secret_id = ?").get(secretId) as
      | Record<string, unknown>
      | undefined;
    return row ? this.rowToOAuthToken(row) : undefined;
  }

  updateOAuthToken(
    secretId: string,
    fields: Partial<
      Pick<
        OAuthTokenRow,
        | "refresh_token_encrypted"
        | "refresh_token_iv"
        | "refresh_token_tag"
        | "access_token_encrypted"
        | "access_token_iv"
        | "access_token_tag"
        | "access_token_expires_at"
        | "scopes"
      >
    >,
  ): void {
    const ALLOWED = new Set([
      "refresh_token_encrypted",
      "refresh_token_iv",
      "refresh_token_tag",
      "access_token_encrypted",
      "access_token_iv",
      "access_token_tag",
      "access_token_expires_at",
      "scopes",
    ]);

    const setClauses: string[] = [];
    const params: unknown[] = [];

    for (const [key, value] of Object.entries(fields)) {
      if (!ALLOWED.has(key)) {
        throw VaultError.internalError(`Invalid column name for OAuth token update: ${key}`);
      }
      setClauses.push(`${key} = ?`);
      params.push(value instanceof Uint8Array ? Buffer.from(value) : value);
    }

    if (setClauses.length === 0) return;

    params.push(secretId);
    this.db
      .prepare(`UPDATE oauth_tokens SET ${setClauses.join(", ")} WHERE secret_id = ?`)
      .run(...params);
  }

  getExpiringOAuthTokens(withinMs: number): OAuthTokenRow[] {
    const threshold = Date.now() + withinMs;
    const rows = this.db
      .prepare(
        `SELECT ot.* FROM oauth_tokens ot
         JOIN secrets s ON s.id = ot.secret_id
         WHERE ot.access_token_expires_at IS NOT NULL
           AND ot.access_token_expires_at <= ?
           AND s.status = 'active'
         ORDER BY ot.access_token_expires_at ASC`,
      )
      .all(threshold) as Record<string, unknown>[];
    return rows.map((row) => this.rowToOAuthToken(row));
  }

  // ---------------------------------------------------------------------------
  // certificates
  // ---------------------------------------------------------------------------

  insertCertificate(record: CertificateRow): void {
    try {
      this.db
        .prepare(
          `INSERT INTO certificates (
            secret_id, subject, issuer, serial_number,
            not_before, not_after,
            private_key_encrypted, private_key_iv, private_key_tag,
            certificate_pem, chain_pem, csr_pem,
            auto_renew, renew_before_days,
            acme_account_encrypted, acme_account_iv, acme_account_tag
          ) VALUES (
            ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?, ?
          )`,
        )
        .run(
          record.secret_id,
          record.subject,
          record.issuer,
          record.serial_number,
          record.not_before,
          record.not_after,
          Buffer.from(record.private_key_encrypted),
          Buffer.from(record.private_key_iv),
          Buffer.from(record.private_key_tag),
          record.certificate_pem,
          record.chain_pem,
          record.csr_pem,
          record.auto_renew ? 1 : 0,
          record.renew_before_days,
          record.acme_account_encrypted ? Buffer.from(record.acme_account_encrypted) : null,
          record.acme_account_iv ? Buffer.from(record.acme_account_iv) : null,
          record.acme_account_tag ? Buffer.from(record.acme_account_tag) : null,
        );
    } catch (err) {
      throw VaultError.databaseError(
        `Failed to insert certificate: ${err instanceof Error ? err.message : "unknown"}`,
      );
    }
  }

  getCertificate(secretId: string): CertificateRow | undefined {
    const row = this.db.prepare("SELECT * FROM certificates WHERE secret_id = ?").get(secretId) as
      | Record<string, unknown>
      | undefined;
    return row ? this.rowToCertificate(row) : undefined;
  }

  updateCertificate(
    secretId: string,
    fields: Partial<
      Pick<
        CertificateRow,
        | "subject"
        | "issuer"
        | "serial_number"
        | "not_before"
        | "not_after"
        | "certificate_pem"
        | "chain_pem"
        | "csr_pem"
        | "auto_renew"
        | "renew_before_days"
        | "acme_account_encrypted"
        | "acme_account_iv"
        | "acme_account_tag"
      >
    >,
  ): void {
    const ALLOWED = new Set([
      "subject",
      "issuer",
      "serial_number",
      "not_before",
      "not_after",
      "certificate_pem",
      "chain_pem",
      "csr_pem",
      "auto_renew",
      "renew_before_days",
      "acme_account_encrypted",
      "acme_account_iv",
      "acme_account_tag",
    ]);

    const setClauses: string[] = [];
    const params: unknown[] = [];

    for (const [key, value] of Object.entries(fields)) {
      if (!ALLOWED.has(key)) {
        throw VaultError.internalError(`Invalid column name for certificate update: ${key}`);
      }
      setClauses.push(`${key} = ?`);
      if (value instanceof Uint8Array) {
        params.push(Buffer.from(value));
      } else if (key === "auto_renew") {
        params.push(value ? 1 : 0);
      } else {
        params.push(value);
      }
    }

    if (setClauses.length === 0) return;

    params.push(secretId);
    this.db
      .prepare(`UPDATE certificates SET ${setClauses.join(", ")} WHERE secret_id = ?`)
      .run(...params);
  }

  getExpiringCertificates(withinDays: number): CertificateRow[] {
    const threshold = Date.now() + withinDays * 24 * 60 * 60 * 1000;
    const rows = this.db
      .prepare(
        `SELECT c.* FROM certificates c
         JOIN secrets s ON s.id = c.secret_id
         WHERE c.not_after IS NOT NULL
           AND c.not_after <= ?
           AND s.status = 'active'
         ORDER BY c.not_after ASC`,
      )
      .all(threshold) as Record<string, unknown>[];
    return rows.map((row) => this.rowToCertificate(row));
  }

  // ---------------------------------------------------------------------------
  // injection_policies
  // ---------------------------------------------------------------------------

  upsertInjectionPolicy(record: InjectionPolicyRow): void {
    try {
      this.db
        .prepare(
          `INSERT INTO injection_policies (
            secret_id, policy_encrypted, policy_iv, policy_tag, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(secret_id) DO UPDATE SET
            policy_encrypted = excluded.policy_encrypted,
            policy_iv = excluded.policy_iv,
            policy_tag = excluded.policy_tag,
            updated_at = excluded.updated_at`,
        )
        .run(
          record.secret_id,
          Buffer.from(record.policy_encrypted),
          Buffer.from(record.policy_iv),
          Buffer.from(record.policy_tag),
          record.created_at,
          record.updated_at,
        );
    } catch (err) {
      throw VaultError.databaseError(
        `Failed to upsert injection policy: ${err instanceof Error ? err.message : "unknown"}`,
      );
    }
  }

  getInjectionPolicy(secretId: string): InjectionPolicyRow | undefined {
    const row = this.db
      .prepare("SELECT * FROM injection_policies WHERE secret_id = ?")
      .get(secretId) as Record<string, unknown> | undefined;
    return row ? this.rowToInjectionPolicy(row) : undefined;
  }

  deleteInjectionPolicy(secretId: string): boolean {
    const result = this.db
      .prepare("DELETE FROM injection_policies WHERE secret_id = ?")
      .run(secretId);
    return result.changes > 0;
  }

  // ---------------------------------------------------------------------------
  // mcp_servers
  // ---------------------------------------------------------------------------

  upsertMcpServer(record: McpServerRow): void {
    try {
      this.db
        .prepare(
          `INSERT INTO mcp_servers (
            secret_id, config_encrypted, config_iv, config_tag, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(secret_id) DO UPDATE SET
            config_encrypted = excluded.config_encrypted,
            config_iv = excluded.config_iv,
            config_tag = excluded.config_tag,
            updated_at = excluded.updated_at`,
        )
        .run(
          record.secret_id,
          Buffer.from(record.config_encrypted),
          Buffer.from(record.config_iv),
          Buffer.from(record.config_tag),
          record.created_at,
          record.updated_at,
        );
    } catch (err) {
      throw VaultError.databaseError(
        `Failed to upsert MCP server config: ${err instanceof Error ? err.message : "unknown"}`,
      );
    }
  }

  getMcpServer(secretId: string): McpServerRow | undefined {
    const row = this.db.prepare("SELECT * FROM mcp_servers WHERE secret_id = ?").get(secretId) as
      | Record<string, unknown>
      | undefined;
    return row ? this.rowToMcpServer(row) : undefined;
  }

  deleteMcpServer(secretId: string): boolean {
    const result = this.db.prepare("DELETE FROM mcp_servers WHERE secret_id = ?").run(secretId);
    return result.changes > 0;
  }

  // ---------------------------------------------------------------------------
  // connection_configs
  // ---------------------------------------------------------------------------

  upsertConnectionConfig(record: ConnectionConfigRow): void {
    try {
      this.db
        .prepare(
          `INSERT INTO connection_configs (
            secret_id, config_encrypted, config_iv, config_tag, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(secret_id) DO UPDATE SET
            config_encrypted = excluded.config_encrypted,
            config_iv = excluded.config_iv,
            config_tag = excluded.config_tag,
            updated_at = excluded.updated_at`,
        )
        .run(
          record.secret_id,
          Buffer.from(record.config_encrypted),
          Buffer.from(record.config_iv),
          Buffer.from(record.config_tag),
          record.created_at,
          record.updated_at,
        );
    } catch (err) {
      throw VaultError.databaseError(
        `Failed to upsert connection config: ${err instanceof Error ? err.message : "unknown"}`,
      );
    }
  }

  getConnectionConfig(secretId: string): ConnectionConfigRow | undefined {
    const row = this.db
      .prepare("SELECT * FROM connection_configs WHERE secret_id = ?")
      .get(secretId) as Record<string, unknown> | undefined;
    return row ? this.rowToConnectionConfig(row) : undefined;
  }

  deleteConnectionConfig(secretId: string): boolean {
    const result = this.db
      .prepare("DELETE FROM connection_configs WHERE secret_id = ?")
      .run(secretId);
    return result.changes > 0;
  }

  // ---------------------------------------------------------------------------
  // Transaction helper
  // ---------------------------------------------------------------------------

  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }

  // ---------------------------------------------------------------------------
  // Close
  // ---------------------------------------------------------------------------

  close(): void {
    this.db.close();
  }

  // ---------------------------------------------------------------------------
  // Row mappers
  // ---------------------------------------------------------------------------

  private rowToSecret(row: Record<string, unknown>): Secret {
    return {
      id: row.id as string,
      name_encrypted: new Uint8Array(row.name_encrypted as Buffer),
      name_iv: new Uint8Array(row.name_iv as Buffer),
      name_tag: new Uint8Array(row.name_tag as Buffer),
      type: row.type as SecretType,
      project: (row.project as string) ?? null,
      wrapped_dek: new Uint8Array(row.wrapped_dek as Buffer),
      dek_iv: new Uint8Array(row.dek_iv as Buffer),
      dek_tag: new Uint8Array(row.dek_tag as Buffer),
      ciphertext: new Uint8Array(row.ciphertext as Buffer),
      ct_iv: new Uint8Array(row.ct_iv as Buffer),
      ct_tag: new Uint8Array(row.ct_tag as Buffer),
      metadata_encrypted: row.metadata_encrypted
        ? new Uint8Array(row.metadata_encrypted as Buffer)
        : null,
      metadata_iv: row.metadata_iv ? new Uint8Array(row.metadata_iv as Buffer) : null,
      metadata_tag: row.metadata_tag ? new Uint8Array(row.metadata_tag as Buffer) : null,
      created_at: row.created_at as number,
      updated_at: row.updated_at as number,
      expires_at: (row.expires_at as number) ?? null,
      rotated_at: (row.rotated_at as number) ?? null,
      version: row.version as number,
      status: row.status as SecretStatus,
      sync_version: row.sync_version as number,
      name_hmac: (row.name_hmac as string) ?? null,
    };
  }

  private rowToPolicy(row: Record<string, unknown>): AccessPolicy {
    return {
      id: row.id as string,
      secret_id: row.secret_id as string,
      principal_type: row.principal_type as PrincipalType,
      principal_id: row.principal_id as string,
      permissions: JSON.parse(row.permissions as string) as AccessPolicy["permissions"],
      created_at: row.created_at as number,
      expires_at: (row.expires_at as number) ?? null,
      created_by: row.created_by as string,
    };
  }

  private rowToAuditEvent(row: Record<string, unknown>): AuditEvent {
    return {
      id: row.id as number,
      timestamp: row.timestamp as number,
      event_type: row.event_type as AuditEventType,
      secret_id: (row.secret_id as string) ?? null,
      principal_type: (row.principal_type as PrincipalType) ?? null,
      principal_id: (row.principal_id as string) ?? null,
      detail_encrypted: row.detail_encrypted
        ? new Uint8Array(row.detail_encrypted as Buffer)
        : null,
      detail_iv: row.detail_iv ? new Uint8Array(row.detail_iv as Buffer) : null,
      detail_tag: row.detail_tag ? new Uint8Array(row.detail_tag as Buffer) : null,
      ip_address: (row.ip_address as string) ?? null,
      session_id: (row.session_id as string) ?? null,
      success: row.success === 1,
    };
  }

  private rowToOAuthToken(row: Record<string, unknown>): OAuthTokenRow {
    return {
      secret_id: row.secret_id as string,
      provider: row.provider as string,
      grant_type: row.grant_type as string,
      token_endpoint: row.token_endpoint as string,
      auth_endpoint: (row.auth_endpoint as string) ?? null,
      client_id_encrypted: new Uint8Array(row.client_id_encrypted as Buffer),
      client_id_iv: new Uint8Array(row.client_id_iv as Buffer),
      client_id_tag: new Uint8Array(row.client_id_tag as Buffer),
      client_secret_encrypted: row.client_secret_encrypted
        ? new Uint8Array(row.client_secret_encrypted as Buffer)
        : null,
      client_secret_iv: row.client_secret_iv
        ? new Uint8Array(row.client_secret_iv as Buffer)
        : null,
      client_secret_tag: row.client_secret_tag
        ? new Uint8Array(row.client_secret_tag as Buffer)
        : null,
      scopes: (row.scopes as string) ?? null,
      refresh_token_encrypted: row.refresh_token_encrypted
        ? new Uint8Array(row.refresh_token_encrypted as Buffer)
        : null,
      refresh_token_iv: row.refresh_token_iv
        ? new Uint8Array(row.refresh_token_iv as Buffer)
        : null,
      refresh_token_tag: row.refresh_token_tag
        ? new Uint8Array(row.refresh_token_tag as Buffer)
        : null,
      access_token_encrypted: row.access_token_encrypted
        ? new Uint8Array(row.access_token_encrypted as Buffer)
        : null,
      access_token_iv: row.access_token_iv ? new Uint8Array(row.access_token_iv as Buffer) : null,
      access_token_tag: row.access_token_tag
        ? new Uint8Array(row.access_token_tag as Buffer)
        : null,
      access_token_expires_at: (row.access_token_expires_at as number) ?? null,
      redirect_uri: (row.redirect_uri as string) ?? null,
      pkce_method: (row.pkce_method as string) ?? "S256",
      token_endpoint_auth_method: (row.token_endpoint_auth_method as string) ?? null,
    };
  }

  private rowToCertificate(row: Record<string, unknown>): CertificateRow {
    return {
      secret_id: row.secret_id as string,
      subject: row.subject as string,
      issuer: (row.issuer as string) ?? null,
      serial_number: (row.serial_number as string) ?? null,
      not_before: (row.not_before as number) ?? null,
      not_after: (row.not_after as number) ?? null,
      private_key_encrypted: new Uint8Array(row.private_key_encrypted as Buffer),
      private_key_iv: new Uint8Array(row.private_key_iv as Buffer),
      private_key_tag: new Uint8Array(row.private_key_tag as Buffer),
      certificate_pem: (row.certificate_pem as string) ?? null,
      chain_pem: (row.chain_pem as string) ?? null,
      csr_pem: (row.csr_pem as string) ?? null,
      auto_renew: row.auto_renew === 1,
      renew_before_days: (row.renew_before_days as number) ?? 30,
      acme_account_encrypted: row.acme_account_encrypted
        ? new Uint8Array(row.acme_account_encrypted as Buffer)
        : null,
      acme_account_iv: row.acme_account_iv ? new Uint8Array(row.acme_account_iv as Buffer) : null,
      acme_account_tag: row.acme_account_tag
        ? new Uint8Array(row.acme_account_tag as Buffer)
        : null,
    };
  }

  private rowToInjectionPolicy(row: Record<string, unknown>): InjectionPolicyRow {
    return {
      secret_id: row.secret_id as string,
      policy_encrypted: new Uint8Array(row.policy_encrypted as Buffer),
      policy_iv: new Uint8Array(row.policy_iv as Buffer),
      policy_tag: new Uint8Array(row.policy_tag as Buffer),
      created_at: row.created_at as number,
      updated_at: row.updated_at as number,
    };
  }

  private rowToMcpServer(row: Record<string, unknown>): McpServerRow {
    return {
      secret_id: row.secret_id as string,
      config_encrypted: new Uint8Array(row.config_encrypted as Buffer),
      config_iv: new Uint8Array(row.config_iv as Buffer),
      config_tag: new Uint8Array(row.config_tag as Buffer),
      created_at: row.created_at as number,
      updated_at: row.updated_at as number,
    };
  }

  private rowToConnectionConfig(row: Record<string, unknown>): ConnectionConfigRow {
    return {
      secret_id: row.secret_id as string,
      config_encrypted: new Uint8Array(row.config_encrypted as Buffer),
      config_iv: new Uint8Array(row.config_iv as Buffer),
      config_tag: new Uint8Array(row.config_tag as Buffer),
      created_at: row.created_at as number,
      updated_at: row.updated_at as number,
    };
  }
}
