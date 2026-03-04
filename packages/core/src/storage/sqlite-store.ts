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
    this.runMigrations();
  }

  private setPragmas(): void {
    for (const [key, value] of Object.entries(SQLITE_PRAGMAS)) {
      this.db.pragma(`${key} = ${value}`);
    }
  }

  private runMigrations(): void {
    const currentVersion = this.getMigrationVersion();
    if (currentVersion < 1) {
      this.db.exec(migration001.up);
      this.setMeta("schema_version", "1");
    }
    if (currentVersion < 2) {
      this.db.exec(migration002.up);
      this.setMeta("schema_version", "2");
    }
    if (currentVersion < 3) {
      this.db.exec(migration003.up);
      this.setMeta("schema_version", "3");
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
    this.db
      .prepare("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)")
      .run(key, value);
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
    this.db
      .prepare(`UPDATE secrets SET ${setClauses.join(", ")} WHERE id = ?`)
      .run(...params);
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

  listPoliciesByPrincipal(
    principalType: PrincipalType,
    principalId: string,
  ): AccessPolicy[] {
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

  insertAuditEvent(event: Omit<AuditEvent, "id">): number {
    const result = this.db
      .prepare(
        `INSERT INTO audit_log (
          timestamp, event_type, secret_id,
          principal_type, principal_id,
          detail_encrypted, detail_iv, detail_tag,
          ip_address, session_id, success
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
      );
    return Number(result.lastInsertRowid);
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
    const row = this.db
      .prepare("SELECT jti FROM revoked_tokens WHERE jti = ?")
      .get(jti) as { jti: string } | undefined;
    return row !== undefined;
  }

  pruneExpiredTokens(): number {
    const result = this.db
      .prepare("DELETE FROM revoked_tokens WHERE expires_at < ?")
      .run(Math.floor(Date.now() / 1000));
    return result.changes;
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
}
