import { chmodSync, closeSync, existsSync, openSync } from "node:fs";
import Database from "better-sqlite3";
import type {
  AccessPolicy,
  AgentStatus,
  AuditEvent,
  AuditEventType,
  Permission,
  PrincipalType,
  Secret,
  SecretStatus,
  SecretType,
  TokenPrincipalType,
} from "@harpoc/shared";
import { SQLITE_PRAGMAS, VaultError } from "@harpoc/shared";
import { baselineSchema } from "./migrations/baseline.js";
import { LATEST_SCHEMA_VERSION } from "./schema.js";

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
  success?: boolean;
  principalType?: PrincipalType;
  principalId?: string;
  /**
   * The secret ids a scoped caller may see (L10). Applied inside the query,
   * ahead of `limit`, so a scoped read gets up to `limit` rows it may see
   * instead of the visible remainder of the newest `limit` rows. Rows without
   * a `secret_id` carry no per-secret metadata and stay visible.
   */
  visibleSecretIds?: string[];
}

/**
 * SQLite's compiled-in host-parameter ceiling (SQLITE_MAX_VARIABLE_NUMBER) is
 * 32766 in the versions better-sqlite3 ships; a visibility list longer than
 * what fits alongside the other predicates is filtered in JS instead.
 */
const MAX_SQL_VARIABLES = 32_000;

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
  token_endpoint_auth_method: string;
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

/**
 * A registered agent as stored (v1.4 agent registry). Plaintext columns; the
 * derived fields of the shared `Agent` wire type (last_active_at, active_tokens,
 * grants) are computed by the engine from the counting queries below.
 * Timestamps are milliseconds.
 */
export interface AgentRow {
  id: string;
  name: string;
  description: string | null;
  owner: string | null;
  status: AgentStatus;
  created_at: number;
  updated_at: number;
  deactivated_at: number | null;
}

/**
 * Claims metadata of an issued token as stored (v1.4 issued-token registry) —
 * never the JWT. `scope`/`secrets` are JSON-encoded on the way in; a null
 * `secrets` means unrestricted. Every timestamp is milliseconds.
 * `revoked_at` is a history mirror; revoked_tokens remains the revocation truth.
 */
export interface IssuedTokenRow {
  jti: string;
  subject: string;
  principal_type: TokenPrincipalType;
  agent_id: string | null;
  scope: Permission[];
  project: string | null;
  secrets: string[] | null;
  label: string | null;
  issued_at: number;
  expires_at: number;
  revoked_at: number | null;
}

/** Filters for listing issued tokens. */
export interface IssuedTokenFilter {
  agentId?: string;
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
    "name_hmac",
  ]);

  readonly db: Database.Database;

  constructor(path: string) {
    try {
      if (!path.startsWith(":") && !existsSync(path)) {
        closeSync(openSync(path, "a", 0o600));
      }
      this.db = new Database(path);
    } catch (err) {
      throw VaultError.databaseError(
        `Failed to open database: ${err instanceof Error ? err.message : "unknown"}`,
      );
    }

    restrictDatabasePermissions(path);
    this.setPragmas();
    try {
      this.runMigrations();
    } catch (err) {
      // A refused open must not leak the handle, which would lock the file on Windows.
      this.db.close();
      throw err;
    }
  }

  private setPragmas(): void {
    for (const [key, value] of Object.entries(SQLITE_PRAGMAS)) {
      this.db.pragma(`${key} = ${value}`);
    }
  }

  /**
   * Bring the store to LATEST_SCHEMA_VERSION. An empty store gets the v1.5
   * baseline in one transaction; a store from the retired 1.0–1.4 migration
   * ladder (schema 1–11) cannot be upgraded and is refused before any DDL.
   * Migrations past the baseline chain below the baseline block as
   * `if (currentVersion < N) { transaction { exec; setMeta } }` steps, one per
   * version, exactly the shape the ladder had — a one-time reset, not a
   * no-migrations policy.
   */
  private runMigrations(): void {
    const currentVersion = this.getMigrationVersion();
    if (currentVersion === 0) {
      this.db.transaction(() => {
        this.db.exec(baselineSchema.up);
        this.setMeta("schema_version", String(baselineSchema.version));
      })();
      return;
    }
    if (currentVersion < baselineSchema.version) {
      throw VaultError.vaultCorrupted(
        `Vault schema ${currentVersion} predates the v1.5 baseline (${baselineSchema.version}) and cannot be upgraded — move or delete the vault directory and run harpoc init`,
      );
    }
  }

  private getMigrationVersion(): number {
    const row = this.db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='vault_meta'")
      .get() as { name: string } | undefined;
    if (!row) return 0;

    const version = this.getMeta("schema_version");
    if (version === undefined) {
      throw VaultError.vaultCorrupted("Missing schema_version");
    }
    if (!/^\d+$/.test(version)) {
      throw VaultError.vaultCorrupted(`Malformed schema_version "${version}"`);
    }
    const parsed = Number(version);
    if (parsed > LATEST_SCHEMA_VERSION) {
      throw VaultError.vaultCorrupted(
        `Vault schema ${parsed} is newer than supported ${LATEST_SCHEMA_VERSION}`,
      );
    }
    return parsed;
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
            version, status, name_hmac
          ) VALUES (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?
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

  /** Remove every policy of one principal, returning the rows that were removed. */
  deletePoliciesForPrincipal(principalType: PrincipalType, principalId: string): AccessPolicy[] {
    const removed = this.listPoliciesByPrincipal(principalType, principalId);
    if (removed.length === 0) return [];
    this.db
      .prepare("DELETE FROM access_policies WHERE principal_type = ? AND principal_id = ?")
      .run(principalType, principalId);
    return removed;
  }

  /** Remove one principal's policies on a single secret, returning the removed rows. */
  deletePoliciesForPrincipalOnSecret(
    secretId: string,
    principalType: PrincipalType,
    principalId: string,
  ): AccessPolicy[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM access_policies
         WHERE secret_id = ? AND principal_type = ? AND principal_id = ?
         ORDER BY created_at DESC`,
      )
      .all(secretId, principalType, principalId) as Record<string, unknown>[];
    if (rows.length === 0) return [];
    this.db
      .prepare(
        "DELETE FROM access_policies WHERE secret_id = ? AND principal_type = ? AND principal_id = ?",
      )
      .run(secretId, principalType, principalId);
    return rows.map((row) => this.rowToPolicy(row));
  }

  /** Count a principal's policies that have not expired at `now` (ms). */
  countActivePoliciesForPrincipal(
    principalType: PrincipalType,
    principalId: string,
    now: number,
  ): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS c FROM access_policies
         WHERE principal_type = ? AND principal_id = ?
           AND (expires_at IS NULL OR expires_at > ?)`,
      )
      .get(principalType, principalId, now) as { c: number };
    return row.c;
  }

  // ---------------------------------------------------------------------------
  // audit_log
  // ---------------------------------------------------------------------------

  insertAuditEvent(event: Omit<AuditEvent, "id">, rowHmac: Uint8Array): number {
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
        Buffer.from(rowHmac),
      );
    return Number(result.lastInsertRowid);
  }

  /**
   * The most recent audit row's id, timestamp and link. Insert-time chaining
   * reads the very last row whatever its link (a NULL tail chains the next
   * row from genesis, and verification reports the erased link); the anchor
   * export refuses a tail without one.
   */
  getLastAuditRow(): { id: number; timestamp: number; row_hmac: Uint8Array | null } | null {
    const row = this.db
      .prepare("SELECT id, timestamp, row_hmac FROM audit_log ORDER BY id DESC LIMIT 1")
      .get() as { id: number; timestamp: number; row_hmac: Buffer | null } | undefined;
    if (!row) return null;
    return {
      id: row.id,
      timestamp: row.timestamp,
      row_hmac: row.row_hmac ? new Uint8Array(row.row_hmac) : null,
    };
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
    if (filter?.principalType) {
      sql += " AND principal_type = ?";
      params.push(filter.principalType);
    }
    if (filter?.principalId) {
      sql += " AND principal_id = ?";
      params.push(filter.principalId);
    }
    if (filter?.since) {
      sql += " AND timestamp >= ?";
      params.push(filter.since);
    }
    if (filter?.until) {
      sql += " AND timestamp <= ?";
      params.push(filter.until);
    }
    if (filter?.success !== undefined) {
      sql += " AND success = ?";
      params.push(filter.success ? 1 : 0);
    }

    const ids = filter?.visibleSecretIds;
    const inlineVisibility = ids !== undefined && params.length + ids.length <= MAX_SQL_VARIABLES;
    if (ids !== undefined && inlineVisibility) {
      // An empty visibility list is a scope that matches no secret: only the
      // secret-less rows remain (`IN ()` is not valid SQLite).
      sql +=
        ids.length === 0
          ? " AND secret_id IS NULL"
          : ` AND (secret_id IS NULL OR secret_id IN (${ids.map(() => "?").join(",")}))`;
      params.push(...ids);
    }

    sql += " ORDER BY timestamp DESC";

    if (filter?.limit && (ids === undefined || inlineVisibility)) {
      sql += " LIMIT ?";
      params.push(filter.limit);
    }

    const rows = this.db.prepare(sql).all(...params) as Record<string, unknown>[];
    let events = rows.map((row) => this.rowToAuditEvent(row));
    if (ids !== undefined && !inlineVisibility) {
      const visible = new Set(ids);
      events = events.filter((event) => event.secret_id === null || visible.has(event.secret_id));
      if (filter?.limit) events = events.slice(0, filter.limit);
    }
    return events;
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
      .run(Date.now());
    return result.changes;
  }

  // ---------------------------------------------------------------------------
  // agents
  // ---------------------------------------------------------------------------

  /** Insert an agent; a duplicate name surfaces as a UNIQUE constraint error. */
  insertAgent(row: AgentRow): void {
    this.db
      .prepare(
        `INSERT INTO agents (
          id, name, description, owner, status, created_at, updated_at, deactivated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.id,
        row.name,
        row.description,
        row.owner,
        row.status,
        row.created_at,
        row.updated_at,
        row.deactivated_at,
      );
  }

  getAgentByName(name: string): AgentRow | undefined {
    const row = this.db.prepare("SELECT * FROM agents WHERE name = ?").get(name) as
      | Record<string, unknown>
      | undefined;
    return row ? this.rowToAgent(row) : undefined;
  }

  getAgentById(id: string): AgentRow | undefined {
    const row = this.db.prepare("SELECT * FROM agents WHERE id = ?").get(id) as
      | Record<string, unknown>
      | undefined;
    return row ? this.rowToAgent(row) : undefined;
  }

  listAgents(status: AgentStatus | "all"): AgentRow[] {
    const rows =
      status === "all"
        ? (this.db.prepare("SELECT * FROM agents ORDER BY name ASC").all() as Record<
            string,
            unknown
          >[])
        : (this.db
            .prepare("SELECT * FROM agents WHERE status = ? ORDER BY name ASC")
            .all(status) as Record<string, unknown>[]);
    return rows.map((row) => this.rowToAgent(row));
  }

  /** Replace the two metadata fields; name and status are untouched here. */
  updateAgentMetadata(
    id: string,
    description: string | null,
    owner: string | null,
    updatedAt: number,
  ): void {
    this.db
      .prepare("UPDATE agents SET description = ?, owner = ?, updated_at = ? WHERE id = ?")
      .run(description, owner, updatedAt, id);
  }

  /** Set status; deactivated_at records the moment of deactivation and clears on reactivation. */
  setAgentStatus(id: string, status: AgentStatus, at: number): void {
    this.db
      .prepare("UPDATE agents SET status = ?, updated_at = ?, deactivated_at = ? WHERE id = ?")
      .run(status, at, status === "inactive" ? at : null, id);
  }

  deleteAgent(id: string): boolean {
    const result = this.db.prepare("DELETE FROM agents WHERE id = ?").run(id);
    return result.changes > 0;
  }

  /** Most recent audit timestamp attributed to this agent, or null if it has none. */
  agentLastActiveAt(name: string): number | null {
    const row = this.db
      .prepare(
        "SELECT MAX(timestamp) AS last_active FROM audit_log WHERE principal_type = 'agent' AND principal_id = ?",
      )
      .get(name) as { last_active: number | null };
    return row.last_active ?? null;
  }

  // ---------------------------------------------------------------------------
  // issued_tokens
  // ---------------------------------------------------------------------------

  insertIssuedToken(row: IssuedTokenRow): void {
    this.db
      .prepare(
        `INSERT INTO issued_tokens (
          jti, subject, principal_type, agent_id, scope, project, secrets, label,
          issued_at, expires_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.jti,
        row.subject,
        row.principal_type,
        row.agent_id,
        JSON.stringify(row.scope),
        row.project,
        row.secrets === null ? null : JSON.stringify(row.secrets),
        row.label,
        row.issued_at,
        row.expires_at,
        row.revoked_at,
      );
  }

  /** Stamp the revocation mirror once — a later revocation never rewrites the first. */
  markIssuedTokenRevoked(jti: string, revokedAt: number): void {
    this.db
      .prepare("UPDATE issued_tokens SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL")
      .run(revokedAt, jti);
  }

  /** One issued-token row by jti, or null — the registry is authoritative for revocation (R9/C33-A). */
  getIssuedToken(jti: string): IssuedTokenRow | null {
    const row = this.db.prepare("SELECT * FROM issued_tokens WHERE jti = ?").get(jti) as
      | Record<string, unknown>
      | undefined;
    return row ? this.rowToIssuedToken(row) : null;
  }

  /** Newest first; agent_name is null for tool/user tokens and for deleted agents. */
  listIssuedTokens(
    filter?: IssuedTokenFilter,
  ): Array<IssuedTokenRow & { agent_name: string | null }> {
    let sql = `SELECT t.*, a.name AS agent_name
       FROM issued_tokens t
       LEFT JOIN agents a ON a.id = t.agent_id
       WHERE 1=1`;
    const params: unknown[] = [];

    if (filter?.agentId) {
      sql += " AND t.agent_id = ?";
      params.push(filter.agentId);
    }

    sql += " ORDER BY t.issued_at DESC";

    const rows = this.db.prepare(sql).all(...params) as Record<string, unknown>[];
    return rows.map((row) => ({
      ...this.rowToIssuedToken(row),
      agent_name: (row.agent_name as string) ?? null,
    }));
  }

  /** jti and expiry of this agent's tokens that are neither expired at `now` (ms) nor revoked. */
  listLiveTokensForAgent(
    agentId: string,
    now: number,
  ): Array<Pick<IssuedTokenRow, "jti" | "expires_at">> {
    return this.db
      .prepare(
        `SELECT jti, expires_at FROM issued_tokens
         WHERE agent_id = ? AND expires_at > ? AND revoked_at IS NULL
         ORDER BY issued_at DESC`,
      )
      .all(agentId, now) as Array<{ jti: string; expires_at: number }>;
  }

  countActiveTokensForAgent(agentId: string, now: number): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS c FROM issued_tokens
         WHERE agent_id = ? AND expires_at > ? AND revoked_at IS NULL`,
      )
      .get(agentId, now) as { c: number };
    return row.c;
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

  /** Remove a secret's OAuth provider row (resume replaces it wholesale). */
  deleteOAuthToken(secretId: string): boolean {
    const result = this.db.prepare("DELETE FROM oauth_tokens WHERE secret_id = ?").run(secretId);
    return result.changes > 0;
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
    ]);

    const setClauses: string[] = [];
    const params: unknown[] = [];

    for (const [key, value] of Object.entries(fields)) {
      if (!ALLOWED.has(key)) {
        throw VaultError.internalError(`Invalid column name for certificate update: ${key}`);
      }
      setClauses.push(`${key} = ?`);
      if (key === "auto_renew") {
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

  /**
   * Run `fn` in a write transaction.
   *
   * `BEGIN IMMEDIATE`, not the plain deferred `BEGIN`: every transaction here
   * writes, and several — AuditLogger.log (SELECT the last chain link, then
   * INSERT) and SecretManager.createSecret (duplicate SELECT, then INSERT) —
   * read first. A deferred BEGIN takes a WAL read snapshot on that first SELECT
   * and only then tries to upgrade to a write; if another connection committed
   * in between, SQLite answers SQLITE_BUSY_SNAPSHOT, which `busy_timeout`
   * deliberately does NOT retry. With multi-process access (a `server start`
   * daemon plus CLI commands — the documented deployment) that surfaced as a
   * spurious failure, and under the atomic-audit semantics it rolls the whole
   * operation back. Taking the write lock up front is what the read-then-write
   * pattern needs; nested calls still run as savepoints.
   */
  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn).immediate();
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
    const nameHmac = row.name_hmac;
    if (typeof nameHmac !== "string") {
      throw VaultError.vaultCorrupted(`secret ${String(row.id)} has no name_hmac`);
    }
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
      name_hmac: nameHmac,
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

  private rowToAgent(row: Record<string, unknown>): AgentRow {
    return {
      id: row.id as string,
      name: row.name as string,
      description: (row.description as string) ?? null,
      owner: (row.owner as string) ?? null,
      status: row.status as AgentStatus,
      created_at: row.created_at as number,
      updated_at: row.updated_at as number,
      deactivated_at: (row.deactivated_at as number) ?? null,
    };
  }

  private rowToIssuedToken(row: Record<string, unknown>): IssuedTokenRow {
    return {
      jti: row.jti as string,
      subject: row.subject as string,
      principal_type: row.principal_type as TokenPrincipalType,
      agent_id: (row.agent_id as string) ?? null,
      scope: JSON.parse(row.scope as string) as Permission[],
      project: (row.project as string) ?? null,
      secrets: row.secrets == null ? null : (JSON.parse(row.secrets as string) as string[]),
      label: (row.label as string) ?? null,
      issued_at: row.issued_at as number,
      expires_at: row.expires_at as number,
      revoked_at: (row.revoked_at as number) ?? null,
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
    const authMethod = row.token_endpoint_auth_method;
    if (typeof authMethod !== "string") {
      throw VaultError.vaultCorrupted(
        `oauth row ${String(row.secret_id)} has no token_endpoint_auth_method`,
      );
    }
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
      token_endpoint_auth_method: authMethod,
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

/**
 * Restrict the vault database (and its WAL sidecars) to the owner on POSIX.
 *
 * The database file is created `0o600` before SQLite opens it (SQLite's unix
 * VFS copies the main file's mode onto `-wal`/`-shm`); the chmod below repairs
 * an older file. Contents are KEK-encrypted, so this is hardening
 * consistency rather than a confidentiality fix: it keeps encrypted blobs,
 * timestamps and row counts off other local accounts. Best-effort by design —
 * a foreign-owned or read-only vault file must still open. No-op on Windows,
 * where ACL inheritance is the mechanism (see the session file's ACL step).
 */
function restrictDatabasePermissions(path: string): void {
  if (process.platform === "win32") return;
  for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
    try {
      if (existsSync(candidate)) chmodSync(candidate, 0o600);
    } catch {
      // Best-effort: the vault stays usable regardless of file mode.
    }
  }
}
