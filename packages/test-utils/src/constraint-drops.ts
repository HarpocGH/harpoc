/**
 * Table rebuilds a database-writing attacker would perform to shed a
 * constraint — SQLite has no `ALTER TABLE … DROP NOT NULL`, so the only way
 * to get a NULL into a NOT NULL column is to recreate the table without it.
 * Test-only: this is how the read-side defenses (the audit verifier's NULL
 * link branch, the OAuth row's auth-method check, the secret manager's NULL
 * name_hmac refusal) are reached on a v1.5 baseline that otherwise refuses the
 * write. All three take any handle with `exec` — better-sqlite3's Database and
 * `SqliteStore.db` alike.
 * Run them outside a transaction: PRAGMA foreign_keys is a no-op inside one,
 * and the secrets rebuild would then cascade-delete six child tables.
 */
export interface SqlExecHandle {
  exec(sql: string): void;
}

export function dropAuditRowHmacConstraint(db: SqlExecHandle): void {
  db.exec(`
    CREATE TABLE audit_log_unconstrained (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp        INTEGER NOT NULL,
      event_type       TEXT NOT NULL,
      secret_id        TEXT,
      principal_type   TEXT,
      principal_id     TEXT,
      detail_encrypted BLOB,
      detail_iv        BLOB,
      detail_tag       BLOB,
      ip_address       TEXT,
      session_id       TEXT,
      success          INTEGER NOT NULL DEFAULT 1,
      row_hmac         BLOB
    ) STRICT;
    INSERT INTO audit_log_unconstrained SELECT * FROM audit_log;
    DROP TABLE audit_log;
    ALTER TABLE audit_log_unconstrained RENAME TO audit_log;
    CREATE INDEX idx_audit_timestamp ON audit_log (timestamp);
    CREATE INDEX idx_audit_secret_id ON audit_log (secret_id);
    CREATE INDEX idx_audit_principal ON audit_log (principal_type, principal_id, timestamp);
  `);
}

export function dropOAuthAuthMethodConstraint(db: SqlExecHandle): void {
  db.exec(`
    CREATE TABLE oauth_tokens_unconstrained (
      secret_id                  TEXT PRIMARY KEY REFERENCES secrets(id) ON DELETE CASCADE,
      provider                   TEXT NOT NULL,
      grant_type                 TEXT NOT NULL,
      token_endpoint             TEXT NOT NULL,
      auth_endpoint              TEXT,
      client_id_encrypted        BLOB NOT NULL,
      client_id_iv               BLOB NOT NULL,
      client_id_tag              BLOB NOT NULL,
      client_secret_encrypted    BLOB,
      client_secret_iv           BLOB,
      client_secret_tag          BLOB,
      scopes                     TEXT,
      refresh_token_encrypted    BLOB,
      refresh_token_iv           BLOB,
      refresh_token_tag          BLOB,
      access_token_encrypted     BLOB,
      access_token_iv            BLOB,
      access_token_tag           BLOB,
      access_token_expires_at    INTEGER,
      redirect_uri               TEXT,
      pkce_method                TEXT DEFAULT 'S256',
      token_endpoint_auth_method TEXT
    ) STRICT;
    INSERT INTO oauth_tokens_unconstrained SELECT * FROM oauth_tokens;
    DROP TABLE oauth_tokens;
    ALTER TABLE oauth_tokens_unconstrained RENAME TO oauth_tokens;
  `);
}

/**
 * `secrets` is the parent of six ON DELETE CASCADE references, so the rebuild
 * runs with foreign keys off — otherwise dropping it would take every
 * dependent row with it — and turns them back on afterwards.
 */
export function dropSecretsNameHmacConstraint(db: SqlExecHandle): void {
  db.exec(`
    PRAGMA foreign_keys = OFF;
    CREATE TABLE secrets_unconstrained (
      id                 TEXT PRIMARY KEY,
      name_encrypted     BLOB NOT NULL,
      name_iv            BLOB NOT NULL,
      name_tag           BLOB NOT NULL,
      type               TEXT NOT NULL CHECK (type IN ('api_key', 'oauth_token', 'certificate')),
      project            TEXT,
      wrapped_dek        BLOB NOT NULL,
      dek_iv             BLOB NOT NULL,
      dek_tag            BLOB NOT NULL,
      ciphertext         BLOB NOT NULL,
      ct_iv              BLOB NOT NULL,
      ct_tag             BLOB NOT NULL,
      metadata_encrypted BLOB,
      metadata_iv        BLOB,
      metadata_tag       BLOB,
      created_at         INTEGER NOT NULL,
      updated_at         INTEGER NOT NULL,
      expires_at         INTEGER,
      rotated_at         INTEGER,
      version            INTEGER NOT NULL DEFAULT 1,
      status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending', 'expired', 'revoked')),
      name_hmac          TEXT
    ) STRICT;
    INSERT INTO secrets_unconstrained SELECT * FROM secrets;
    DROP TABLE secrets;
    ALTER TABLE secrets_unconstrained RENAME TO secrets;
    CREATE INDEX idx_secrets_project ON secrets (project);
    CREATE INDEX idx_secrets_type ON secrets (type);
    CREATE INDEX idx_secrets_status ON secrets (status);
    CREATE INDEX idx_secrets_expires_at ON secrets (expires_at);
    CREATE INDEX idx_secrets_name_hmac ON secrets (name_hmac);
    CREATE UNIQUE INDEX idx_secrets_name_hmac_live
      ON secrets (name_hmac) WHERE status != 'revoked';
    PRAGMA foreign_keys = ON;
  `);
}
