/** DDL constants for the v1.0 vault database schema. */

export const CREATE_VAULT_META = `
CREATE TABLE IF NOT EXISTS vault_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;
`;

export const CREATE_SECRETS = `
CREATE TABLE IF NOT EXISTS secrets (
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
  sync_version       INTEGER NOT NULL DEFAULT 0
) STRICT;
`;

export const CREATE_SECRETS_INDEXES = `
CREATE INDEX IF NOT EXISTS idx_secrets_project ON secrets (project);
CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets (type);
CREATE INDEX IF NOT EXISTS idx_secrets_status ON secrets (status);
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at);
`;

export const CREATE_ACCESS_POLICIES = `
CREATE TABLE IF NOT EXISTS access_policies (
  id              TEXT PRIMARY KEY,
  secret_id       TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  principal_type  TEXT NOT NULL CHECK (principal_type IN ('agent', 'tool', 'project', 'user')),
  principal_id    TEXT NOT NULL,
  permissions     TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER,
  created_by      TEXT NOT NULL
) STRICT;
`;

export const CREATE_ACCESS_POLICIES_INDEXES = `
CREATE INDEX IF NOT EXISTS idx_policies_secret_id ON access_policies (secret_id);
CREATE INDEX IF NOT EXISTS idx_policies_principal ON access_policies (principal_type, principal_id);
`;

export const CREATE_AUDIT_LOG = `
CREATE TABLE IF NOT EXISTS audit_log (
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
  success          INTEGER NOT NULL DEFAULT 1
) STRICT;
`;

export const CREATE_AUDIT_LOG_INDEXES = `
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_secret_id ON audit_log (secret_id);
`;

export const CREATE_REVOKED_TOKENS = `
CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti        TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER NOT NULL
) STRICT;
`;

export const CREATE_REVOKED_TOKENS_INDEXES = `
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens (expires_at);
`;

export const ALTER_SECRETS_ADD_NAME_HMAC = `
ALTER TABLE secrets ADD COLUMN name_hmac TEXT;
`;

export const CREATE_NAME_HMAC_INDEX = `
CREATE INDEX IF NOT EXISTS idx_secrets_name_hmac ON secrets (name_hmac);
`;

export const CREATE_OAUTH_TOKENS = `
CREATE TABLE oauth_tokens (
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
  pkce_method                TEXT DEFAULT 'S256'
) STRICT;
`;

export const CREATE_CERTIFICATES = `
CREATE TABLE certificates (
  secret_id                TEXT PRIMARY KEY REFERENCES secrets(id) ON DELETE CASCADE,
  subject                  TEXT NOT NULL,
  issuer                   TEXT,
  serial_number            TEXT,
  not_before               INTEGER,
  not_after                INTEGER,
  private_key_encrypted    BLOB NOT NULL,
  private_key_iv           BLOB NOT NULL,
  private_key_tag          BLOB NOT NULL,
  certificate_pem          TEXT,
  chain_pem                TEXT,
  csr_pem                  TEXT,
  auto_renew               INTEGER NOT NULL DEFAULT 0,
  renew_before_days        INTEGER DEFAULT 30,
  acme_account_encrypted   BLOB,
  acme_account_iv          BLOB,
  acme_account_tag         BLOB
) STRICT;
`;

export const CREATE_CERTIFICATES_INDEXES = `
CREATE INDEX IF NOT EXISTS idx_certs_expiry ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_certs_subject ON certificates(subject);
`;
