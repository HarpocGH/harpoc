/**
 * DDL constants for the vault database — the v1.5 baseline at schema 12.
 * The 1.0–1.4 line's migrations 001–012 were collapsed into this set on
 * 2026-08-30 (compromise audit R2); their history lives in the docs repo's
 * implementation-history.md. Every table is a SQLite STRICT table; every
 * timestamp is milliseconds.
 */

/**
 * The schema version the baseline creates and the highest this binary knows.
 * A vault stamped above it is refused; one stamped below it (1–11, the retired
 * migration ladder) cannot be upgraded and is refused too — see runMigrations.
 */
export const LATEST_SCHEMA_VERSION = 12;

export const CREATE_VAULT_META = `
CREATE TABLE IF NOT EXISTS vault_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;
`;

/** `name_hmac` is populated on every insert (see CREATE_NAME_HMAC_UNIQUE_INDEX). */
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
  name_hmac          TEXT NOT NULL
) STRICT;
`;

export const CREATE_SECRETS_INDEXES = `
CREATE INDEX IF NOT EXISTS idx_secrets_project ON secrets (project);
CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets (type);
CREATE INDEX IF NOT EXISTS idx_secrets_status ON secrets (status);
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at);
`;

/** Serves the all-status lookup (`getSecretsByNameHmac`); the partial unique index below covers live rows only. */
export const CREATE_NAME_HMAC_INDEX = `
CREATE INDEX IF NOT EXISTS idx_secrets_name_hmac ON secrets (name_hmac);
`;

/**
 * Enforce name uniqueness among live (non-revoked) secrets at the storage
 * layer, closing the create-time check-then-insert TOCTOU. Partial index:
 * revoked rows are excluded (recreating a revoked name stays legal).
 */
export const CREATE_NAME_HMAC_UNIQUE_INDEX = `
CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_name_hmac_live
  ON secrets (name_hmac) WHERE status != 'revoked';
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

/**
 * `row_hmac` is the tamper-evidence chain link over the row (audit-chain.ts);
 * NOT NULL, so an erased link is refused by the table itself — the verifier's
 * own NULL check stays for the adversary who rebuilds the table.
 */
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
  success          INTEGER NOT NULL DEFAULT 1,
  row_hmac         BLOB NOT NULL
) STRICT;
`;

/** The principal index serves last-active and the audit attribution filter. */
export const CREATE_AUDIT_LOG_INDEXES = `
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_secret_id ON audit_log (secret_id);
CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit_log (principal_type, principal_id, timestamp);
`;

/** `expires_at` is milliseconds like every other timestamp (R2/C36). */
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

/**
 * Client authentication at the token endpoint is plain provider metadata like
 * token_endpoint/pkce_method — nothing secret. Every row carries one of the two
 * methods; the engine writes client_secret_post when a provider config omits it.
 */
export const CREATE_OAUTH_TOKENS = `
CREATE TABLE IF NOT EXISTS oauth_tokens (
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
  token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_post'
    CHECK (token_endpoint_auth_method IN ('client_secret_post', 'client_secret_basic'))
) STRICT;
`;

export const CREATE_CERTIFICATES = `
CREATE TABLE IF NOT EXISTS certificates (
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

export const CREATE_INJECTION_POLICIES = `
CREATE TABLE IF NOT EXISTS injection_policies (
  secret_id         TEXT PRIMARY KEY REFERENCES secrets(id) ON DELETE CASCADE,
  policy_encrypted  BLOB NOT NULL,
  policy_iv         BLOB NOT NULL,
  policy_tag        BLOB NOT NULL,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
) STRICT;
`;

export const CREATE_MCP_SERVERS = `
CREATE TABLE IF NOT EXISTS mcp_servers (
  secret_id         TEXT PRIMARY KEY REFERENCES secrets(id) ON DELETE CASCADE,
  config_encrypted  BLOB NOT NULL,
  config_iv         BLOB NOT NULL,
  config_tag        BLOB NOT NULL,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
) STRICT;
`;

export const CREATE_CONNECTION_CONFIGS = `
CREATE TABLE IF NOT EXISTS connection_configs (
  secret_id         TEXT PRIMARY KEY REFERENCES secrets(id) ON DELETE CASCADE,
  config_encrypted  BLOB NOT NULL,
  config_iv         BLOB NOT NULL,
  config_tag        BLOB NOT NULL,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
) STRICT;
`;

/**
 * The agent registry. Plaintext columns like access_policies and
 * revoked_tokens: rows are looked up by name and filtered by status, never
 * read whole by secret id. `name` is the `principal_id` every agent-typed
 * policy and token carries, and is immutable once registered.
 */
export const CREATE_AGENTS = `
CREATE TABLE IF NOT EXISTS agents (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,
  description    TEXT,
  owner          TEXT,
  status         TEXT NOT NULL CHECK (status IN ('active', 'inactive')),
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  deactivated_at INTEGER
) STRICT;
`;

/**
 * Claims metadata of issued tokens — never the JWT itself. `scope` and
 * `secrets` hold JSON arrays; a NULL `secrets` means unrestricted. `revoked_at`
 * is a history mirror written beside the revoked_tokens insert — revoked_tokens
 * stays the sole revocation truth verifyToken reads.
 */
export const CREATE_ISSUED_TOKENS = `
CREATE TABLE IF NOT EXISTS issued_tokens (
  jti            TEXT PRIMARY KEY,
  subject        TEXT NOT NULL,
  principal_type TEXT NOT NULL CHECK (principal_type IN ('agent', 'tool', 'user')),
  agent_id       TEXT REFERENCES agents(id) ON DELETE SET NULL,
  scope          TEXT NOT NULL,
  project        TEXT,
  secrets        TEXT,
  label          TEXT,
  issued_at      INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  revoked_at     INTEGER
) STRICT;
`;

export const CREATE_ISSUED_TOKENS_INDEXES = `
CREATE INDEX IF NOT EXISTS idx_issued_tokens_agent ON issued_tokens (agent_id);
CREATE INDEX IF NOT EXISTS idx_issued_tokens_expires ON issued_tokens (expires_at);
`;
