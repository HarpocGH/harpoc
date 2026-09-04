// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

// -- Paths (relative names only — runtime resolution belongs in core/) -------

export const VAULT_DIR_NAME = ".harpoc";
export const VAULT_DB_NAME = "default.vault.db";
export const SESSION_FILE_NAME = "session.json";
export const CONFIG_FILE_NAME = "config.json";
export const AUDIT_DIR_NAME = "audit";

// -- Crypto: Argon2id --------------------------------------------------------

// RFC 9106 first recommended (high-security) profile: 2 GiB, t=1, p=4.
// The only adversary who ever faces the KDF is the offline at-rest attacker,
// and memory per guess is the entire margin; the latency cost is paid once
// per session under the 24 h ceiling.
export const ARGON2_MEMORY_COST = 2_097_152; // 2 GiB in KiB
export const ARGON2_TIME_COST = 1;
export const ARGON2_PARALLELISM = 4;
export const ARGON2_HASH_LENGTH = 32; // 256 bits
export const ARGON2_VERSION = 0x13; // v1.3
export const ARGON2_SALT_LENGTH = 16; // 128 bits

// -- Crypto: AES-256-GCM ----------------------------------------------------

export const AES_KEY_LENGTH = 32; // 256 bits
export const AES_IV_LENGTH = 12; // 96 bits
export const AES_TAG_LENGTH = 16; // 128 bits

// -- AAD (Additional Authenticated Data) strings -----------------------------

export const AAD_VAULT_KEK = "vault-kek";
export const AAD_SESSION_KEK = "session-kek";
export const AAD_SESSION_JWT = "session-jwt";
export const AAD_SESSION_AUDIT = "session-audit";

/**
 * Row-bound AAD for audit detail (v2): binds the ciphertext to the row's
 * identity so a detail blob moved to another row fails authentication. All
 * inputs are known before the row is written.
 */
export function AAD_AUDIT_DETAIL_V2(
  eventType: string,
  timestamp: number,
  secretId: string | null,
): string {
  return `harpoc:audit-detail:v2|${eventType}|${timestamp}|${secretId ?? "-"}`;
}

/** Domain-separation label deriving the audit chain HMAC key from the audit key. */
export const AUDIT_CHAIN_KEY_LABEL = "harpoc:audit-chain-key";

/** Fixed genesis value seeding the first row's HMAC chain link. */
export const AUDIT_CHAIN_GENESIS = "harpoc:audit-chain:genesis:v1";

export function AAD_DEK_WRAP(secretId: string): string {
  return `dek-wrap:${secretId}`;
}

export function AAD_SECRET_PAYLOAD(secretId: string, version: number): string {
  return `secret-payload:${secretId}:${version}`;
}

export function AAD_NAME_ENCRYPTION(secretId: string): string {
  return `name-enc:${secretId}`;
}

export function AAD_METADATA(secretId: string): string {
  return `metadata:${secretId}`;
}

// -- Session -----------------------------------------------------------------

export const DEFAULT_SESSION_TTL_MS = 15 * 60 * 1_000; // 15 minutes
export const MAX_SESSION_TTL_MS = 24 * 60 * 60 * 1_000; // 24 hours
export const SESSION_SLIDE_INTERVAL_MS = 30 * 1_000; // 30 seconds
export const SESSION_CLEANUP_INTERVAL_MS = 30 * 1_000; // 30 seconds
export const SESSION_LOCK_STALE_MS = 10 * 1_000; // 10 seconds — a lock older than this was left by a dead process
export const SESSION_LOCK_POLL_MS = 25;

// -- Rate limits -------------------------------------------------------------

export const RATE_LIMIT_GLOBAL = 1_000; // per minute
export const RATE_LIMIT_PER_SECRET = 60; // per minute
export const RATE_LIMIT_AUTH_ATTEMPTS = 10;
export const RATE_LIMIT_AUTH_WINDOW_MS = 5 * 60 * 1_000; // 5 minutes
export const RATE_LIMIT_USE_SECRET = 120; // per minute

// -- Lockout -----------------------------------------------------------------

export const LOCKOUT_MAX_ATTEMPTS = 5;
export const LOCKOUT_DURATIONS_MS = [
  30 * 1_000, // 30 seconds
  5 * 60 * 1_000, // 5 minutes
  30 * 60 * 1_000, // 30 minutes
] as const;

// -- SQLite pragmas ----------------------------------------------------------

export const SQLITE_PRAGMAS = {
  journal_mode: "WAL",
  busy_timeout: 5_000,
  foreign_keys: "ON",
  synchronous: "FULL",
} as const;

// -- Vault defaults ----------------------------------------------------------

export const VAULT_VERSION = "1.5.0";
/**
 * The oldest `vault_version` this binary opens (R2, 2026-08-30): v1.5 runs on
 * a single baseline schema and cannot upgrade a vault from the 1.0–1.4 line.
 * Stays at 1.5.0 while VAULT_VERSION advances through 1.5.x — a one-time
 * reset, not a stamp that must match.
 */
export const VAULT_VERSION_FLOOR = "1.5.0";
export const VAULT_AUDIT_ENABLED = true;

// -- HTTP / use_secret defaults ----------------------------------------------

export const DEFAULT_HTTP_TIMEOUT_MS = 30_000; // 30 seconds
export const MAX_HTTP_RESPONSE_BYTES = 4_194_304; // 4 MiB — equals core's MAX_STRUCTURAL_CHARS, so a capped body never skips the structural redaction pass

// -- Process execution / use_secret defaults ---------------------------------

export const DEFAULT_PROCESS_TIMEOUT_MS = 30_000; // 30 seconds
export const MAX_PROCESS_OUTPUT_BYTES = 1_048_576; // 1 MiB captured per stream
export const MAX_PROCESS_ARGS = 256;

// -- MCP proxy / use_secret defaults ------------------------------------------

export const DEFAULT_MCP_TIMEOUT_MS = 30_000; // per tools/call
export const MCP_INIT_TIMEOUT_MS = 15_000; // connect + initialize handshake
export const MCP_SHUTDOWN_TIMEOUT_MS = 5_000; // graceful close budget on session end
export const MCP_IDLE_TTL_MS = 10 * 60 * 1_000; // a downstream child no use has touched (E73)
export const MCP_IDLE_SWEEP_INTERVAL_MS = 30 * 1_000; // idle-sweep cadence (E73)
export const MAX_MCP_RESULT_BYTES = 1_048_576; // 1 MiB serialized tool result
export const MAX_MCP_STDERR_BYTES = 65_536; // capped downstream stderr ring (audit only)
export const MAX_MCP_STDOUT_BUFFER_BYTES = 4_194_304; // 4 MiB unframed downstream stdout

// -- Database / Git / SSH / use_secret defaults -------------------------------

export const DEFAULT_DB_TIMEOUT_MS = 30_000; // connect + query budget
export const DEFAULT_GIT_TIMEOUT_MS = 120_000; // clone/pull/push may be slow
export const DEFAULT_SSH_TIMEOUT_MS = 30_000; // remote command budget
export const MAX_DB_ROWS = 10_000; // result-set row cap (flags truncated)
export const MAX_DB_RESULT_BYTES = 1_048_576; // 1 MiB serialized result set

// -- Token -------------------------------------------------------------------

export const MAX_TOKEN_TTL_MS = 24 * 60 * 60 * 1_000; // 24 hours

// -- Password ----------------------------------------------------------------

export const MIN_PASSWORD_LENGTH = 8;

// -- HKDF info strings for name indexing -------------------------------------

export const HKDF_INFO_NAME_INDEX = "name-index-v1";

// -- AAD for wrapped JWT/audit keys in vault_meta ----------------------------

export const AAD_WRAPPED_JWT_KEY = "wrapped-jwt-key";
export const AAD_WRAPPED_AUDIT_KEY = "wrapped-audit-key";

// -- AAD for OAuth encrypted fields (v1.1) -----------------------------------

export function AAD_OAUTH_CLIENT_ID(secretId: string): string {
  return `oauth-client-id:${secretId}`;
}

export function AAD_OAUTH_CLIENT_SECRET(secretId: string): string {
  return `oauth-client-secret:${secretId}`;
}

export function AAD_OAUTH_ACCESS_TOKEN(secretId: string): string {
  return `oauth-access-token:${secretId}`;
}

export function AAD_OAUTH_REFRESH_TOKEN(secretId: string): string {
  return `oauth-refresh-token:${secretId}`;
}

// -- AAD for certificate encrypted fields (v1.1 Phase 9) ----------------------

export function AAD_CERT_PRIVATE_KEY(secretId: string): string {
  return `cert-private-key:${secretId}`;
}

export function AAD_CERT_ACME_ACCOUNT(secretId: string): string {
  return `cert-acme-account:${secretId}`;
}

// -- AAD for per-secret injection policy -------------------------------------

export function AAD_INJECTION_POLICY(secretId: string): string {
  return `injection-policy:${secretId}`;
}

// -- AAD for per-secret MCP server config -------------------------------------

export function AAD_MCP_SERVER_CONFIG(secretId: string): string {
  return `mcp-server-config:${secretId}`;
}

// -- AAD for per-secret connection config (database TLS / SSH host keys) -------

export function AAD_CONNECTION_CONFIG(secretId: string): string {
  return `connection-config:${secretId}`;
}

// -- Name constraints --------------------------------------------------------

export const MAX_NAME_LENGTH = 255;

// -- Agent governance (v1.4) --------------------------------------------------

export const AGENT_DESCRIPTION_MAX_LENGTH = 1024;
export const AGENT_OWNER_MAX_LENGTH = 255;
export const TOKEN_LABEL_MAX_LENGTH = 255;

// -- SMTP / IMAP / WebSocket / Docker registry / use_secret defaults (v1.3) --

export const MAX_SMTP_RECIPIENTS = 100;
export const MAX_SMTP_ATTACHMENTS = 16;
export const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024; // 10 MiB per file
export const MAX_ATTACHMENT_TOTAL_BYTES = 25 * 1024 * 1024; // 25 MiB per message
export const MAX_WS_COLLECT_MESSAGES = 100;
export const MAX_WS_COLLECT_WINDOW_MS = 300_000; // 5 minutes
export const DEFAULT_WS_COLLECT_WINDOW_MS = 30_000; // 30 seconds
export const MAX_DOCKER_TIMEOUT_MS = 1_800_000; // 30 minutes
export const DEFAULT_SMTP_TLS_PORT = 465;
export const DEFAULT_SMTP_STARTTLS_PORT = 587;
export const DEFAULT_IMAP_PORT = 993;
export const MAX_IMAP_FETCH_UIDS = 100;

// -- Output sanitization ------------------------------------------------------

/**
 * Shortest credential fragment (a username half) worth redacting — shorter ones
 * would shred unrelated output. One floor for every injector.
 */
export const MIN_REDACTABLE_FRAGMENT = 3;
