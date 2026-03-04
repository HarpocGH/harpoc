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

export const ARGON2_MEMORY_COST = 65_536; // 64 MB
export const ARGON2_TIME_COST = 3;
export const ARGON2_PARALLELISM = 4;
export const ARGON2_HASH_LENGTH = 32; // 256 bits
export const ARGON2_VERSION = 0x13; // v1.3
export const ARGON2_SALT_LENGTH = 16; // 128 bits

// -- Crypto: AES-256-GCM ----------------------------------------------------

export const AES_KEY_LENGTH = 32; // 256 bits
export const AES_IV_LENGTH = 12; // 96 bits
export const AES_TAG_LENGTH = 16; // 128 bits

// -- HKDF info strings -------------------------------------------------------

export const HKDF_INFO_JWT_SIGNING = "api-token-signing-v1";
export const HKDF_INFO_SYNC = "sync-key-v1";
export const HKDF_INFO_AUDIT = "audit-key-v1";

// -- AAD (Additional Authenticated Data) strings -----------------------------

export const AAD_VAULT_KEK = "vault-kek";
export const AAD_SESSION_KEK = "session-kek";
export const AAD_SESSION_JWT = "session-jwt";
export const AAD_SESSION_AUDIT = "session-audit";
export const AAD_AUDIT_DETAIL = "audit-detail";

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

export const VAULT_VERSION = "1.0.0";
export const VAULT_AUDIT_ENABLED = true;

// -- HTTP / use_secret defaults ----------------------------------------------

export const DEFAULT_HTTP_TIMEOUT_MS = 30_000; // 30 seconds

// -- Token -------------------------------------------------------------------

export const MAX_TOKEN_TTL_MS = 24 * 60 * 60 * 1_000; // 24 hours

// -- Password ----------------------------------------------------------------

export const MIN_PASSWORD_LENGTH = 8;

// -- HKDF info strings for name indexing -------------------------------------

export const HKDF_INFO_NAME_INDEX = "name-index-v1";

// -- AAD for wrapped JWT/audit keys in vault_meta ----------------------------

export const AAD_WRAPPED_JWT_KEY = "wrapped-jwt-key";
export const AAD_WRAPPED_AUDIT_KEY = "wrapped-audit-key";

// -- Name constraints --------------------------------------------------------

export const MAX_NAME_LENGTH = 255;
