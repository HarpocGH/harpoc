import { describe, expect, it } from "vitest";

import {
  AAD_AUDIT_DETAIL,
  AAD_DEK_WRAP,
  AAD_MCP_SERVER_CONFIG,
  AAD_METADATA,
  AAD_NAME_ENCRYPTION,
  AAD_SECRET_PAYLOAD,
  AAD_SESSION_JWT,
  AAD_SESSION_KEK,
  AAD_VAULT_KEK,
  AES_IV_LENGTH,
  AES_KEY_LENGTH,
  AES_TAG_LENGTH,
  ARGON2_HASH_LENGTH,
  ARGON2_MEMORY_COST,
  ARGON2_PARALLELISM,
  ARGON2_TIME_COST,
  ARGON2_VERSION,
  AUDIT_DIR_NAME,
  CONFIG_FILE_NAME,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_SESSION_TTL_MS,
  MAX_NAME_LENGTH,
  HKDF_INFO_AUDIT,
  HKDF_INFO_JWT_SIGNING,
  HKDF_INFO_SYNC,
  LOCKOUT_DURATIONS_MS,
  LOCKOUT_MAX_ATTEMPTS,
  MAX_SESSION_TTL_MS,
  RATE_LIMIT_AUTH_ATTEMPTS,
  RATE_LIMIT_AUTH_WINDOW_MS,
  RATE_LIMIT_GLOBAL,
  RATE_LIMIT_PER_SECRET,
  RATE_LIMIT_USE_SECRET,
  SESSION_CLEANUP_INTERVAL_MS,
  SESSION_FILE_NAME,
  SESSION_SLIDE_INTERVAL_MS,
  SQLITE_PRAGMAS,
  VAULT_AUDIT_ENABLED,
  VAULT_DB_NAME,
  VAULT_DIR_NAME,
  VAULT_VERSION,
} from "./constants.js";

// ---------------------------------------------------------------------------
// AAD functions
// ---------------------------------------------------------------------------

describe("AAD_DEK_WRAP", () => {
  it("returns 'dek-wrap:<secretId>'", () => {
    expect(AAD_DEK_WRAP("abc-123")).toBe("dek-wrap:abc-123");
  });

  it("handles empty string", () => {
    expect(AAD_DEK_WRAP("")).toBe("dek-wrap:");
  });

  it("includes UUID-style ids verbatim", () => {
    const id = "550e8400-e29b-41d4-a716-446655440000";
    expect(AAD_DEK_WRAP(id)).toBe(`dek-wrap:${id}`);
  });
});

describe("AAD_SECRET_PAYLOAD", () => {
  it("returns 'secret-payload:<secretId>:<version>'", () => {
    expect(AAD_SECRET_PAYLOAD("abc", 1)).toBe("secret-payload:abc:1");
  });

  it("handles version 0", () => {
    expect(AAD_SECRET_PAYLOAD("id", 0)).toBe("secret-payload:id:0");
  });

  it("handles empty secretId", () => {
    expect(AAD_SECRET_PAYLOAD("", 5)).toBe("secret-payload::5");
  });
});

describe("AAD_NAME_ENCRYPTION", () => {
  it("returns 'name-enc:<secretId>'", () => {
    expect(AAD_NAME_ENCRYPTION("abc-123")).toBe("name-enc:abc-123");
  });

  it("handles empty string", () => {
    expect(AAD_NAME_ENCRYPTION("")).toBe("name-enc:");
  });
});

describe("AAD_METADATA", () => {
  it("returns 'metadata:<secretId>'", () => {
    expect(AAD_METADATA("abc-123")).toBe("metadata:abc-123");
  });

  it("handles empty string", () => {
    expect(AAD_METADATA("")).toBe("metadata:");
  });
});

describe("AAD_MCP_SERVER_CONFIG", () => {
  it("returns 'mcp-server-config:<secretId>'", () => {
    expect(AAD_MCP_SERVER_CONFIG("abc-123")).toBe("mcp-server-config:abc-123");
  });
});

// ---------------------------------------------------------------------------
// Static AAD strings
// ---------------------------------------------------------------------------

describe("static AAD strings", () => {
  it("AAD_VAULT_KEK", () => {
    expect(AAD_VAULT_KEK).toBe("vault-kek");
  });

  it("AAD_SESSION_KEK", () => {
    expect(AAD_SESSION_KEK).toBe("session-kek");
  });

  it("AAD_SESSION_JWT", () => {
    expect(AAD_SESSION_JWT).toBe("session-jwt");
  });

  it("AAD_AUDIT_DETAIL", () => {
    expect(AAD_AUDIT_DETAIL).toBe("audit-detail");
  });
});

// ---------------------------------------------------------------------------
// Crypto: Argon2id
// ---------------------------------------------------------------------------

describe("Argon2id constants", () => {
  it("ARGON2_MEMORY_COST is 65536 (64 MB)", () => {
    expect(ARGON2_MEMORY_COST).toBe(65_536);
  });

  it("ARGON2_TIME_COST is 3", () => {
    expect(ARGON2_TIME_COST).toBe(3);
  });

  it("ARGON2_PARALLELISM is 4", () => {
    expect(ARGON2_PARALLELISM).toBe(4);
  });

  it("ARGON2_HASH_LENGTH is 32 (256 bits)", () => {
    expect(ARGON2_HASH_LENGTH).toBe(32);
  });

  it("ARGON2_VERSION is 0x13 (v1.3)", () => {
    expect(ARGON2_VERSION).toBe(0x13);
  });
});

// ---------------------------------------------------------------------------
// Crypto: AES-256-GCM
// ---------------------------------------------------------------------------

describe("AES-256-GCM constants", () => {
  it("AES_KEY_LENGTH is 32 (256 bits)", () => {
    expect(AES_KEY_LENGTH).toBe(32);
  });

  it("AES_IV_LENGTH is 12 (96 bits)", () => {
    expect(AES_IV_LENGTH).toBe(12);
  });

  it("AES_TAG_LENGTH is 16 (128 bits)", () => {
    expect(AES_TAG_LENGTH).toBe(16);
  });
});

// ---------------------------------------------------------------------------
// Path constants
// ---------------------------------------------------------------------------

describe("path constants", () => {
  it("VAULT_DIR_NAME", () => {
    expect(VAULT_DIR_NAME).toBe(".harpoc");
  });

  it("VAULT_DB_NAME", () => {
    expect(VAULT_DB_NAME).toBe("default.vault.db");
  });

  it("SESSION_FILE_NAME", () => {
    expect(SESSION_FILE_NAME).toBe("session.json");
  });

  it("CONFIG_FILE_NAME", () => {
    expect(CONFIG_FILE_NAME).toBe("config.json");
  });

  it("AUDIT_DIR_NAME", () => {
    expect(AUDIT_DIR_NAME).toBe("audit");
  });
});

// ---------------------------------------------------------------------------
// Session timing
// ---------------------------------------------------------------------------

describe("session timing constants", () => {
  it("DEFAULT_SESSION_TTL_MS is 15 minutes", () => {
    expect(DEFAULT_SESSION_TTL_MS).toBe(15 * 60 * 1_000);
  });

  it("MAX_SESSION_TTL_MS is 24 hours", () => {
    expect(MAX_SESSION_TTL_MS).toBe(24 * 60 * 60 * 1_000);
  });

  it("SESSION_SLIDE_INTERVAL_MS is 30 seconds", () => {
    expect(SESSION_SLIDE_INTERVAL_MS).toBe(30_000);
  });

  it("SESSION_CLEANUP_INTERVAL_MS is 30 seconds", () => {
    expect(SESSION_CLEANUP_INTERVAL_MS).toBe(30_000);
  });
});

// ---------------------------------------------------------------------------
// Rate limits
// ---------------------------------------------------------------------------

describe("rate limit constants", () => {
  it("RATE_LIMIT_GLOBAL is 1000 per minute", () => {
    expect(RATE_LIMIT_GLOBAL).toBe(1_000);
  });

  it("RATE_LIMIT_PER_SECRET is 60 per minute", () => {
    expect(RATE_LIMIT_PER_SECRET).toBe(60);
  });

  it("RATE_LIMIT_AUTH_ATTEMPTS is 10", () => {
    expect(RATE_LIMIT_AUTH_ATTEMPTS).toBe(10);
  });

  it("RATE_LIMIT_AUTH_WINDOW_MS is 5 minutes", () => {
    expect(RATE_LIMIT_AUTH_WINDOW_MS).toBe(5 * 60 * 1_000);
  });

  it("RATE_LIMIT_USE_SECRET is 120 per minute", () => {
    expect(RATE_LIMIT_USE_SECRET).toBe(120);
  });
});

// ---------------------------------------------------------------------------
// Lockout
// ---------------------------------------------------------------------------

describe("lockout constants", () => {
  it("LOCKOUT_MAX_ATTEMPTS is 5", () => {
    expect(LOCKOUT_MAX_ATTEMPTS).toBe(5);
  });

  it("LOCKOUT_DURATIONS_MS has 3 entries", () => {
    expect(LOCKOUT_DURATIONS_MS).toHaveLength(3);
  });

  it("LOCKOUT_DURATIONS_MS[0] is 30 seconds", () => {
    expect(LOCKOUT_DURATIONS_MS[0]).toBe(30_000);
  });

  it("LOCKOUT_DURATIONS_MS[1] is 5 minutes", () => {
    expect(LOCKOUT_DURATIONS_MS[1]).toBe(300_000);
  });

  it("LOCKOUT_DURATIONS_MS[2] is 30 minutes", () => {
    expect(LOCKOUT_DURATIONS_MS[2]).toBe(1_800_000);
  });
});

// ---------------------------------------------------------------------------
// SQLite pragmas
// ---------------------------------------------------------------------------

describe("SQLite pragmas", () => {
  it("journal_mode is WAL", () => {
    expect(SQLITE_PRAGMAS.journal_mode).toBe("WAL");
  });

  it("busy_timeout is 5000", () => {
    expect(SQLITE_PRAGMAS.busy_timeout).toBe(5_000);
  });

  it("foreign_keys is ON", () => {
    expect(SQLITE_PRAGMAS.foreign_keys).toBe("ON");
  });

  it("synchronous is FULL", () => {
    expect(SQLITE_PRAGMAS.synchronous).toBe("FULL");
  });
});

// ---------------------------------------------------------------------------
// HKDF info strings
// ---------------------------------------------------------------------------

describe("HKDF info strings", () => {
  it("HKDF_INFO_JWT_SIGNING", () => {
    expect(HKDF_INFO_JWT_SIGNING).toBe("api-token-signing-v1");
  });

  it("HKDF_INFO_SYNC", () => {
    expect(HKDF_INFO_SYNC).toBe("sync-key-v1");
  });

  it("HKDF_INFO_AUDIT", () => {
    expect(HKDF_INFO_AUDIT).toBe("audit-key-v1");
  });
});

// ---------------------------------------------------------------------------
// Vault defaults
// ---------------------------------------------------------------------------

describe("vault defaults", () => {
  it("VAULT_VERSION is 1.0.0", () => {
    expect(VAULT_VERSION).toBe("1.0.0");
  });

  it("VAULT_AUDIT_ENABLED is true", () => {
    expect(VAULT_AUDIT_ENABLED).toBe(true);
  });

  it("DEFAULT_HTTP_TIMEOUT_MS is 30 seconds", () => {
    expect(DEFAULT_HTTP_TIMEOUT_MS).toBe(30_000);
  });

  it("MAX_NAME_LENGTH is 255", () => {
    expect(MAX_NAME_LENGTH).toBe(255);
  });
});
