import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteStore } from "./sqlite-store.js";
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

describe("migration 011 upgrade (v10 → v11)", () => {
  let tempDir: string;
  let secretId: string;

  /** Build a v10 vault: all pre-011 migrations, one secret + one oauth_tokens row without the column. */
  const buildV10Db = (dbPath: string): void => {
    const db = new Database(dbPath);
    for (const m of [
      migration001,
      migration002,
      migration003,
      migration004,
      migration005,
      migration006,
      migration007,
      migration008,
      migration009,
      migration010,
    ]) {
      db.exec(m.up);
    }
    db.prepare(
      "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', '10')",
    ).run();

    secretId = randomUUID();
    db.prepare(
      `INSERT INTO secrets (
        id, name_encrypted, name_iv, name_tag, type, project,
        wrapped_dek, dek_iv, dek_tag, ciphertext, ct_iv, ct_tag,
        created_at, updated_at, version, status, sync_version, name_hmac
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      secretId,
      Buffer.from([1]),
      Buffer.from([1]),
      Buffer.from([1]),
      "oauth_token",
      null,
      Buffer.from([1]),
      Buffer.from([1]),
      Buffer.from([1]),
      Buffer.from([1]),
      Buffer.from([1]),
      Buffer.from([1]),
      Date.now(),
      Date.now(),
      1,
      "active",
      0,
      "legacy-oauth",
    );

    // The pre-011 column list — this INSERT must not mention the new column.
    db.prepare(
      `INSERT INTO oauth_tokens (
        secret_id, provider, grant_type, token_endpoint, auth_endpoint,
        client_id_encrypted, client_id_iv, client_id_tag,
        scopes, access_token_expires_at, redirect_uri, pkce_method
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      secretId,
      "github",
      "authorization_code",
      "https://github.com/login/oauth/access_token",
      null,
      Buffer.from([10]),
      Buffer.from([11]),
      Buffer.from([12]),
      null,
      null,
      null,
      "S256",
    );
    db.close();
  };

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "harpoc-mig011-"));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("upgrades a v10 DB and reads the legacy row with a null auth method", () => {
    const dbPath = join(tempDir, "upgrade.vault.db");
    buildV10Db(dbPath);

    const store = new SqliteStore(dbPath);
    expect(Number(store.getMeta("schema_version"))).toBeGreaterThanOrEqual(11);

    const row = store.getOAuthToken(secretId);
    expect(row).toBeDefined();
    expect(row?.token_endpoint_auth_method).toBeNull();
    expect(row?.provider).toBe("github");
    expect(row?.token_endpoint).toBe("https://github.com/login/oauth/access_token");
    expect(row?.pkce_method).toBe("S256");
    store.close();
  });

  it("accepts a populated auth method on a fresh insert after the upgrade", () => {
    const dbPath = join(tempDir, "insert.vault.db");
    buildV10Db(dbPath);

    const store = new SqliteStore(dbPath);
    const newId = randomUUID();
    store.db
      .prepare(
        `INSERT INTO secrets (
          id, name_encrypted, name_iv, name_tag, type, project,
          wrapped_dek, dek_iv, dek_tag, ciphertext, ct_iv, ct_tag,
          created_at, updated_at, version, status, sync_version, name_hmac
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        newId,
        Buffer.from([1]),
        Buffer.from([1]),
        Buffer.from([1]),
        "oauth_token",
        null,
        Buffer.from([1]),
        Buffer.from([1]),
        Buffer.from([1]),
        Buffer.from([1]),
        Buffer.from([1]),
        Buffer.from([1]),
        Date.now(),
        Date.now(),
        1,
        "active",
        0,
        "fresh-oauth",
      );
    store.insertOAuthToken({
      secret_id: newId,
      provider: "custom",
      grant_type: "client_credentials",
      token_endpoint: "https://issuer.example/token",
      auth_endpoint: null,
      client_id_encrypted: new Uint8Array([1]),
      client_id_iv: new Uint8Array(12).fill(1),
      client_id_tag: new Uint8Array(16).fill(2),
      client_secret_encrypted: null,
      client_secret_iv: null,
      client_secret_tag: null,
      scopes: null,
      refresh_token_encrypted: null,
      refresh_token_iv: null,
      refresh_token_tag: null,
      access_token_encrypted: null,
      access_token_iv: null,
      access_token_tag: null,
      access_token_expires_at: null,
      redirect_uri: null,
      pkce_method: "S256",
      token_endpoint_auth_method: "client_secret_basic",
    });

    expect(store.getOAuthToken(newId)?.token_endpoint_auth_method).toBe("client_secret_basic");
    expect(store.getOAuthToken(secretId)?.token_endpoint_auth_method).toBeNull();
    store.close();
  });

  it("creates a fresh DB at v11 with the column present", () => {
    const dbPath = join(tempDir, "fresh.vault.db");
    const store = new SqliteStore(dbPath);
    expect(store.getMeta("schema_version")).toBe("11");

    const columns = store.db
      .prepare("PRAGMA table_info(oauth_tokens)")
      .all() as { name: string }[];
    expect(columns.map((c) => c.name)).toContain("token_endpoint_auth_method");
    store.close();
  });
});
