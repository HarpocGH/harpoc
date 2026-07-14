import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { computeNameHmac, createVaultKeys } from "../crypto/key-hierarchy.js";
import { SqliteStore } from "../storage/sqlite-store.js";
import { migration001 } from "../storage/migrations/001-initial.js";
import { migration002 } from "../storage/migrations/002-revoked-tokens.js";
import { migration003 } from "../storage/migrations/003-name-hmac.js";
import { migration004 } from "../storage/migrations/004-oauth-tokens.js";
import { migration005 } from "../storage/migrations/005-certificates.js";
import { migration006 } from "../storage/migrations/006-injection-policies.js";
import { migration007 } from "../storage/migrations/007-mcp-servers.js";
import { migration008 } from "../storage/migrations/008-connection-configs.js";
import { SecretManager } from "./secret-manager.js";

let kek: Uint8Array;

beforeAll(async () => {
  const keys = await createVaultKeys("test-password");
  kek = keys.kek;
});

describe("createSecret duplicate handling (TOCTOU fix)", () => {
  let store: SqliteStore;
  let manager: SecretManager;

  beforeEach(() => {
    store = new SqliteStore(":memory:");
    manager = new SecretManager(store, kek);
  });

  afterEach(() => {
    store.close();
  });

  it("rejects a second concurrent create of the same name with DUPLICATE_SECRET (one row)", async () => {
    const create = (): Promise<unknown> =>
      manager.createSecret({
        name: "race",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v")),
      });

    const results = await Promise.allSettled([create(), create()]);
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");

    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({
      code: ErrorCode.DUPLICATE_SECRET,
    });
    expect(store.getSecretsByNameHmac(await computeNameHmac(kek, "race", null))).toHaveLength(1);
  });

  it("allows recreating a name after the original is revoked", async () => {
    await manager.createSecret({
      name: "reusable",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v1")),
    });
    await manager.revokeSecret("secret://reusable");

    await expect(
      manager.createSecret({
        name: "reusable",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v2")),
      }),
    ).resolves.toMatchObject({ status: "created" });
  });

  it("still blocks recreating a name held by an expired secret", async () => {
    await manager.createSecret({
      name: "soon",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      expiresAt: Date.now() - 1000, // already expired (still non-revoked)
    });

    await expect(
      manager.createSecret({
        name: "soon",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v2")),
      }),
    ).rejects.toMatchObject({ code: ErrorCode.DUPLICATE_SECRET });
  });

  it("enforces the unique index at the storage layer (cross-process backstop)", async () => {
    const hmac = await computeNameHmac(kek, "pinned", null);
    const row = (status: string) => ({
      id: randomUUID(),
      name_encrypted: new Uint8Array([1]),
      name_iv: new Uint8Array([1]),
      name_tag: new Uint8Array([1]),
      type: "api_key" as const,
      project: null,
      wrapped_dek: new Uint8Array([1]),
      dek_iv: new Uint8Array([1]),
      dek_tag: new Uint8Array([1]),
      ciphertext: new Uint8Array([1]),
      ct_iv: new Uint8Array([1]),
      ct_tag: new Uint8Array([1]),
      metadata_encrypted: null,
      metadata_iv: null,
      metadata_tag: null,
      created_at: Date.now(),
      updated_at: Date.now(),
      expires_at: null,
      rotated_at: null,
      version: 1,
      status: status as "active",
      sync_version: 0,
      name_hmac: hmac,
    });

    store.insertSecret(row("active"));
    // Second live row with the same name_hmac violates the partial unique index.
    expect(() => store.insertSecret(row("active"))).toThrow();
    // A revoked row with the same name_hmac is allowed (excluded from the index).
    expect(() => store.insertSecret(row("revoked"))).not.toThrow();
  });
});

describe("migration 009 upgrade (v8 → v9)", () => {
  let tempDir: string;

  const dummySecret = (status: string, nameHmac: string): Record<string, unknown> => ({
    id: randomUUID(),
    name_encrypted: Buffer.from([1]),
    name_iv: Buffer.from([1]),
    name_tag: Buffer.from([1]),
    type: "api_key",
    project: null,
    wrapped_dek: Buffer.from([1]),
    dek_iv: Buffer.from([1]),
    dek_tag: Buffer.from([1]),
    ciphertext: Buffer.from([1]),
    ct_iv: Buffer.from([1]),
    ct_tag: Buffer.from([1]),
    metadata_encrypted: null,
    metadata_iv: null,
    metadata_tag: null,
    created_at: Date.now(),
    updated_at: Date.now(),
    expires_at: null,
    rotated_at: null,
    version: 1,
    status,
    sync_version: 0,
    name_hmac: nameHmac,
  });

  const buildV8Db = (dbPath: string, secrets: Record<string, unknown>[]): void => {
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
    ]) {
      db.exec(m.up);
    }
    db.prepare("INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', '8')").run();
    const cols = Object.keys(dummySecret("active", "x"));
    const insert = db.prepare(
      `INSERT INTO secrets (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`,
    );
    for (const s of secrets) {
      insert.run(...cols.map((c) => s[c]));
    }
    db.close();
  };

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "harpoc-mig009-"));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("upgrades a v8 DB with a revoked+active same-name pair, preserving rows", () => {
    const dbPath = join(tempDir, "ok.vault.db");
    buildV8Db(dbPath, [dummySecret("active", "aaa"), dummySecret("revoked", "aaa")]);

    const store = new SqliteStore(dbPath);
    // Opening runs 009 (this fix) and every later migration; landing >= 9 with
    // the live-name index present is what matters here.
    expect(Number(store.getMeta("schema_version"))).toBeGreaterThanOrEqual(9);
    expect(store.getSecretsByNameHmac("aaa")).toHaveLength(2);
    const index = store.db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_secrets_name_hmac_live'",
      )
      .get() as { name: string } | undefined;
    expect(index?.name).toBe("idx_secrets_name_hmac_live");
    store.close();
  });

  it("aborts the upgrade when a live duplicate pair exists, leaving the DB untouched", () => {
    const dbPath = join(tempDir, "dupe.vault.db");
    buildV8Db(dbPath, [dummySecret("active", "bbb"), dummySecret("active", "bbb")]);

    expect(() => new SqliteStore(dbPath)).toThrow(VaultError);
    try {
      new SqliteStore(dbPath);
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.VAULT_CORRUPTED);
    }

    // Version stayed at 8; the index was not created (rollback).
    const db = new Database(dbPath);
    const version = (
      db.prepare("SELECT value FROM vault_meta WHERE key='schema_version'").get() as {
        value: string;
      }
    ).value;
    expect(version).toBe("8");
    const index = db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_secrets_name_hmac_live'",
      )
      .get();
    expect(index).toBeUndefined();
    db.close();
  });
});
