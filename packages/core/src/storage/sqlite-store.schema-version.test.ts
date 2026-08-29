import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { SqliteStore } from "./sqlite-store.js";
import { LATEST_SCHEMA_VERSION } from "./schema.js";
import { expectVaultError } from "../test-helpers/expect-vault-error.js";

let dir: string;
let dbPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-schemaver-"));
  dbPath = join(dir, "v.vault.db");
  new SqliteStore(dbPath).close();
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function stampSchemaVersion(value: string): void {
  const db = new Database(dbPath);
  db.prepare("UPDATE vault_meta SET value = ? WHERE key = 'schema_version'").run(value);
  db.close();
}

describe("schema_version guard (N2 — fail closed)", () => {
  it("refuses a malformed schema_version instead of skipping every migration", async () => {
    stampSchemaVersion("abc");
    const err = await expectVaultError(() => new SqliteStore(dbPath), ErrorCode.VAULT_CORRUPTED);
    expect(err.message).toContain("schema_version");
  });

  it("refuses a schema_version newer than the binary supports", async () => {
    stampSchemaVersion(String(LATEST_SCHEMA_VERSION + 1));
    const err = await expectVaultError(() => new SqliteStore(dbPath), ErrorCode.VAULT_CORRUPTED);
    expect(err.message).toContain(String(LATEST_SCHEMA_VERSION + 1));
  });

  it("still opens a vault at the current version and a fresh in-memory store", () => {
    const store = new SqliteStore(dbPath);
    expect(store.getMeta("schema_version")).toBe(String(LATEST_SCHEMA_VERSION));
    store.close();
    const mem = new SqliteStore(":memory:");
    expect(mem.getMeta("schema_version")).toBe(String(LATEST_SCHEMA_VERSION));
    mem.close();
  });
});
