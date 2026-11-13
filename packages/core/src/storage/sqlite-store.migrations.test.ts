import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AuditEvent } from "@harpoc/shared";
import { AAD_AUDIT_DETAIL_V2, AuditEventType, ErrorCode } from "@harpoc/shared";
import {
  AUDIT_CHAIN_GENESIS_BYTES,
  computeAuditRowHmac,
  deriveAuditChainKey,
} from "../audit/audit-chain.js";
import { AuditLogger } from "../audit/audit-logger.js";
import { AuditQuery } from "../audit/audit-query.js";
import { encrypt } from "../crypto/aes-gcm.js";
import { generateRandomBytes } from "../crypto/random.js";
import { baselineSchema } from "./migrations/baseline.js";
import { CREATE_AUDIT_PRINCIPAL_ACTIVE_INDEX, LATEST_SCHEMA_VERSION } from "./schema.js";
import { SqliteStore } from "./sqlite-store.js";
import { expectVaultError } from "@harpoc/test-utils";

const ACTIVE_INDEX = "idx_audit_principal_active";
const T0 = 1_800_000_000_000;

let dir: string;
let dbPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-migrations-"));
  dbPath = join(dir, "v.vault.db");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function onRawDb<T>(run: (db: Database.Database) => T): T {
  const db = new Database(dbPath);
  try {
    return run(db);
  } finally {
    db.close();
  }
}

function stampOf(db: Database.Database): string | undefined {
  const row = db.prepare("SELECT value FROM vault_meta WHERE key = 'schema_version'").get() as
    { value: string } | undefined;
  return row?.value;
}

function indexSql(db: Database.Database, name: string): string | undefined {
  const row = db
    .prepare("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?")
    .get(name) as { sql: string } | undefined;
  return row?.sql;
}

function schemaObjects(db: Database.Database): unknown[] {
  return db.prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").all();
}

function auditRows(db: Database.Database): unknown[] {
  return db.prepare("SELECT * FROM audit_log ORDER BY id").all();
}

function trail(auditKey: Uint8Array): Omit<AuditEvent, "id">[] {
  const detail = encrypt(
    auditKey,
    new Uint8Array(Buffer.from(JSON.stringify({ context: "http" }), "utf8")),
    AAD_AUDIT_DETAIL_V2(AuditEventType.SECRET_USE, T0 + 1, "s1"),
  );
  const row = (
    timestamp: number,
    event_type: AuditEventType,
    principal_id: string | null,
  ): Omit<AuditEvent, "id"> => ({
    timestamp,
    event_type,
    secret_id: null,
    principal_type: principal_id === null ? null : "agent",
    principal_id,
    detail_encrypted: null,
    detail_iv: null,
    detail_tag: null,
    ip_address: null,
    session_id: null,
    success: true,
  });
  return [
    row(T0, AuditEventType.VAULT_UNLOCK, null),
    {
      ...row(T0 + 1, AuditEventType.SECRET_USE, "alpha"),
      secret_id: "s1",
      detail_encrypted: detail.ciphertext,
      detail_iv: detail.iv,
      detail_tag: detail.tag,
    },
    row(T0 + 2, AuditEventType.VAULT_READ, "alpha"),
    row(T0 + 3, AuditEventType.VAULT_READ, "alpha"),
    { ...row(T0 + 4, AuditEventType.ACCESS_DENIED, "beta"), success: false },
  ];
}

/**
 * A vault file as a v1.5 build before schema 13 left it: the frozen baseline
 * DDL stamped with `stamp`, and a chained audit trail when an audit key is given.
 */
function buildBaselineStore(stamp: string, auditKey?: Uint8Array): void {
  onRawDb((db) => {
    db.exec(baselineSchema.up);
    db.prepare("INSERT INTO vault_meta (key, value) VALUES ('schema_version', ?)").run(stamp);
    if (auditKey === undefined) return;
    const chainKey = deriveAuditChainKey(auditKey);
    const insert = db.prepare(
      `INSERT INTO audit_log (
        timestamp, event_type, secret_id, principal_type, principal_id,
        detail_encrypted, detail_iv, detail_tag, ip_address, session_id, success, row_hmac
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    let prev = AUDIT_CHAIN_GENESIS_BYTES;
    for (const event of trail(auditKey)) {
      const link = computeAuditRowHmac(chainKey, event, prev);
      insert.run(
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
        Buffer.from(link),
      );
      prev = link;
    }
  });
}

describe("schema 13 — the last-active partial index, a step past the frozen baseline", () => {
  it("indexes the agent's non-read rows, its predicate naming AuditEventType.VAULT_READ's value", () => {
    const predicate = `WHERE event_type != '${AuditEventType.VAULT_READ}'`;
    expect(CREATE_AUDIT_PRINCIPAL_ACTIVE_INDEX).toContain(predicate);

    new SqliteStore(dbPath).close();
    onRawDb((db) => {
      expect(indexSql(db, ACTIVE_INDEX)).toContain(predicate);
      const columns = (
        db.prepare(`PRAGMA index_info(${ACTIVE_INDEX})`).all() as { name: string }[]
      ).map((c) => c.name);
      expect(columns).toEqual(["principal_type", "principal_id", "timestamp"]);
    });
  });

  it("brings an empty store through the baseline and the step to 13", () => {
    const store = new SqliteStore(dbPath);
    try {
      expect(LATEST_SCHEMA_VERSION).toBe(13);
      expect(store.getMeta("schema_version")).toBe("13");
      expect(indexSql(store.db, "idx_audit_principal")).toBeDefined();
      expect(indexSql(store.db, ACTIVE_INDEX)).toBeDefined();
    } finally {
      store.close();
    }
  });

  it("upgrades a schema-12 store built from the frozen baseline in place on its next open", () => {
    buildBaselineStore("12");
    onRawDb((db) => {
      expect(stampOf(db)).toBe("12");
      expect(indexSql(db, ACTIVE_INDEX)).toBeUndefined();
    });

    new SqliteStore(dbPath).close();

    onRawDb((db) => {
      expect(stampOf(db)).toBe("13");
      expect(indexSql(db, ACTIVE_INDEX)).toBeDefined();
    });
  });

  it("keeps every audit row of an upgraded schema-12 store, and its chain still verifies", () => {
    const auditKey = generateRandomBytes(32);
    buildBaselineStore("12", auditKey);
    const before = onRawDb(auditRows);
    expect(before).toHaveLength(5);

    const store = new SqliteStore(dbPath);
    try {
      expect(store.getMeta("schema_version")).toBe("13");
      expect(auditRows(store.db)).toEqual(before);

      const query = new AuditQuery(store, auditKey);
      expect(query.verifyChain()).toEqual({ valid: true, checked: 5, firstBrokenId: null });
      expect(query.query({ eventType: AuditEventType.SECRET_USE })[0]?.detail).toEqual({
        context: "http",
      });
      expect(store.agentLastActiveAt("alpha")).toBe(T0 + 1);

      new AuditLogger(store, auditKey).log({ eventType: AuditEventType.VAULT_LOCK });
      expect(query.verifyChain()).toEqual({ valid: true, checked: 6, firstBrokenId: null });
    } finally {
      store.close();
    }
  });

  it("leaves a schema-13 store alone on its next open — the step does not run again", () => {
    new SqliteStore(dbPath).close();
    onRawDb((db) => db.exec(`DROP INDEX ${ACTIVE_INDEX}`));
    const before = onRawDb(schemaObjects);

    new SqliteStore(dbPath).close();

    onRawDb((db) => {
      expect(stampOf(db)).toBe("13");
      expect(indexSql(db, ACTIVE_INDEX)).toBeUndefined();
      expect(schemaObjects(db)).toEqual(before);
    });
  });

  it("refuses a schema-14 store as newer than supported, before any DDL", async () => {
    buildBaselineStore("14");
    const before = onRawDb(schemaObjects);

    const err = await expectVaultError(() => new SqliteStore(dbPath), ErrorCode.VAULT_CORRUPTED);
    expect(err.message).toContain("Vault schema 14 is newer than supported 13");

    onRawDb((db) => {
      expect(stampOf(db)).toBe("14");
      expect(schemaObjects(db)).toEqual(before);
    });
  });

  it("freezes the baseline's DDL text — a schema change belongs in a step past the baseline, never in it", () => {
    expect(createHash("sha256").update(baselineSchema.up, "utf8").digest("hex")).toBe(
      "637aa0f942893523fd424e7a4820f2659db471280d5321a6c1143b5dc29191b0",
    );
  });

  it("fails a step that cannot complete as DATABASE_ERROR naming no driver text, the store left at 12", async () => {
    buildBaselineStore("12");
    onRawDb((db) =>
      db.exec(
        "CREATE TRIGGER refuse_stamp BEFORE INSERT ON vault_meta BEGIN SELECT RAISE(ABORT, 'refused by the test'); END;",
      ),
    );

    const err = await expectVaultError(() => new SqliteStore(dbPath), ErrorCode.DATABASE_ERROR);
    expect(err.message).toBe(
      "Database error: schema step 13 could not be applied (SQLITE_CONSTRAINT_TRIGGER)",
    );

    onRawDb((db) => {
      expect(stampOf(db)).toBe("12");
      expect(indexSql(db, ACTIVE_INDEX)).toBeUndefined();
    });
  });

  it("fails a baseline that cannot complete as DATABASE_ERROR naming no driver text, nothing created", async () => {
    onRawDb((db) => db.exec("CREATE TABLE secrets (x INTEGER) STRICT;"));
    const before = onRawDb(schemaObjects);

    const err = await expectVaultError(() => new SqliteStore(dbPath), ErrorCode.DATABASE_ERROR);
    expect(err.message).toBe(
      "Database error: the v1.5 baseline (schema 12) could not be applied (SQLITE_ERROR)",
    );

    onRawDb((db) => expect(schemaObjects(db)).toEqual(before));
  });
});
