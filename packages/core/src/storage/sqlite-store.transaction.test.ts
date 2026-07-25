import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import { AuditLogger } from "../audit/audit-logger.js";
import { AuditQuery } from "../audit/audit-query.js";
import { generateRandomBytes } from "../crypto/random.js";
import { SqliteStore } from "./sqlite-store.js";

/**
 * M7. `db.transaction(fn)()` issues a plain (deferred) BEGIN. Transactions whose
 * first statement is a SELECT — AuditLogger.log and SecretManager.createSecret —
 * took a WAL read snapshot and only then attempted to upgrade to a write. If
 * another connection committed in between, SQLite returned SQLITE_BUSY_SNAPSHOT,
 * which `busy_timeout` deliberately does not retry: with a `server start` daemon
 * alongside CLI commands (the documented deployment) that is a spurious failure,
 * and under the atomic-audit semantics the whole operation rolls back.
 */

let dir: string;
let dbPath: string;
let store: SqliteStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-txn-"));
  dbPath = join(dir, "test.vault.db");
  store = new SqliteStore(dbPath);
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

/** A second process's connection, with no patience for a held write lock. */
function otherConnection(): Database.Database {
  const db = new Database(dbPath);
  db.pragma("busy_timeout = 0");
  return db;
}

describe("SqliteStore.transaction write-lock acquisition (M7)", () => {
  it("holds the write lock from BEGIN, so a read-then-write transaction cannot lose its snapshot", () => {
    let otherWriteCommitted = false;

    // The read-then-write shape: SELECT first, another connection tries to
    // commit, then the upgrade to a write.
    store.transaction(() => {
      store.db.prepare("SELECT COUNT(*) AS n FROM audit_log").get();

      const other = otherConnection();
      try {
        other
          .prepare("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)")
          .run("intruder", "1");
        otherWriteCommitted = true;
      } catch {
        // Expected: the write lock is already held by this transaction.
      } finally {
        other.close();
      }

      // Under a deferred BEGIN this upgrade is what raised SQLITE_BUSY_SNAPSHOT.
      store.setMeta("txn_state", "written");
    });

    expect(otherWriteCommitted).toBe(false);
    expect(store.getMeta("txn_state")).toBe("written");
    expect(store.getMeta("intruder")).toBeUndefined();
  });

  it("an audit write racing another connection still commits", () => {
    const auditKey = generateRandomBytes(32);
    const logger = new AuditLogger(store, auditKey);
    const query = new AuditQuery(store, auditKey);

    logger.log({ eventType: AuditEventType.VAULT_UNLOCK });

    store.transaction(() => {
      // A read before any write is what opened the snapshot window.
      store.db.prepare("SELECT COUNT(*) AS n FROM audit_log").get();

      const other = otherConnection();
      try {
        other
          .prepare("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)")
          .run("intruder", "1");
      } catch {
        // Expected.
      } finally {
        other.close();
      }

      // AuditLogger.log's own SELECT-last + INSERT runs here as a savepoint.
      logger.log({ eventType: AuditEventType.SECRET_READ, detail: { a: 1 } });
      logger.log({ eventType: AuditEventType.SECRET_USE, detail: { b: 2 } });
    });

    const result = query.verifyChain();
    expect(result.valid).toBe(true);
    expect(result.checked).toBe(3);
  });

  it("control: another connection writes freely outside a transaction", () => {
    const other = otherConnection();
    try {
      other
        .prepare("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)")
        .run("outside", "1");
    } finally {
      other.close();
    }

    expect(store.getMeta("outside")).toBe("1");
  });

  it("control: nested transactions still run as savepoints and roll back cleanly", () => {
    expect(() =>
      store.transaction(() => {
        store.setMeta("outer", "1");
        store.transaction(() => {
          store.setMeta("inner", "1");
        });
        throw new Error("boom");
      }),
    ).toThrow("boom");

    expect(store.getMeta("outer")).toBeUndefined();
    expect(store.getMeta("inner")).toBeUndefined();

    // The connection is healthy afterwards.
    store.transaction(() => store.setMeta("after", "1"));
    expect(store.getMeta("after")).toBe("1");
  });
});
