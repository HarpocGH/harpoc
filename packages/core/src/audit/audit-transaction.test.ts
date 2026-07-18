import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import { generateRandomBytes } from "../crypto/random.js";
import { SqliteStore } from "../storage/sqlite-store.js";
import { AuditLogger } from "./audit-logger.js";
import { AuditQuery } from "./audit-query.js";

// Mechanism pins for transactional audit writes (NM3): the plan composes an
// operation's state write and its audit row inside one outer store.transaction,
// relying on better-sqlite3 running a nested transaction function (the one
// inside AuditLogger.log) as a SAVEPOINT on the same connection. These tests
// pin that behavior before any production code depends on it.

let store: SqliteStore;
let auditKey: Uint8Array;
let logger: AuditLogger;
let query: AuditQuery;

beforeEach(() => {
  store = new SqliteStore(":memory:");
  auditKey = generateRandomBytes(32);
  logger = new AuditLogger(store, auditKey);
  query = new AuditQuery(store, auditKey);
});

afterEach(() => {
  vi.restoreAllMocks();
  store.close();
});

function auditRowCount(): number {
  const row = store.db.prepare("SELECT COUNT(*) AS n FROM audit_log").get() as { n: number };
  return row.n;
}

describe("audit log inside an outer transaction (savepoint nesting)", () => {
  it("commits the state write and the audit row together", () => {
    store.transaction(() => {
      store.setMeta("p0_state", "written");
      logger.log({ eventType: AuditEventType.SECRET_CREATE, detail: { handle: "secret://x" } });
    });

    expect(store.getMeta("p0_state")).toBe("written");
    expect(auditRowCount()).toBe(1);
    expect(query.verifyChain().valid).toBe(true);
  });

  it("rolls back both when the outer transaction throws after the log", () => {
    logger.log({ eventType: AuditEventType.VAULT_UNLOCK });
    const tailBefore = store.getLastAuditRowHmac();

    expect(() =>
      store.transaction(() => {
        store.setMeta("p0_state", "written");
        logger.log({ eventType: AuditEventType.SECRET_CREATE, detail: { handle: "secret://x" } });
        throw new Error("post-log failure");
      }),
    ).toThrow("post-log failure");

    expect(store.getMeta("p0_state")).toBeUndefined();
    expect(auditRowCount()).toBe(1);

    // The next write chains onto the pre-transaction tail — no gap, no fork.
    logger.log({ eventType: AuditEventType.SECRET_READ, detail: { after: true } });
    const result = query.verifyChain();
    expect(result.valid).toBe(true);
    expect(result.checked).toBe(2);
    expect(store.getLastAuditRowHmac()).not.toEqual(tailBefore);
  });

  it("keeps the chain linear across two logs in one transaction", () => {
    // The second log's SELECT-last must see the first's uncommitted insert
    // (same connection) — the multi-row case setInjectionPolicy produces.
    logger.log({ eventType: AuditEventType.VAULT_UNLOCK });

    store.transaction(() => {
      logger.log({ eventType: AuditEventType.POLICY_GRANT, detail: { policy: "injection" } });
      logger.log({
        eventType: AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED,
        detail: { interpreters: ["node"] },
      });
    });

    const result = query.verifyChain();
    expect(result.valid).toBe(true);
    expect(result.checked).toBe(3);
  });

  it("rolls back the state write when the audit insert fails (fail-closed)", () => {
    // The fault-injection instrument every later phase reuses: force the audit
    // INSERT itself to fail and assert the paired state write never commits.
    vi.spyOn(store, "insertAuditEvent").mockImplementationOnce(() => {
      throw new Error("audit write failed");
    });

    expect(() =>
      store.transaction(() => {
        store.setMeta("p0_state", "written");
        logger.log({ eventType: AuditEventType.SECRET_CREATE, detail: { handle: "secret://x" } });
      }),
    ).toThrow("audit write failed");

    expect(store.getMeta("p0_state")).toBeUndefined();
    expect(auditRowCount()).toBe(0);

    // The store is healthy afterwards: the next paired write commits and verifies.
    store.transaction(() => {
      store.setMeta("p0_state", "second");
      logger.log({ eventType: AuditEventType.SECRET_CREATE, detail: { handle: "secret://y" } });
    });
    expect(store.getMeta("p0_state")).toBe("second");
    expect(auditRowCount()).toBe(1);
    expect(query.verifyChain().valid).toBe(true);
  });
});
