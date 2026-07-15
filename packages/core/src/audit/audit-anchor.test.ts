import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import { generateRandomBytes } from "../crypto/random.js";
import { SqliteStore } from "../storage/sqlite-store.js";
import { AuditLogger } from "./audit-logger.js";
import { AuditQuery } from "./audit-query.js";
import type { AuditChainAnchorInput, AuditChainTailLink } from "./audit-query.js";

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
  store.close();
});

function logRows(count: number): number[] {
  const ids: number[] = [];
  for (let i = 0; i < count; i++) {
    ids.push(logger.log({ eventType: AuditEventType.SECRET_READ, detail: { i } }));
  }
  return ids;
}

function insertLegacyRow(): number {
  const result = store.db
    .prepare(
      `INSERT INTO audit_log (timestamp, event_type, secret_id, principal_type, principal_id,
         detail_encrypted, detail_iv, detail_tag, ip_address, session_id, success, row_hmac)
       VALUES (?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1, NULL)`,
    )
    .run(Date.now(), AuditEventType.VAULT_UNLOCK);
  return Number(result.lastInsertRowid);
}

function takeAnchor(): AuditChainAnchorInput {
  const tail = query.chainTail() as AuditChainTailLink;
  expect(tail).not.toBeNull();
  return { lastId: tail.lastId, rowHmac: tail.rowHmac };
}

describe("chainTail", () => {
  it("returns the newest chained row", () => {
    const ids = logRows(3);
    const tail = query.chainTail();
    expect(tail?.lastId).toBe(ids[2]);
    expect(tail?.rowHmac).toBeInstanceOf(Uint8Array);
    expect(tail?.rowHmac.length).toBe(32);
    expect(tail?.timestamp).toBeGreaterThan(0);
  });

  it("returns null on an empty log", () => {
    expect(query.chainTail()).toBeNull();
  });

  it("returns null when only legacy rows exist", () => {
    insertLegacyRow();
    expect(query.chainTail()).toBeNull();
  });

  it("skips trailing legacy rows back to the newest chained row", () => {
    const ids = logRows(2);
    insertLegacyRow();
    const tail = query.chainTail();
    expect(tail?.lastId).toBe(ids[1]);
  });
});

describe("anchored chain verification (tail truncation)", () => {
  it("pins the vulnerability: plain verifyChain stays blind to tail truncation, the anchor catches it", () => {
    const ids = logRows(5);
    const anchor = takeAnchor();

    // Attacker with DB write access deletes the newest 2 rows (anchored row included).
    store.db.prepare("DELETE FROM audit_log WHERE id >= ?").run(ids[3]);

    // The shorter chain is still perfectly valid — this assertion IS the finding.
    const plain = query.verifyChain();
    expect(plain.valid).toBe(true);
    expect(plain.checked).toBe(3);

    const anchored = query.verifyChain(anchor);
    expect(anchored.valid).toBe(false);
    expect(anchored.anchor).toEqual({ lastId: anchor.lastId, status: "row_missing" });
    expect(anchored.firstBrokenId).toBeNull();
  });

  it("passes when rows were appended after the anchor", () => {
    logRows(3);
    const anchor = takeAnchor();
    logRows(4);

    const result = query.verifyChain(anchor);
    expect(result.valid).toBe(true);
    expect(result.checked).toBe(7);
    expect(result.anchor).toEqual({ lastId: anchor.lastId, status: "ok" });
    expect(query.chainTail()?.lastId).toBeGreaterThan(anchor.lastId);
  });

  it("passes on the exact anchored state (nothing appended)", () => {
    logRows(3);
    const anchor = takeAnchor();
    const result = query.verifyChain(anchor);
    expect(result.valid).toBe(true);
    expect(result.anchor?.status).toBe("ok");
  });

  it("detects a rollback where the anchored id is re-minted with different content", () => {
    const ids = logRows(4);
    const anchor = takeAnchor();

    // Simulate restoring an older DB copy: the tail rows are gone AND the
    // AUTOINCREMENT sequence is back at the older value, so appends re-mint ids.
    store.db.prepare("DELETE FROM audit_log WHERE id >= ?").run(ids[2]);
    store.db
      .prepare("UPDATE sqlite_sequence SET seq = ? WHERE name = 'audit_log'")
      .run(ids[1] as number);

    logRows(3);
    const reminted = store.db
      .prepare("SELECT id FROM audit_log WHERE id = ?")
      .get(anchor.lastId) as { id: number } | undefined;
    expect(reminted).toBeDefined();

    const plain = query.verifyChain();
    expect(plain.valid).toBe(true);

    const anchored = query.verifyChain(anchor);
    expect(anchored.valid).toBe(false);
    expect(anchored.anchor).toEqual({ lastId: anchor.lastId, status: "hmac_mismatch" });
  });

  it("reports chain break and anchor status independently (interior tamper, intact anchor)", () => {
    const ids = logRows(4);
    const anchor = takeAnchor();
    store.db.prepare("UPDATE audit_log SET success = 0 WHERE id = ?").run(ids[1]);

    const result = query.verifyChain(anchor);
    expect(result.valid).toBe(false);
    expect(result.firstBrokenId).toBe(ids[1]);
    // The anchored row itself is untouched — the two signals are independent.
    expect(result.anchor?.status).toBe("ok");
  });

  it("treats a legacy row at the anchored id as a mismatch", () => {
    logRows(2);
    const legacyId = insertLegacyRow();
    const anchor: AuditChainAnchorInput = {
      lastId: legacyId,
      rowHmac: generateRandomBytes(32),
    };
    const result = query.verifyChain(anchor);
    expect(result.valid).toBe(false);
    expect(result.anchor).toEqual({ lastId: legacyId, status: "hmac_mismatch" });
  });

  it("fails on an anchor whose id never existed", () => {
    logRows(2);
    const anchor: AuditChainAnchorInput = { lastId: 9999, rowHmac: generateRandomBytes(32) };
    const result = query.verifyChain(anchor);
    expect(result.valid).toBe(false);
    expect(result.anchor).toEqual({ lastId: 9999, status: "row_missing" });
  });

  it("leaves the anchor-less result shape unchanged", () => {
    logRows(2);
    const result = query.verifyChain();
    expect(result).toEqual({ valid: true, checked: 2, legacy: 0, firstBrokenId: null });
    expect("anchor" in result).toBe(false);
  });
});
