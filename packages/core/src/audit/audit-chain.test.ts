import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AAD_AUDIT_DETAIL, AuditEventType } from "@harpoc/shared";
import { encrypt } from "../crypto/aes-gcm.js";
import { generateRandomBytes } from "../crypto/random.js";
import { SqliteStore } from "../storage/sqlite-store.js";
import { AuditLogger } from "./audit-logger.js";
import { AuditQuery } from "./audit-query.js";

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

describe("row-bound audit detail AAD (v2)", () => {
  it("fails to decrypt a detail blob swapped to a different row", () => {
    logger.log({ eventType: AuditEventType.SECRET_READ, detail: { a: 1 } });
    logger.log({ eventType: AuditEventType.SECRET_USE, detail: { b: 2 } });

    const rows = store.db
      .prepare("SELECT id, detail_encrypted, detail_iv, detail_tag FROM audit_log ORDER BY id")
      .all() as { id: number; detail_encrypted: Buffer; detail_iv: Buffer; detail_tag: Buffer }[];

    // Swap the two rows' detail blobs (ct + iv + tag as a unit).
    store.db
      .prepare("UPDATE audit_log SET detail_encrypted=?, detail_iv=?, detail_tag=? WHERE id=?")
      .run(rows[1]?.detail_encrypted, rows[1]?.detail_iv, rows[1]?.detail_tag, rows[0]?.id);
    store.db
      .prepare("UPDATE audit_log SET detail_encrypted=?, detail_iv=?, detail_tag=? WHERE id=?")
      .run(rows[0]?.detail_encrypted, rows[0]?.detail_iv, rows[0]?.detail_tag, rows[1]?.id);

    const events = query.query();
    for (const e of events) {
      expect(e.detail).toBeNull();
      expect(e.detail_unreadable).toBe(true);
    }
  });

  it("still decrypts an untouched row (control)", () => {
    logger.log({ eventType: AuditEventType.SECRET_READ, detail: { a: 1 } });
    const events = query.query();
    expect(events[0]?.detail).toEqual({ a: 1 });
    expect(events[0]?.detail_unreadable).toBe(false);
  });

  it("marks a legacy (constant-AAD) row unreadable without breaking the listing", () => {
    // Simulate a pre-fix row written with the old constant AAD and no chain.
    const plaintext = new Uint8Array(Buffer.from(JSON.stringify({ legacy: true }), "utf8"));
    const enc = encrypt(auditKey, plaintext, AAD_AUDIT_DETAIL);
    store.db
      .prepare(
        `INSERT INTO audit_log (timestamp, event_type, secret_id, principal_type, principal_id,
           detail_encrypted, detail_iv, detail_tag, ip_address, session_id, success, row_hmac)
         VALUES (?, ?, NULL, NULL, NULL, ?, ?, ?, NULL, NULL, 1, NULL)`,
      )
      .run(
        Date.now(),
        AuditEventType.SECRET_READ,
        Buffer.from(enc.ciphertext),
        Buffer.from(enc.iv),
        Buffer.from(enc.tag),
      );
    // A normal v2 row alongside it.
    logger.log({ eventType: AuditEventType.SECRET_USE, detail: { ok: 1 } });

    const events = query.query();
    expect(events).toHaveLength(2);
    const legacy = events.find((e) => e.detail_unreadable);
    const fresh = events.find((e) => !e.detail_unreadable);
    expect(legacy?.detail).toBeNull();
    expect(fresh?.detail).toEqual({ ok: 1 });
  });
});

describe("audit HMAC chain verification", () => {
  it("verifies a clean chain", () => {
    for (let i = 0; i < 5; i++) {
      logger.log({ eventType: AuditEventType.SECRET_READ, detail: { i } });
    }
    const result = query.verifyChain();
    expect(result.valid).toBe(true);
    expect(result.checked).toBe(5);
    expect(result.legacy).toBe(0);
    expect(result.firstBrokenId).toBeNull();
  });

  it("detects a tampered plaintext column (success flipped)", () => {
    for (let i = 0; i < 3; i++) {
      logger.log({ eventType: AuditEventType.SECRET_READ, detail: { i } });
    }
    const target = store.db
      .prepare("SELECT id FROM audit_log ORDER BY id LIMIT 1 OFFSET 1")
      .get() as { id: number };
    store.db.prepare("UPDATE audit_log SET success = 0 WHERE id = ?").run(target.id);

    const result = query.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.firstBrokenId).toBe(target.id);
  });

  it("detects a deleted middle row", () => {
    const ids: number[] = [];
    for (let i = 0; i < 4; i++) {
      ids.push(logger.log({ eventType: AuditEventType.SECRET_READ, detail: { i } }));
    }
    store.db.prepare("DELETE FROM audit_log WHERE id = ?").run(ids[1]);

    const result = query.verifyChain();
    // The row after the gap expected the deleted row's link as prev → breaks there.
    expect(result.valid).toBe(false);
    expect(result.firstBrokenId).toBe(ids[2]);
  });

  it("counts legacy rows and still verifies chained rows after them", () => {
    // One unchained legacy row, then chained rows.
    store.db
      .prepare(
        `INSERT INTO audit_log (timestamp, event_type, secret_id, principal_type, principal_id,
           detail_encrypted, detail_iv, detail_tag, ip_address, session_id, success, row_hmac)
         VALUES (?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1, NULL)`,
      )
      .run(Date.now(), AuditEventType.VAULT_UNLOCK);
    logger.log({ eventType: AuditEventType.SECRET_READ, detail: { a: 1 } });
    logger.log({ eventType: AuditEventType.SECRET_USE, detail: { b: 2 } });

    const result = query.verifyChain();
    expect(result.valid).toBe(true);
    expect(result.legacy).toBe(1);
    expect(result.checked).toBe(2);
  });

  it("cross-instance writes stay linear and verify", () => {
    // Two logger instances sharing one store, interleaving writes.
    const logger2 = new AuditLogger(store, auditKey);
    logger.log({ eventType: AuditEventType.SECRET_READ, detail: { a: 1 } });
    logger2.log({ eventType: AuditEventType.SECRET_USE, detail: { b: 2 } });
    logger.log({ eventType: AuditEventType.SECRET_ROTATE, detail: { c: 3 } });

    const result = query.verifyChain();
    expect(result.valid).toBe(true);
    expect(result.checked).toBe(3);
  });

  it("reports valid with zero checks when auditing is disabled (no key)", () => {
    const keyless = new AuditLogger(store, null);
    keyless.log({ eventType: AuditEventType.SECRET_READ });
    const keylessQuery = new AuditQuery(store, null);
    const result = keylessQuery.verifyChain();
    expect(result.valid).toBe(true);
    expect(result.checked).toBe(0);
    expect(result.legacy).toBe(1);
  });
});
