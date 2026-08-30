import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import { encrypt } from "../crypto/aes-gcm.js";
import { generateRandomBytes } from "../crypto/random.js";
import { SqliteStore } from "../storage/sqlite-store.js";
import { AuditLogger } from "./audit-logger.js";
import { AuditQuery } from "./audit-query.js";
import { dropAuditRowHmacConstraint } from "@harpoc/test-utils";

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

  it("marks a tampered or mis-bound detail blob unreadable without breaking the listing", () => {
    // A blob encrypted under an AAD that is not the row's v2 AAD — a moved or tampered row.
    const plaintext = new Uint8Array(Buffer.from(JSON.stringify({ misbound: true }), "utf8"));
    const enc = encrypt(auditKey, plaintext, "harpoc:audit-detail:mis-bound");
    store.db
      .prepare(
        `INSERT INTO audit_log (timestamp, event_type, secret_id, principal_type, principal_id,
           detail_encrypted, detail_iv, detail_tag, ip_address, session_id, success, row_hmac)
         VALUES (?, ?, NULL, NULL, NULL, ?, ?, ?, NULL, NULL, 1, ?)`,
      )
      .run(
        Date.now(),
        AuditEventType.SECRET_READ,
        Buffer.from(enc.ciphertext),
        Buffer.from(enc.iv),
        Buffer.from(enc.tag),
        Buffer.from(generateRandomBytes(32)),
      );
    // A normal v2 row alongside it.
    logger.log({ eventType: AuditEventType.SECRET_USE, detail: { ok: 1 } });

    const events = query.query();
    expect(events).toHaveLength(2);
    const misbound = events.find((e) => e.detail_unreadable);
    const fresh = events.find((e) => !e.detail_unreadable);
    expect(misbound?.detail).toBeNull();
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

  it("a NULL link ahead of the first chained row is a break, not history", () => {
    dropAuditRowHmacConstraint(store.db);
    const legacyId = Number(
      store.db
        .prepare(
          `INSERT INTO audit_log (timestamp, event_type, secret_id, principal_type, principal_id,
             detail_encrypted, detail_iv, detail_tag, ip_address, session_id, success, row_hmac)
           VALUES (?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1, NULL)`,
        )
        .run(Date.now(), AuditEventType.VAULT_UNLOCK).lastInsertRowid,
    );
    logger.log({ eventType: AuditEventType.SECRET_READ, detail: { a: 1 } });
    logger.log({ eventType: AuditEventType.SECRET_USE, detail: { b: 2 } });

    const result = query.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.firstBrokenId).toBe(legacyId);
    expect(result.checked).toBe(2);
    expect("legacy" in result).toBe(false);
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
});

/**
 * M2. `row_hmac IS NULL` marked a pre-migration-010 row, which verification
 * counted and skipped. Nothing enforced that such rows may only be a PREFIX, so
 * a database-writing attacker (the exact adversary the chain exists for — they
 * hold no audit key) could null the column on any suffix and then insert,
 * delete and edit those rows with `harpoc audit verify` reporting OK.
 * Since Wave 2 (C30) a NULL link anywhere — prefix included — is a break.
 * Since v1.5 (R2) the column is NOT NULL, so these cases first rebuild the
 * table without the constraint — the attacker's own move — while the
 * describe below pins that the shipped table refuses the write.
 */
describe("audit chain: NULL links are not a free pass", () => {
  beforeEach(() => {
    dropAuditRowHmacConstraint(store.db);
  });

  function nullLinks(fromId: number): void {
    store.db.prepare("UPDATE audit_log SET row_hmac = NULL WHERE id >= ?").run(fromId);
  }

  it("pins the vulnerability: nulling a suffix then rewriting it is detected", () => {
    const ids: number[] = [];
    for (let i = 0; i < 5; i++) {
      ids.push(logger.log({ eventType: AuditEventType.SECRET_READ, detail: { i } }));
    }
    const from = ids[2] as number;
    nullLinks(from);
    // With the links gone the attacker edits the plaintext columns freely.
    store.db.prepare("UPDATE audit_log SET success = 0 WHERE id >= ?").run(from);
    store.db.prepare("DELETE FROM audit_log WHERE id = ?").run(ids[4]);

    const result = query.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.firstBrokenId).toBe(from);
  });

  it("detects a single nulled link in the middle of the chain", () => {
    const ids: number[] = [];
    for (let i = 0; i < 3; i++) {
      ids.push(logger.log({ eventType: AuditEventType.SECRET_READ, detail: { i } }));
    }
    store.db.prepare("UPDATE audit_log SET row_hmac = NULL WHERE id = ?").run(ids[1]);

    const result = query.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.firstBrokenId).toBe(ids[1]);
  });

  it("detects a nulled tail (the whole log after the first row)", () => {
    const ids: number[] = [];
    for (let i = 0; i < 3; i++) {
      ids.push(logger.log({ eventType: AuditEventType.SECRET_READ, detail: { i } }));
    }
    nullLinks(ids[1] as number);

    const result = query.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.firstBrokenId).toBe(ids[1]);
  });

  it("detects a wholly nulled log, which the prefix rule alone would allow", () => {
    const ids: number[] = [];
    for (let i = 0; i < 3; i++) {
      ids.push(logger.log({ eventType: AuditEventType.SECRET_READ, detail: { i } }));
    }
    nullLinks(ids[0] as number);

    const result = query.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.checked).toBe(0);
    expect(result.firstBrokenId).toBe(ids[0]);
  });

  it("control: an empty log and an untampered chain stay valid", () => {
    expect(query.verifyChain()).toEqual({
      valid: true,
      checked: 0,
      firstBrokenId: null,
    });

    logger.log({ eventType: AuditEventType.SECRET_READ, detail: { a: 1 } });
    logger.log({ eventType: AuditEventType.SECRET_USE, detail: { b: 2 } });
    expect(query.verifyChain().valid).toBe(true);
  });
});

describe("audit chain: the v1.5 table refuses an erased link (R2)", () => {
  function sqliteCode(run: () => void): string | undefined {
    let caught: unknown;
    try {
      run();
    } catch (err) {
      caught = err;
    }
    return (caught as { code?: string } | undefined)?.code;
  }

  it("UPDATE … SET row_hmac = NULL fails on the constraint and the chain stays valid", () => {
    const id = logger.log({ eventType: AuditEventType.SECRET_READ, detail: { a: 1 } });
    expect(
      sqliteCode(() =>
        store.db.prepare("UPDATE audit_log SET row_hmac = NULL WHERE id = ?").run(id),
      ),
    ).toBe("SQLITE_CONSTRAINT_NOTNULL");
    expect(query.verifyChain()).toEqual({ valid: true, checked: 1, firstBrokenId: null });
  });

  it("a link-less INSERT fails on the constraint", () => {
    expect(
      sqliteCode(() =>
        store.db
          .prepare(
            `INSERT INTO audit_log (timestamp, event_type, secret_id, principal_type, principal_id,
               detail_encrypted, detail_iv, detail_tag, ip_address, session_id, success, row_hmac)
             VALUES (?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1, NULL)`,
          )
          .run(Date.now(), AuditEventType.VAULT_UNLOCK),
      ),
    ).toBe("SQLITE_CONSTRAINT_NOTNULL");
  });

  it("compile-time pin: the store requires a link", () => {
    const eventRow = {
      timestamp: Date.now(),
      event_type: AuditEventType.VAULT_UNLOCK,
      secret_id: null,
      principal_type: null,
      principal_id: null,
      detail_encrypted: null,
      detail_iv: null,
      detail_tag: null,
      ip_address: null,
      session_id: null,
      success: true,
    };
    // @ts-expect-error — a link-less insert no longer typechecks (R2)
    const call = (): number => store.insertAuditEvent(eventRow);
    expect(typeof call).toBe("function");
  });
});
