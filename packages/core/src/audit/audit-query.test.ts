import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType } from "@harpoc/shared";
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

describe("AuditQuery", () => {
  it("roundtrips encrypted detail", () => {
    logger.log({
      eventType: AuditEventType.SECRET_USE,
      detail: { url: "https://api.example.com", method: "POST" },
    });

    const events = query.query();
    expect(events.length).toBe(1);
    expect(events[0]?.detail).toEqual({
      url: "https://api.example.com",
      method: "POST",
    });
  });

  it("returns null detail when auditKey is null", () => {
    logger.log({
      eventType: AuditEventType.SECRET_USE,
      detail: { test: true },
    });

    const queryNoKey = new AuditQuery(store, null);
    const events = queryNoKey.query();
    expect(events[0]?.detail).toBeNull();
  });

  it("returns null detail when no detail was stored", () => {
    logger.log({ eventType: AuditEventType.VAULT_UNLOCK });

    const events = query.query();
    expect(events[0]?.detail).toBeNull();
  });

  it("filters by secretId", () => {
    logger.log({ eventType: AuditEventType.SECRET_READ, secretId: "s1" });
    logger.log({ eventType: AuditEventType.SECRET_READ, secretId: "s2" });

    const events = query.query({ secretId: "s1" });
    expect(events.length).toBe(1);
  });

  it("filters by event type", () => {
    logger.log({ eventType: AuditEventType.VAULT_UNLOCK });
    logger.log({ eventType: AuditEventType.SECRET_CREATE });

    const events = query.query({ eventType: AuditEventType.VAULT_UNLOCK });
    expect(events.length).toBe(1);
    expect(events[0]?.event_type).toBe("vault.unlock");
  });

  it("respects limit", () => {
    for (let i = 0; i < 5; i++) {
      logger.log({ eventType: AuditEventType.SECRET_READ });
    }

    const events = query.query({ limit: 2 });
    expect(events.length).toBe(2);
  });

  it("filters by combined secretId and eventType", () => {
    logger.log({ eventType: AuditEventType.SECRET_READ, secretId: "s1" });
    logger.log({ eventType: AuditEventType.SECRET_CREATE, secretId: "s1" });
    logger.log({ eventType: AuditEventType.SECRET_READ, secretId: "s2" });

    const events = query.query({
      secretId: "s1",
      eventType: AuditEventType.SECRET_READ,
    });
    expect(events).toHaveLength(1);
    expect(events[0]?.event_type).toBe("secret.read");
    expect(events[0]?.secret_id).toBe("s1");
  });

  it("returns empty array when no events match filters", () => {
    logger.log({ eventType: AuditEventType.SECRET_READ, secretId: "s1" });

    const events = query.query({ secretId: "nonexistent" });
    expect(events).toHaveLength(0);
  });

  it("omits raw encrypted fields from result", () => {
    logger.log({
      eventType: AuditEventType.SECRET_USE,
      detail: { test: true },
    });

    const events = query.query();
    const event = events[0] as Record<string, unknown>;
    expect(event).not.toHaveProperty("detail_encrypted");
    expect(event).not.toHaveProperty("detail_iv");
    expect(event).not.toHaveProperty("detail_tag");
  });
});
