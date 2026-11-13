import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, PrincipalType } from "@harpoc/shared";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";
import type { VaultEngineOptions } from "./vault-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-ve-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
});

// Every engine a case opens beside `engine` is destroyed here, on the failure
// path too, before its directory is removed (an open store is EBUSY on win32).
const secondEngines: VaultEngine[] = [];
function secondEngine(options: VaultEngineOptions): VaultEngine {
  const opened = new VaultEngine(options);
  secondEngines.push(opened);
  return opened;
}

afterEach(async () => {
  for (const opened of secondEngines.splice(0)) await opened.destroy();
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("audit-chain anchor (tail truncation)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "anchored",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
  });

  it("exports the tail as a complete anchor whose hex hmac matches the stored link", () => {
    const anchor = engine.getAuditChainTail();
    expect(anchor).not.toBeNull();
    expect(anchor?.format).toBe("harpoc-audit-anchor/1");
    expect(anchor?.vault_id).toBeTruthy();
    expect(anchor?.row_hmac).toMatch(/^[0-9a-f]{64}$/);

    const db = new Database(dbPath);
    const row = db.prepare("SELECT id, row_hmac FROM audit_log ORDER BY id DESC LIMIT 1").get() as {
      id: number;
      row_hmac: Buffer;
    };
    db.close();
    expect(anchor?.last_id).toBe(row.id);
    expect(anchor?.row_hmac).toBe(row.row_hmac.toString("hex"));
  });

  function newestRowId(): number {
    const db = new Database(dbPath);
    const row = db.prepare("SELECT MAX(id) AS id FROM audit_log").get() as { id: number };
    db.close();
    return row.id;
  }

  it("verifies against its own fresh anchor and after appends, always reporting the tail", async () => {
    const anchor = engine.getAuditChainTail();
    expect(anchor).not.toBeNull();

    const fresh = engine.verifyAuditChain({ anchor: anchor ?? undefined });
    expect(fresh.valid).toBe(true);
    expect(fresh.anchor?.status).toBe("ok");
    expect(fresh.tail?.last_id).toBe(newestRowId());

    await engine.createSecret({
      name: "later",
      type: "api_key",
      value: new Uint8Array(Buffer.from("w")),
    });
    const appended = engine.verifyAuditChain({ anchor: anchor ?? undefined });
    expect(appended.valid).toBe(true);
    expect(appended.anchor?.status).toBe("ok");
    expect(appended.tail?.last_id).toBeGreaterThan(anchor?.last_id ?? Infinity);

    const plain = engine.verifyAuditChain();
    expect(plain.anchor).toBeUndefined();
    expect(plain.tail?.last_id).toBe(newestRowId());
  });

  it("detects tail truncation the plain verify cannot see", async () => {
    const anchor = engine.getAuditChainTail();
    await engine.createSecret({
      name: "victim",
      type: "api_key",
      value: new Uint8Array(Buffer.from("x")),
    });
    const later = engine.getAuditChainTail();

    // Attacker deletes everything after the first anchor — including `later`'s rows.
    const db = new Database(dbPath);
    db.prepare("DELETE FROM audit_log WHERE id > ?").run(anchor?.last_id ?? 0);
    db.close();

    const plain = engine.verifyAuditChain();
    expect(plain.valid).toBe(true);

    const oldAnchorResult = engine.verifyAuditChain({ anchor: anchor ?? undefined });
    expect(oldAnchorResult.valid).toBe(true);

    const newAnchorResult = engine.verifyAuditChain({ anchor: later ?? undefined });
    expect(newAnchorResult.valid).toBe(false);
    expect(newAnchorResult.anchor?.status).toBe("row_missing");
  });

  it("rejects an anchor taken from a different vault before touching any rows", async () => {
    const anchor = engine.getAuditChainTail();
    expect(anchor).not.toBeNull();
    const foreign = { ...(anchor as NonNullable<typeof anchor>), vault_id: "someone-elses-vault" };
    const err = await expectVaultError(
      () => engine.verifyAuditChain({ anchor: foreign }),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toContain("different vault");
  });
});

describe("audit trail", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("logs vault unlock event", () => {
    const events = engine.queryAudit({ eventType: AuditEventType.VAULT_UNLOCK });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      success: true,
      secret_id: null,
      principal_type: null,
      session_id: expect.any(String),
    });
  });

  it("logs secret creation", async () => {
    await engine.createSecret({
      name: "audit-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.handle).toBe("secret://audit-test");
  });

  it("logs getSecretValue with action: get_value", async () => {
    await engine.createSecret({
      name: "audit-getval",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await engine.getSecretValue("secret://audit-getval");

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_READ });
    const getValEvents = events.filter((e) => e.detail?.action === "get_value");
    expect(getValEvents.length).toBe(1);
    expect(getValEvents[0]?.detail?.handle).toBe("secret://audit-getval");
  });
});

describe("audit trail for denied access and lazy expiry", () => {
  const VALUE = new Uint8Array(Buffer.from("v"));

  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("emits secret.expire exactly once on the lazy-expiry transition", async () => {
    await engine.createSecret({
      name: "exp-once",
      type: "api_key",
      value: VALUE,
      expiresAt: Date.now() - 1000,
    });

    await expect(engine.getSecretValue("secret://exp-once")).rejects.toMatchObject({
      code: ErrorCode.SECRET_EXPIRED,
    });
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE })).toHaveLength(1);

    // A second denied read is not a new transition — no second expire event.
    await expect(engine.getSecretValue("secret://exp-once")).rejects.toMatchObject({
      code: ErrorCode.SECRET_EXPIRED,
    });
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE })).toHaveLength(1);
  });

  it("logs a denied read of an expired secret with success=false", async () => {
    await engine.createSecret({
      name: "exp-read",
      type: "api_key",
      value: VALUE,
      expiresAt: Date.now() - 1000,
    });

    await expectVaultError(
      () => engine.getSecretValue("secret://exp-read"),
      ErrorCode.SECRET_EXPIRED,
    );

    const denied = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((e) => !e.success);
    expect(denied).toHaveLength(1);
    expect(denied[0]?.detail?.error).toBe(ErrorCode.SECRET_EXPIRED);
    expect(denied[0]?.detail?.handle).toBe("secret://exp-read");
  });

  it("logs denied rotate and revoke of a revoked secret with success=false", async () => {
    await engine.createSecret({ name: "rev-mut", type: "api_key", value: VALUE });
    await engine.revokeSecret("secret://rev-mut");

    await expect(engine.rotateSecret("secret://rev-mut", VALUE)).rejects.toMatchObject({
      code: ErrorCode.SECRET_REVOKED,
    });
    await expect(engine.revokeSecret("secret://rev-mut")).rejects.toMatchObject({
      code: ErrorCode.SECRET_REVOKED,
    });

    const rotates = engine
      .queryAudit({ eventType: AuditEventType.SECRET_ROTATE })
      .filter((e) => !e.success);
    expect(rotates).toHaveLength(1);
    expect(rotates[0]?.detail?.error).toBe(ErrorCode.SECRET_REVOKED);

    const revokes = engine
      .queryAudit({ eventType: AuditEventType.SECRET_REVOKE })
      .filter((e) => !e.success);
    expect(revokes).toHaveLength(1);
    expect(revokes[0]?.detail?.error).toBe(ErrorCode.SECRET_REVOKED);
  });

  it("logs a denied useSecret value resolution with success=false", async () => {
    await engine.createSecret({ name: "use-denied", type: "api_key", value: VALUE });
    await engine.revokeSecret("secret://use-denied");

    await expect(
      engine.useSecret("secret://use-denied", {
        type: "http",
        method: "GET",
        url: "https://api.example.com/x",
        injection: { type: "bearer" },
      }),
    ).rejects.toMatchObject({ code: ErrorCode.SECRET_REVOKED });

    const denied = engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .filter((e) => !e.success);
    expect(denied).toHaveLength(1);
    expect(denied[0]?.detail?.error).toBe(ErrorCode.SECRET_REVOKED);
    expect(denied[0]?.detail?.context).toBe("http");
  });

  it("logs a probe of a nonexistent secret with success=false", async () => {
    await expect(engine.getSecretValue("secret://no-such-secret")).rejects.toMatchObject({
      code: ErrorCode.SECRET_NOT_FOUND,
    });

    const denied = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((e) => !e.success);
    expect(denied).toHaveLength(1);
    expect(denied[0]?.detail?.error).toBe(ErrorCode.SECRET_NOT_FOUND);
  });

  it("successful operations still log success=true only", async () => {
    await engine.createSecret({ name: "ok-secret", type: "api_key", value: VALUE });
    await engine.getSecretValue("secret://ok-secret");

    const reads = engine.queryAudit({ eventType: AuditEventType.SECRET_READ });
    expect(reads.filter((e) => !e.success)).toHaveLength(0);
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE })).toHaveLength(0);
  });
});

describe("audit trail completeness", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    registerAgents(engine, "agent-1");
  });

  it("logs secret rotation", async () => {
    await engine.createSecret({
      name: "rot-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("old")),
    });

    await engine.rotateSecret("secret://rot-audit", new Uint8Array(Buffer.from("new")));

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_ROTATE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.handle).toBe("secret://rot-audit");
  });

  it("logs secret revocation", async () => {
    await engine.createSecret({
      name: "rev-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await engine.revokeSecret("secret://rev-audit");

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_REVOKE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.handle).toBe("secret://rev-audit");
  });

  it("logs set_value on pending secret", async () => {
    await engine.createSecret({ name: "pending-audit", type: "api_key" });
    await engine.setSecretValue("secret://pending-audit", new Uint8Array(Buffer.from("val")));

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    const setValueEvents = events.filter((e) => e.detail?.action === "set_value");
    expect(setValueEvents.length).toBe(1);
    expect(setValueEvents[0]?.detail?.handle).toBe("secret://pending-audit");
  });

  it("logs vault lock", async () => {
    await engine.lock();

    // Need a new engine to query audit (current engine is sealed)
    const engine2 = secondEngine({ dbPath, sessionPath });
    await engine2.unlock("password");

    const events = engine2.queryAudit({ eventType: AuditEventType.VAULT_LOCK });
    expect(events.length).toBe(1);

    await engine2.destroy();
  });

  it("attributes a caller's lock to its principal, peer and interface; the trusted lock keeps NULL columns", async () => {
    const caller: CallerContext = {
      principal_type: "agent",
      principal_id: "agent-1",
      interface: "rest",
      remote_address: "127.0.0.1",
      admin_scope: true,
    };
    await engine.lock(caller);

    const relocker = secondEngine({ dbPath, sessionPath });
    await relocker.unlock("password");
    await relocker.lock();

    const reader = secondEngine({ dbPath, sessionPath });
    await reader.unlock("password");
    const [trusted, remote] = reader.queryAudit({ eventType: AuditEventType.VAULT_LOCK });
    expect(remote).toMatchObject({
      secret_id: null,
      principal_type: "agent",
      principal_id: "agent-1",
      ip_address: "127.0.0.1",
      success: true,
    });
    expect(remote?.detail).toEqual({ interface: "rest" });
    expect(trusted).toMatchObject({
      principal_type: null,
      principal_id: null,
      ip_address: null,
      success: true,
      detail: null,
    });
  });

  it("logs password change", async () => {
    await engine.changePassword("password", "new-password");

    const events = engine.queryAudit({ eventType: AuditEventType.VAULT_PASSWORD_CHANGE });
    expect(events.length).toBe(1);
  });

  it("logs policy grant", async () => {
    await engine.createSecret({
      name: "pol-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const secretId = await engine.resolveSecretId("secret://pol-audit");

    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "agent-1", permissions: ["read"] },
      "admin",
    );

    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.principal).toBe("agent:agent-1");
  });

  it("logs policy revocation", async () => {
    await engine.createSecret({
      name: "pol-rev-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const secretId = await engine.resolveSecretId("secret://pol-rev-audit");

    const policy = engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "agent-1", permissions: ["read"] },
      "admin",
    );

    engine.revokePolicy(policy.id);

    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_REVOKE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.policy_id).toBe(policy.id);
  });
});

describe("the trail's own reads write their vault.read row (A3)", () => {
  const VALUE = new Uint8Array(Buffer.from("v"));
  const READER: CallerContext = {
    principal_type: "agent",
    principal_id: "agent-1",
    interface: "rest",
    remote_address: "127.0.0.1",
    admin_scope: true,
    project: "finance",
  };
  const UNSCOPED: CallerContext = {
    principal_type: "user",
    principal_id: "admin-1",
    interface: "rest",
    admin_scope: true,
  };

  function liveStore(): SqliteStore {
    return (engine as unknown as { store: SqliteStore }).store;
  }

  function rowCount(): number {
    const row = liveStore().db.prepare("SELECT COUNT(*) AS count FROM audit_log").get() as {
      count: number;
    };
    return row.count;
  }

  function failNextAuditInsert(): void {
    vi.spyOn(liveStore(), "insertAuditEvent").mockImplementationOnce(() => {
      throw new Error("audit unavailable");
    });
  }

  beforeEach(async () => {
    await engine.initVault("password");
    for (const name of ["ledger", "payroll", "invoices", "budget", "forecast"]) {
      await engine.createSecret({ name, type: "api_key", project: "finance", value: VALUE });
    }
    await engine.createSecret({ name: "db-prod", type: "api_key", value: VALUE });
  });

  it("queryAudit writes one row after the read: vault.read, the caller's principal, operation, count and limit; the page does not hold it", () => {
    const before = rowCount();

    const page = engine.queryAudit({ limit: 5 }, { project: "finance" }, READER);

    expect(page).toHaveLength(5);
    expect(rowCount()).toBe(before + 1);
    const [row] = engine.queryAudit({ eventType: AuditEventType.VAULT_READ });
    expect(row).toMatchObject({
      event_type: AuditEventType.VAULT_READ,
      secret_id: null,
      principal_type: "agent",
      principal_id: "agent-1",
      ip_address: "127.0.0.1",
      success: true,
    });
    expect(row?.detail).toEqual({
      operation: "audit_query",
      count: 5,
      limit: 5,
      interface: "rest",
    });
  });

  it("a principal-id filter is recorded as its presence: principal_id true, the filter text in no part of the detail", () => {
    const FILTER = "payroll-reader";

    const page = engine.queryAudit(
      { principalType: "agent", principalId: FILTER },
      undefined,
      READER,
    );

    const [row] = engine.queryAudit({ eventType: AuditEventType.VAULT_READ });
    expect(row?.detail).toEqual({
      operation: "audit_query",
      principal_type: "agent",
      principal_id: true,
      count: page.length,
      interface: "rest",
    });
    expect(JSON.stringify(row?.detail).includes(FILTER)).toBe(false);
  });

  it("an event type or principal type outside its vocabulary is recorded by its presence, the typed text in no part of the detail", () => {
    const TYPED = {
      eventType: "ledger-owner",
      excludeEventType: "payroll-run",
      principalType: "budget-bot",
    };

    const page = engine.queryAudit(
      {
        eventType: TYPED.eventType as AuditEventType,
        excludeEventType: TYPED.excludeEventType as AuditEventType,
        principalType: TYPED.principalType as PrincipalType,
      },
      undefined,
      READER,
    );

    const [row] = engine.queryAudit({ eventType: AuditEventType.VAULT_READ });
    expect(row?.detail).toEqual({
      operation: "audit_query",
      event_type: true,
      exclude_event_type: true,
      principal_type: true,
      count: page.length,
      interface: "rest",
    });
    for (const text of Object.values(TYPED)) {
      expect(JSON.stringify(row?.detail).includes(text)).toBe(false);
    }
  });

  it("every filter set: the closed vocabulary verbatim, the others by their presence, the secret id in no part of the detail", async () => {
    const secretId = await engine.resolveSecretId("secret://finance/ledger");

    const page = engine.queryAudit(
      {
        secretId,
        eventType: AuditEventType.SECRET_CREATE,
        excludeEventType: AuditEventType.VAULT_READ,
        principalType: "agent",
        principalId: "payroll-reader",
        since: 1,
        until: Date.now() + 60_000,
        success: false,
        limit: 3,
      },
      undefined,
      READER,
    );

    const [row] = engine.queryAudit({ eventType: AuditEventType.VAULT_READ });
    expect(row?.detail).toEqual({
      operation: "audit_query",
      event_type: "secret.create",
      exclude_event_type: "vault.read",
      principal_type: "agent",
      principal_id: true,
      secret_id: true,
      since: true,
      until: true,
      success: false,
      limit: 3,
      count: page.length,
      interface: "rest",
    });
    expect(JSON.stringify(row?.detail).includes(secretId)).toBe(false);
  });

  it("verifyAuditChain writes audit_verify before the walk: checked counts it, the tail is that row, no audit_anchor row", () => {
    const before = rowCount();

    const report = engine.verifyAuditChain(undefined, READER);

    expect(rowCount()).toBe(before + 1);
    expect(report.valid).toBe(true);
    expect(report.checked).toBe(before + 1);
    const [row] = engine.queryAudit({ eventType: AuditEventType.VAULT_READ });
    expect(row).toMatchObject({
      principal_type: "agent",
      principal_id: "agent-1",
      ip_address: "127.0.0.1",
    });
    expect(row?.detail).toEqual({ operation: "audit_verify", interface: "rest" });
    expect(report.tail?.last_id).toBe(row?.id);
  });

  it("getAuditChainTail writes audit_anchor before it reads the tail: the anchor is that row", () => {
    const before = rowCount();

    const anchor = engine.getAuditChainTail(READER);

    expect(rowCount()).toBe(before + 1);
    const [row] = engine.queryAudit({ eventType: AuditEventType.VAULT_READ });
    expect(row?.detail).toEqual({ operation: "audit_anchor", interface: "rest" });
    expect(anchor?.last_id).toBe(row?.id);
    expect(engine.verifyAuditChain({ anchor: anchor ?? undefined }).anchor?.status).toBe("ok");
  });

  it("the trusted path writes each row with NULL principal columns and no interface key", () => {
    engine.queryAudit({ limit: 1 });
    engine.verifyAuditChain();
    engine.getAuditChainTail();

    const rows = engine.queryAudit({ eventType: AuditEventType.VAULT_READ });
    expect(rows.map((r) => [r.principal_type, r.principal_id, r.ip_address, r.detail])).toEqual([
      [null, null, null, { operation: "audit_anchor" }],
      [null, null, null, { operation: "audit_verify" }],
      [null, null, null, { operation: "audit_query", count: 1, limit: 1 }],
    ]);
  });

  it.each([
    ["queryAudit", () => engine.queryAudit({ limit: 5 }, undefined, READER)],
    ["verifyAuditChain", () => engine.verifyAuditChain(undefined, READER)],
    ["getAuditChainTail", () => engine.getAuditChainTail(READER)],
  ])(
    "%s throws the logger's error and returns nothing when its row cannot be written",
    (_read, read) => {
      const before = rowCount();
      failNextAuditInsert();

      let answer: unknown;
      expect(() => {
        answer = read();
      }).toThrow("audit unavailable");
      expect(answer).toBeUndefined();
      expect(rowCount()).toBe(before);
    },
  );

  it("a foreign anchor is refused INVALID_INPUT before the row: the refusal writes none (U-7)", async () => {
    const anchor = engine.getAuditChainTail(READER);
    const foreign = { ...(anchor as NonNullable<typeof anchor>), vault_id: "someone-elses-vault" };
    const before = rowCount();

    await expectVaultError(
      () => engine.verifyAuditChain({ anchor: foreign }, READER),
      ErrorCode.INVALID_INPUT,
    );
    expect(rowCount()).toBe(before);
  });

  it("a scoped reader sees no vault.read row, another reader's or its own, while the unscoped reader's next page holds them (A-2)", () => {
    engine.queryAudit({}, undefined, UNSCOPED);
    const nameReader: CallerContext = {
      principal_type: "agent",
      principal_id: "agent-2",
      interface: "rest",
      admin_scope: true,
    };

    const pages = [
      engine.queryAudit({}, { project: "finance" }, READER),
      engine.queryAudit({}, { secrets: ["db-*"] }, nameReader),
      engine.queryAudit({}, { project: "finance" }, READER),
    ];

    for (const page of pages) {
      expect(page.length).toBeGreaterThan(0);
      expect(page.filter((r) => r.event_type === AuditEventType.VAULT_READ)).toEqual([]);
    }
    const reads = engine.queryAudit({ eventType: AuditEventType.VAULT_READ }, undefined, UNSCOPED);
    expect(reads.map((r) => r.principal_id)).toEqual(["agent-1", "agent-2", "agent-1", "admin-1"]);
    expect(JSON.stringify(reads.map((r) => r.detail)).includes("db-")).toBe(false);
    expect(JSON.stringify(reads.map((r) => r.detail)).includes("finance")).toBe(false);
  });
});
