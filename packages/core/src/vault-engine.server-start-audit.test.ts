import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array) => {
      const { createHash } = await import("node:crypto");
      return new Uint8Array(createHash("sha256").update(password).update(salt).digest());
    },
  };
});

let tempDir: string;
let engine: VaultEngine;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-srvstart-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
});

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("auditServerStart (W6)", () => {
  it("writes exactly one server.start row carrying the waiver detail", () => {
    engine.auditServerStart({ transport: "stdio", tokenless: true, ttyPrompt: true });

    const rows = engine.queryAudit({ eventType: AuditEventType.SERVER_START });
    expect(rows).toHaveLength(1);
    const row = rows[0];
    expect(row?.success).toBe(true);
    expect(row?.detail?.tokenless).toBe(true);
    expect(row?.detail?.transport).toBe("stdio");
    expect(row?.detail?.tty_prompt).toBe(true);
  });

  it("defaults tty_prompt to false when the caller omits it", () => {
    engine.auditServerStart({ transport: "stdio", tokenless: true });

    const row = engine.queryAudit({ eventType: AuditEventType.SERVER_START })[0];
    expect(row?.detail?.tty_prompt).toBe(false);
  });

  it("writes a success:false row with the refusal code", () => {
    engine.auditServerStart({
      transport: "stdio",
      tokenless: false,
      success: false,
      error: ErrorCode.TOKEN_REQUIRED,
    });

    const rows = engine.queryAudit({ eventType: AuditEventType.SERVER_START });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail?.error).toBe(ErrorCode.TOKEN_REQUIRED);
    expect(rows[0]?.detail?.tokenless).toBe(false);
    expect(rows[0]?.detail?.tty_prompt).toBe(false);
  });

  it("omits the error key from a successful waiver row", () => {
    engine.auditServerStart({ transport: "stdio", tokenless: true });

    const row = engine.queryAudit({ eventType: AuditEventType.SERVER_START })[0];
    expect(row?.success).toBe(true);
    expect(row?.detail && "error" in (row.detail as object)).toBe(false);
  });

  it("keeps the row unattributed but session-stamped (D5 pin)", () => {
    engine.auditServerStart({ transport: "stdio", tokenless: true });

    const row = engine.queryAudit({ eventType: AuditEventType.SERVER_START })[0];
    // The operator at the console is the trusted local path, not a requesting
    // principal — NULL principal columns, exactly like vault.unlock.
    expect(row?.principal_type).toBeNull();
    expect(row?.principal_id).toBeNull();
    expect(row?.secret_id).toBeNull();
    expect(row?.session_id).toEqual(expect.any(String));
    // No caller exists, so no interface tag either; transport conveys the fact.
    expect(row?.detail && "interface" in (row.detail as object)).toBe(false);
  });

  it("the audit chain stays green over the new row", () => {
    engine.auditServerStart({ transport: "stdio", tokenless: true });

    const report = engine.verifyAuditChain();
    expect(report.firstBrokenId).toBeNull();
    expect(report.valid).toBe(true);
  });

  it("an exported anchor taken after the row still verifies", () => {
    engine.auditServerStart({ transport: "stdio", tokenless: true });
    const anchor = engine.getAuditChainTail();
    expect(anchor).not.toBeNull();

    const report = engine.verifyAuditChain({ anchor: anchor ?? undefined });
    expect(report.valid).toBe(true);
    expect(report.anchor?.status).toBe("ok");
  });

  it("refuses on a sealed vault", async () => {
    await engine.lock();

    expect(() => engine.auditServerStart({ transport: "stdio", tokenless: true })).toThrow(
      expect.objectContaining({ code: ErrorCode.VAULT_LOCKED }),
    );
  });

  it("propagates a failed audit write instead of swallowing it (D4 fail-closed)", () => {
    const store = (engine as unknown as { store: { insertAuditEvent: () => number } }).store;
    const original = store.insertAuditEvent;
    store.insertAuditEvent = () => {
      throw new Error("audit log unwritable");
    };

    try {
      expect(() => engine.auditServerStart({ transport: "stdio", tokenless: true })).toThrow(
        "audit log unwritable",
      );
    } finally {
      store.insertAuditEvent = original;
    }
  });
});

describe("auditServerStart on every transport (R4/B22)", () => {
  it("a token-bearing stdio start writes tokenless: false with the subject, unattributed", () => {
    engine.auditServerStart({
      transport: "stdio",
      tokenless: false,
      subject: "agent-1",
    });
    const rows = engine.queryAudit({ eventType: AuditEventType.SERVER_START });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(true);
    expect(rows[0]?.principal_type).toBeNull();
    expect(rows[0]?.detail).toEqual({
      transport: "stdio",
      tokenless: false,
      tty_prompt: false,
      subject: "agent-1",
    });
  });

  it("a listener start carries its transport, port and host", () => {
    engine.auditServerStart({
      transport: "http",
      tokenless: false,
      port: 3001,
      host: "127.0.0.1",
    });
    engine.auditServerStart({
      transport: "rest",
      tokenless: false,
      port: 3000,
      host: "::1",
    });
    const byTransport = new Map(
      engine
        .queryAudit({ eventType: AuditEventType.SERVER_START })
        .map((r) => [r.detail?.transport, r.detail]),
    );
    expect(byTransport.get("http")).toEqual({
      transport: "http",
      tokenless: false,
      tty_prompt: false,
      port: 3001,
      host: "127.0.0.1",
    });
    expect(byTransport.get("rest")).toEqual({
      transport: "rest",
      tokenless: false,
      tty_prompt: false,
      port: 3000,
      host: "::1",
    });
  });

  it("the waiver row keeps its exact shape", () => {
    engine.auditServerStart({
      transport: "stdio",
      tokenless: true,
      ttyPrompt: true,
    });
    const [row] = engine.queryAudit({ eventType: AuditEventType.SERVER_START });
    expect(row?.detail).toEqual({
      transport: "stdio",
      tokenless: true,
      tty_prompt: true,
    });
  });
});

describe("auditServerStop (R4/D67)", () => {
  it("writes an unattributed server.stop row after the start, chain intact", () => {
    engine.auditServerStart({
      transport: "http",
      tokenless: false,
      port: 3001,
      host: "127.0.0.1",
    });
    engine.auditServerStop({
      transport: "http",
      tokenless: false,
      port: 3001,
      uptimeMs: 1234,
      trigger: "SIGTERM",
    });
    const [start] = engine.queryAudit({
      eventType: AuditEventType.SERVER_START,
    });
    const stops = engine.queryAudit({ eventType: AuditEventType.SERVER_STOP });
    expect(stops).toHaveLength(1);
    expect(stops[0]?.success).toBe(true);
    expect(stops[0]?.principal_type).toBeNull();
    expect(stops[0]?.detail).toEqual({
      transport: "http",
      tokenless: false,
      port: 3001,
      uptime_ms: 1234,
      trigger: "SIGTERM",
    });
    expect(stops[0]?.id).toBeGreaterThan(start?.id ?? Number.MAX_SAFE_INTEGER);
    expect(engine.verifyAuditChain().valid).toBe(true);
  });

  it("omits port for the stdio server", () => {
    engine.auditServerStop({
      transport: "stdio",
      tokenless: true,
      uptimeMs: 10,
      trigger: "transport_closed",
    });
    const [row] = engine.queryAudit({ eventType: AuditEventType.SERVER_STOP });
    expect(row?.detail).toEqual({
      transport: "stdio",
      tokenless: true,
      uptime_ms: 10,
      trigger: "transport_closed",
    });
  });

  it("refuses on a sealed vault — the callers make it best-effort", async () => {
    await engine.lock();
    expect(() =>
      engine.auditServerStop({
        transport: "stdio",
        tokenless: true,
        uptimeMs: 1,
        trigger: "SIGINT",
      }),
    ).toThrow(expect.objectContaining({ code: ErrorCode.VAULT_LOCKED }));
  });
});
