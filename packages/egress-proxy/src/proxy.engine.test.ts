import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { VaultEngine } from "@harpoc/core";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { createEgressProxy } from "./proxy.js";
import type { EgressProxy, ProxyEngine } from "./proxy.js";
import { proxyRequest } from "./__fixtures__/proxy-client.js";
import type { ProxyReply } from "./__fixtures__/proxy-client.js";
import {
  CAN_SET_DEFAULT_CA,
  startUpstream,
  trustFixtureCaByDefault,
} from "./__fixtures__/upstream-server.js";
import type { UpstreamFixture } from "./__fixtures__/upstream-server.js";

// Mock argon2 for speed (oauth-proxy's real-engine suites, the same stub).
vi.mock("argon2", () => ({
  hash: async (password: Buffer | string, opts: { salt: Buffer | Uint8Array }) => {
    const { createHash } = await import("node:crypto");
    const salt = opts.salt instanceof Uint8Array ? Buffer.from(opts.salt) : opts.salt;
    return createHash("sha256")
      .update(typeof password === "string" ? password : Buffer.from(password))
      .update(salt)
      .digest();
  },
}));

let upstream: UpstreamFixture;
let tempDir: string;
let engine: VaultEngine;
let resolveForProxy: Mock<ProxyEngine["resolveForProxy"]>;
let proxy: EgressProxy;
let port: number;

beforeAll(async () => {
  upstream = await startUpstream();
});

afterAll(async () => {
  await upstream.close();
});

beforeEach(async () => {
  upstream.seen.length = 0;
  tempDir = join(
    tmpdir(),
    `harpoc-egress-proxy-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  engine.registerAgent({ name: "agent-a" });
  resolveForProxy = vi.fn<ProxyEngine["resolveForProxy"]>();
  // The real engine behind the four members; resolveForProxy is the engine
  // lane's, so these rows reach it only to prove they never do.
  const proxyEngine: ProxyEngine = {
    verifyToken: (token) => engine.verifyToken(token),
    auditScopeRefusal: (caller, operation, reason) =>
      engine.auditScopeRefusal(caller, operation, reason),
    auditServerStart: (options) => engine.auditServerStart(options),
    resolveForProxy,
  };
  proxy = createEgressProxy({ engine: proxyEngine });
  port = (await proxy.listenTcp(0, "127.0.0.1")).port;
});

afterEach(async () => {
  try {
    await proxy?.close();
    await engine?.destroy();
  } finally {
    rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

function send(token: string, headers: Record<string, string> = {}): Promise<ProxyReply> {
  return proxyRequest({
    port,
    path: `/127.0.0.1:${upstream.port}/user`,
    headers: { "proxy-authorization": `Bearer ${token}`, ...headers },
  });
}

interface SqliteHandle {
  prepare(sql: string): { get(...params: unknown[]): unknown };
}

/** The number of audit rows whose type is not `vault.read`, counted in the engine's store. */
function nonReadAuditCount(of: VaultEngine): number {
  const { db } = (of as unknown as { store: { db: SqliteHandle } }).store;
  const row = db
    .prepare("SELECT COUNT(*) AS count FROM audit_log WHERE event_type != ?")
    .get(AuditEventType.VAULT_READ) as { count: number };
  return row.count;
}

// A pass-through has no CA pin: the fixture CA joins the default store, which
// tls.setDefaultCACertificates needs (Node >= 22.19 / 24.5).
describe.skipIf(!CAN_SET_DEFAULT_CA)("a pass-through against a real engine", () => {
  let restore: () => void;

  beforeAll(() => {
    restore = trustFixtureCaByDefault();
  });

  afterAll(() => {
    restore();
  });

  it("a live use token passes a request through; the engine writes no secret.use row", async () => {
    const token = engine.createToken("agent-a", ["use"]);
    const reply = await send(token);

    expect(reply.status).toBe(200);
    expect(upstream.seen).toHaveLength(1);
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_USE })).toHaveLength(0);
  });
});

describe("the proxy against a real engine", () => {
  it.each([
    ["an expired token", "expired", 401, ErrorCode.TOKEN_EXPIRED],
    ["a revoked token", "revoked", 401, ErrorCode.TOKEN_REVOKED],
    ["a malformed token", "malformed", 401, ErrorCode.INVALID_TOKEN],
  ])("%s (%s) is %i %s and writes no audit row", async (_title, kind, status, code) => {
    let token = "not-a-jwt";
    if (kind === "expired") token = engine.createToken("agent-a", ["use"], 0);
    if (kind === "revoked") {
      token = engine.createToken("agent-a", ["use"]);
      engine.revokeToken(engine.verifyToken(token).jti);
    }
    const rowsBefore = nonReadAuditCount(engine);

    const reply = await send(token, { authorization: "Bearer harpoc:gh-pat" });

    expect(reply.status).toBe(status);
    expect(JSON.parse(reply.body)).toMatchObject({ error: code });
    expect(nonReadAuditCount(engine)).toBe(rowsBefore);
    expect(resolveForProxy).not.toHaveBeenCalled();
    expect(upstream.seen).toHaveLength(0);
  });

  it("a sealed vault answers 503 VAULT_LOCKED", async () => {
    const token = engine.createToken("agent-a", ["use"]);
    await engine.lock();

    const reply = await send(token);

    expect(reply.status).toBe(503);
    expect(JSON.parse(reply.body)).toEqual({
      error: ErrorCode.VAULT_LOCKED,
      message: "Vault is locked",
    });
    expect(upstream.seen).toHaveLength(0);
  });

  it("a read-scoped token's brokered request is 403 after one access.denied row naming the proxy operation", async () => {
    const token = engine.createToken("agent-a", ["read"]);
    const reply = await send(token, { authorization: "Bearer harpoc:gh-pat" });

    expect(reply.status).toBe(403);
    expect(JSON.parse(reply.body)).toMatchObject({ error: ErrorCode.ACCESS_DENIED });
    const rows = engine.queryAudit({ eventType: AuditEventType.ACCESS_DENIED });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      secret_id: null,
      principal_type: "agent",
      principal_id: "agent-a",
      ip_address: "127.0.0.1",
      success: false,
      detail: {
        operation: `GET ${upstream.origin}/user`,
        error: ErrorCode.ACCESS_DENIED,
        reason: "permission",
        interface: "proxy",
      },
    });
    expect(resolveForProxy).not.toHaveBeenCalled();
    expect(upstream.seen).toHaveLength(0);
  });

  it("listenTcp wrote one server.start row: transport proxy, the bound port, the host", () => {
    const rows = engine.queryAudit({ eventType: AuditEventType.SERVER_START });

    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail).toEqual({
      transport: "proxy",
      tokenless: false,
      tty_prompt: false,
      port,
      host: "127.0.0.1",
    });
  });
});
