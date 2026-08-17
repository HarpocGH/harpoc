import { request as httpRequest } from "node:http";
import { describe, it, expect, vi, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { VaultEngine } from "@harpoc/core";
import { VaultError } from "@harpoc/shared";
import { startMcpHttpServer } from "./http.js";
import type { McpHttpServer } from "./http.js";

const TOKEN = "valid.jwt.token";

function tokenPayload(scope: string[] = ["use", "list"]): Record<string, unknown> {
  return {
    sub: "agent",
    vault_id: "v",
    scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: "jti-1",
  };
}

function mockEngine(overrides: Record<string, unknown> = {}): VaultEngine {
  return {
    listSecrets: vi.fn().mockReturnValue([]),
    getSecretInfo: vi.fn().mockResolvedValue({}),
    useSecret: vi.fn().mockResolvedValue({ type: "http", status: 200, body: "" }),
    createSecret: vi
      .fn()
      .mockResolvedValue({ handle: "secret://x", status: "pending", message: "" }),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-123"),
    getState: vi.fn().mockReturnValue("unlocked"),
    queryAudit: vi.fn().mockReturnValue([]),
    verifyToken: vi.fn().mockReturnValue(tokenPayload()),
    auditServerStart: vi.fn(),
    isTokenRevoked: vi.fn().mockReturnValue(false),
    ...overrides,
  } as unknown as VaultEngine;
}

const INIT_BODY = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "raw-client", version: "1.0.0" },
  },
};

function rpcHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...extra,
  };
}

interface RawResponse {
  status: number;
  body: string;
}

/** node:http request that allows forbidden-by-fetch headers (e.g. Host). */
function rawRequest(
  port: number,
  headers: Record<string, string>,
  body: string,
  method = "POST",
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path: "/mcp", method, headers }, (res) => {
      let data = "";
      res.on("data", (chunk: Buffer) => (data += chunk.toString("utf8")));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function connectClient(
  port: number,
  token: string,
): Promise<{ client: Client; transport: StreamableHTTPClientTransport }> {
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(transport);
  return { client, transport };
}

describe("startMcpHttpServer", () => {
  let server: McpHttpServer | undefined;
  const clients: Client[] = [];

  afterEach(async () => {
    for (const client of clients.splice(0)) {
      try {
        await client.close();
      } catch {
        // already closed by the test
      }
    }
    await server?.close();
    server = undefined;
  });

  async function start(engine: VaultEngine): Promise<McpHttpServer> {
    server = await startMcpHttpServer({ engine, port: 0 });
    return server;
  }

  it("reports the actual bound port and endpoint", async () => {
    const { port, endpoint } = await start(mockEngine());
    expect(port).toBeGreaterThan(0);
    expect(endpoint).toBe("/mcp");
  });

  it("completes an initialize handshake and lists all 9 tools", async () => {
    const engine = mockEngine();
    const { port } = await start(engine);

    const { client } = await connectClient(port, TOKEN);
    clients.push(client);

    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      "check_secret_health",
      "create_secret",
      "get_secret_info",
      "list_secrets",
      "renew_certificate",
      "revoke_secret",
      "rotate_secret",
      "start_oauth_flow",
      "use_secret",
    ]);
    expect(engine.verifyToken).toHaveBeenCalledWith(TOKEN);
  });

  it("forwards tool calls to the engine over HTTP", async () => {
    const engine = mockEngine();
    const { port } = await start(engine);

    const { client } = await connectClient(port, TOKEN);
    clients.push(client);

    const result = (await client.callTool({ name: "list_secrets", arguments: {} })) as {
      content: Array<{ type: string; text: string }>;
    };
    expect(result.content).toBeDefined();
    expect(engine.listSecrets).toHaveBeenCalled();
  });

  it("writes no server.start row per HTTP session (W6/D2 pin)", async () => {
    const engine = mockEngine();
    const { port } = await start(engine);

    const { client } = await connectClient(port, TOKEN);
    clients.push(client);

    // Every HTTP session constructs its own McpServer; logging each one would
    // put up to 128 rows per client into the trail for a mode that already
    // authenticates every request. Only the stdio tokenless waiver is audited.
    expect(engine.auditServerStart).not.toHaveBeenCalled();
  });

  it("enforces token scope across the HTTP transport", async () => {
    const engine = mockEngine();
    const { port } = await start(engine);

    const { client } = await connectClient(port, TOKEN);
    clients.push(client);

    const result = (await client.callTool({
      name: "create_secret",
      arguments: { name: "x", type: "api_key" },
    })) as { content: Array<{ text: string }>; isError?: boolean };
    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain("Access denied");
  });

  it("rejects requests without a bearer token with 401", async () => {
    const { port } = await start(mockEngine());

    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: rpcHeaders(),
      body: JSON.stringify(INIT_BODY),
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("Bearer");
    // The rejection happens at bearer extraction — HTTP has no tokenless mode,
    // so the stdio-only allowTokenless gate is never reachable on this path.
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("Authorization");
    expect(body.error.message).not.toContain("--allow-tokenless");
  });

  it("rejects tokens the engine does not verify with 401", async () => {
    const engine = mockEngine({
      verifyToken: vi.fn().mockImplementation(() => {
        throw VaultError.tokenExpired();
      }),
    });
    const { port } = await start(engine);

    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: rpcHeaders({ authorization: `Bearer ${TOKEN}` }),
      body: JSON.stringify(INIT_BODY),
    });
    expect(res.status).toBe(401);
  });

  it("rejects a locked vault with 503", async () => {
    const engine = mockEngine({
      verifyToken: vi.fn().mockImplementation(() => {
        throw VaultError.vaultLocked();
      }),
    });
    const { port } = await start(engine);

    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: rpcHeaders({ authorization: `Bearer ${TOKEN}` }),
      body: JSON.stringify(INIT_BODY),
    });
    expect(res.status).toBe(503);
  });

  it("pins the session to the token presented at initialize", async () => {
    const { port } = await start(mockEngine());

    const { client, transport } = await connectClient(port, TOKEN);
    clients.push(client);
    const sessionId = transport.sessionId as string;
    expect(sessionId).toBeDefined();

    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: rpcHeaders({
        authorization: "Bearer some.other.token",
        "mcp-session-id": sessionId,
      }),
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    });
    expect(res.status).toBe(401);
  });

  it("re-verifies the token on every request (expiry mid-session)", async () => {
    const engine = mockEngine();
    const { port } = await start(engine);

    const { client, transport } = await connectClient(port, TOKEN);
    clients.push(client);
    const sessionId = transport.sessionId as string;

    vi.mocked(engine.verifyToken).mockImplementation(() => {
      throw VaultError.tokenExpired();
    });

    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: rpcHeaders({ authorization: `Bearer ${TOKEN}`, "mcp-session-id": sessionId }),
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    });
    expect(res.status).toBe(401);
  });

  it("rejects unknown session IDs with 404", async () => {
    const { port } = await start(mockEngine());

    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: rpcHeaders({
        authorization: `Bearer ${TOKEN}`,
        "mcp-session-id": "00000000-0000-0000-0000-000000000000",
      }),
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    });
    expect(res.status).toBe(404);
  });

  it("rejects non-initialize requests without a session with 400", async () => {
    const { port } = await start(mockEngine());

    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: rpcHeaders({ authorization: `Bearer ${TOKEN}` }),
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    });
    expect(res.status).toBe(400);
  });

  it("rejects invalid JSON bodies with a parse error", async () => {
    const { port } = await start(mockEngine());

    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: rpcHeaders({ authorization: `Bearer ${TOKEN}` }),
      body: "{not json",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32700);
  });

  it("rejects an oversized initialize body with 413", async () => {
    const { port } = await start(mockEngine());

    const oversized = JSON.stringify({
      ...INIT_BODY,
      params: { ...INIT_BODY.params, padding: "x".repeat(4 * 1024 * 1024) },
    });
    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: rpcHeaders({ authorization: `Bearer ${TOKEN}` }),
      body: oversized,
    });
    expect(res.status).toBe(413);
  });

  it("rejects an oversized body on an established session with 413", async () => {
    const engine = mockEngine();
    const { port } = await start(engine);

    const { client, transport } = await connectClient(port, TOKEN);
    clients.push(client);
    const sessionId = transport.sessionId as string;

    const oversized = JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "list_secrets", arguments: { padding: "x".repeat(4 * 1024 * 1024) } },
    });
    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: rpcHeaders({ authorization: `Bearer ${TOKEN}`, "mcp-session-id": sessionId }),
      body: oversized,
    });
    expect(res.status).toBe(413);
    expect(engine.listSecrets).not.toHaveBeenCalled();

    const { tools } = await client.listTools();
    expect(tools).toHaveLength(9);
  });

  it("rejects unknown paths with 404", async () => {
    const { port } = await start(mockEngine());

    const res = await fetch(`http://127.0.0.1:${port}/other`, {
      method: "POST",
      headers: rpcHeaders({ authorization: `Bearer ${TOKEN}` }),
      body: JSON.stringify(INIT_BODY),
    });
    expect(res.status).toBe(404);
  });

  it("rejects spoofed Host headers on loopback binds (DNS rebinding)", async () => {
    const { port } = await start(mockEngine());

    const res = await rawRequest(
      port,
      rpcHeaders({ authorization: `Bearer ${TOKEN}`, host: "evil.example.com" }),
      JSON.stringify(INIT_BODY),
    );
    expect(res.status).toBe(403);
  });

  it("terminates a session on DELETE and rejects subsequent use", async () => {
    const { port } = await start(mockEngine());

    const { client, transport } = await connectClient(port, TOKEN);
    clients.push(client);
    const sessionId = transport.sessionId as string;

    const del = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "DELETE",
      headers: rpcHeaders({ authorization: `Bearer ${TOKEN}`, "mcp-session-id": sessionId }),
    });
    expect(del.status).toBeLessThan(300);

    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: rpcHeaders({ authorization: `Bearer ${TOKEN}`, "mcp-session-id": sessionId }),
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    });
    expect(res.status).toBe(404);
  });

  it("supports multiple concurrent sessions with distinct tokens", async () => {
    const engine = mockEngine();
    const { port } = await start(engine);

    const a = await connectClient(port, "token.for.alpha");
    const b = await connectClient(port, "token.for.beta");
    clients.push(a.client, b.client);

    const [toolsA, toolsB] = await Promise.all([a.client.listTools(), b.client.listTools()]);
    expect(toolsA.tools).toHaveLength(9);
    expect(toolsB.tools).toHaveLength(9);
    expect(a.transport.sessionId).not.toBe(b.transport.sessionId);
  });

  it("refuses connections after close()", async () => {
    const { port } = await start(mockEngine());
    await server?.close();
    server = undefined;

    await expect(
      fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: rpcHeaders({ authorization: `Bearer ${TOKEN}` }),
        body: JSON.stringify(INIT_BODY),
      }),
    ).rejects.toThrow();
  });

  it("caps concurrent sessions at 128 and frees the slot when a session closes", async () => {
    const { port } = await start(mockEngine());

    const rawWithHeaders = (
      method: string,
      headers: Record<string, string>,
      body?: string,
    ): Promise<{ status: number; sessionId?: string }> =>
      new Promise((resolve, reject) => {
        const req = httpRequest(
          { host: "127.0.0.1", port, path: "/mcp", method, headers },
          (res) => {
            res.resume();
            res.on("end", () =>
              resolve({
                status: res.statusCode ?? 0,
                sessionId: res.headers["mcp-session-id"] as string | undefined,
              }),
            );
          },
        );
        req.on("error", reject);
        req.end(body);
      });

    const initialize = (): Promise<{ status: number; sessionId?: string }> =>
      rawWithHeaders(
        "POST",
        rpcHeaders({ authorization: `Bearer ${TOKEN}` }),
        JSON.stringify(INIT_BODY),
      );

    const ids: string[] = [];
    for (let i = 0; i < 128; i++) {
      const r = await initialize();
      expect(r.status).toBe(200);
      expect(r.sessionId).toBeTruthy();
      ids.push(r.sessionId as string);
    }

    const overflow = await initialize();
    expect(overflow.status).toBe(429);

    // Terminating one session frees its slot.
    const del = await rawWithHeaders("DELETE", {
      authorization: `Bearer ${TOKEN}`,
      "mcp-session-id": ids[0] as string,
    });
    expect(del.status).toBeLessThan(300);

    const refill = await initialize();
    expect(refill.status).toBe(200);
  }, 30_000);
});

/**
 * M6. A session left the map only on an explicit `DELETE /mcp` or on shutdown:
 * no idle TTL, and sessions whose pinned token had expired or been revoked were
 * refused per request but never evicted. Clients that die without a DELETE
 * (crash, sleep, network drop) leaked a slot each, and the least-privileged
 * token in the deployment could deliberately consume all of them with cheap
 * initializes and lock out every other principal — `admin` included — until the
 * daemon was restarted.
 */
describe("startMcpHttpServer — session reclamation (M6)", () => {
  let server: McpHttpServer | undefined;

  afterEach(async () => {
    await server?.close();
    server = undefined;
  });

  const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

  function raw(
    port: number,
    method: string,
    headers: Record<string, string>,
    body?: string,
  ): Promise<{ status: number; sessionId?: string }> {
    return new Promise((resolve, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port, path: "/mcp", method, headers }, (res) => {
        res.resume();
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            sessionId: res.headers["mcp-session-id"] as string | undefined,
          }),
        );
      });
      req.on("error", reject);
      req.end(body);
    });
  }

  const initialize = (
    port: number,
    token = TOKEN,
  ): Promise<{ status: number; sessionId?: string }> =>
    raw(port, "POST", rpcHeaders({ authorization: `Bearer ${token}` }), JSON.stringify(INIT_BODY));

  const ping = (port: number, sessionId: string): Promise<{ status: number }> =>
    raw(
      port,
      "POST",
      rpcHeaders({ authorization: `Bearer ${TOKEN}`, "mcp-session-id": sessionId }),
      JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }),
    );

  it("reclaims a session abandoned without a DELETE", async () => {
    server = await startMcpHttpServer({
      engine: mockEngine(),
      port: 0,
      sessionLimits: { idleTtlMs: 150, sweepIntervalMs: 40 },
    });

    const created = await initialize(server.port);
    expect(created.status).toBe(200);

    await sleep(400);

    // The client is gone; the slot must be gone with it.
    const after = await ping(server.port, created.sessionId as string);
    expect(after.status).toBe(404);
  }, 20_000);

  it("keeps a session that is still being used", async () => {
    server = await startMcpHttpServer({
      engine: mockEngine(),
      port: 0,
      sessionLimits: { idleTtlMs: 1_000, sweepIntervalMs: 40 },
    });

    const created = await initialize(server.port);
    const sessionId = created.sessionId as string;

    // Well past the idle TTL in total, but never idle for it. The gap must
    // stay far under the TTL: with 250/100 the 150 ms margin was breached by
    // loaded-runner scheduling jitter (windows leg, run 31591341443).
    for (let i = 0; i < 10; i++) {
      await sleep(200);
      expect((await ping(server.port, sessionId)).status).toBeLessThan(400);
    }
  }, 20_000);

  it("reclaims a session whose pinned token has expired", async () => {
    const engine = mockEngine({
      verifyToken: vi.fn().mockReturnValue({
        ...tokenPayload(),
        exp: Math.floor(Date.now() / 1000) - 1,
      }),
    });
    server = await startMcpHttpServer({
      engine,
      port: 0,
      sessionLimits: { idleTtlMs: 600_000, sweepIntervalMs: 40 },
    });

    const created = await initialize(server.port);
    expect(created.status).toBe(200);

    await sleep(200);
    expect((await ping(server.port, created.sessionId as string)).status).toBe(404);
  }, 20_000);

  it("reclaims a session whose pinned token has been revoked", async () => {
    const isTokenRevoked = vi.fn().mockReturnValue(false);
    const engine = mockEngine({ isTokenRevoked });
    server = await startMcpHttpServer({
      engine,
      port: 0,
      sessionLimits: { idleTtlMs: 600_000, sweepIntervalMs: 40 },
    });

    const created = await initialize(server.port);
    expect(created.status).toBe(200);

    isTokenRevoked.mockReturnValue(true);
    await sleep(200);
    expect((await ping(server.port, created.sessionId as string)).status).toBe(404);
  }, 20_000);

  it("admits a new client by reclaiming the quietest session at capacity", async () => {
    server = await startMcpHttpServer({
      engine: mockEngine(),
      port: 0,
      // No sweep and no idle expiry in play: the admission path itself has to
      // give up the least-recently-used slot.
      sessionLimits: {
        max: 2,
        idleTtlMs: 600_000,
        sweepIntervalMs: 600_000,
        evictionGraceMs: 100,
      },
    });

    const first = await initialize(server.port);
    const second = await initialize(server.port);
    expect(second.status).toBe(200);
    await sleep(150);

    const third = await initialize(server.port);
    expect(third.status).toBe(200);
    // The oldest slot was the one given up.
    expect((await ping(server.port, first.sessionId as string)).status).toBe(404);
    expect((await ping(server.port, third.sessionId as string)).status).toBeLessThan(400);
  }, 20_000);

  it("control: a fleet of busy sessions is refused, not churned", async () => {
    server = await startMcpHttpServer({
      engine: mockEngine(),
      port: 0,
      sessionLimits: {
        max: 2,
        idleTtlMs: 600_000,
        sweepIntervalMs: 600_000,
        evictionGraceMs: 30_000,
      },
    });

    const first = await initialize(server.port);
    const second = await initialize(server.port);

    expect((await initialize(server.port)).status).toBe(429);
    expect((await ping(server.port, first.sessionId as string)).status).toBeLessThan(400);
    expect((await ping(server.port, second.sessionId as string)).status).toBeLessThan(400);
  }, 20_000);
});
