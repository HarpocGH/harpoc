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
    const req = httpRequest(
      { host: "127.0.0.1", port, path: "/mcp", method, headers },
      (res) => {
        let data = "";
        res.on("data", (chunk: Buffer) => (data += chunk.toString("utf8")));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }));
      },
    );
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

  it("completes an initialize handshake and lists all 7 tools", async () => {
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
      "revoke_secret",
      "rotate_secret",
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
    expect(toolsA.tools).toHaveLength(7);
    expect(toolsB.tools).toHaveLength(7);
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
});
