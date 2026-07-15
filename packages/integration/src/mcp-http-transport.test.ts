import { request as httpRequest } from "node:http";
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { VaultEngine } from "@harpoc/core";
import { startMcpHttpServer } from "@harpoc/mcp-server";
import type { McpHttpServer } from "@harpoc/mcp-server";
import { SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

const PASSWORD = "mcp-http-transport-pw";

/**
 * Harpoc's own MCP server over the REAL Streamable HTTP transport with REAL
 * vault-signed tokens — the Bearer + fingerprint-pinning path that the direct
 * tool-handler helper (mcp-helpers.ts) bypasses, and that mcp-server's own
 * http.test.ts covers only through a stubbed verifier.
 */
describe("MCP Streamable HTTP transport (real engine, real tokens)", () => {
  let vault: TestVault;
  let engine: VaultEngine;
  let server: McpHttpServer;
  const clients: Client[] = [];

  beforeAll(async () => {
    vault = createTestVault();
    engine = vault.engine;
    await engine.initVault(PASSWORD);
    await engine.createSecret({
      name: "db-prod",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("value-db"),
    });
    await engine.createSecret({
      name: "api-key",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("value-api"),
    });
    server = await startMcpHttpServer({ engine, port: 0 });
  });

  afterAll(async () => {
    await server.close();
    await destroyTestVault(vault);
  });

  afterEach(async () => {
    for (const client of clients.splice(0)) {
      try {
        await client.close();
      } catch {
        // already closed
      }
    }
  });

  async function connect(token: string): Promise<Client> {
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${server.port}${server.endpoint}`),
      { requestInit: { headers: { Authorization: `Bearer ${token}` } } },
    );
    const client = new Client({ name: "integration-client", version: "1.0.0" });
    await client.connect(transport);
    clients.push(client);
    return client;
  }

  function textOf(result: { content?: unknown }): string {
    const content = result.content as { type: string; text?: string }[] | undefined;
    return (content ?? []).map((c) => c.text ?? "").join("\n");
  }

  it("a real admin token initializes a session and lists secrets through the wire", async () => {
    const token = engine.createToken("it-admin", ["admin", "list", "read"]);
    const client = await connect(token);

    const result = await client.callTool({ name: "list_secrets", arguments: {} });
    expect(result.isError ?? false).toBe(false);
    const text = textOf(result);
    expect(text).toContain("db-prod");
    expect(text).toContain("api-key");
  });

  it("a name-pattern-scoped token sees only matching secrets end-to-end", async () => {
    const token = engine.createToken("it-scoped", ["list", "read"], 3600_000, {
      secrets: ["db-*"],
    });
    const client = await connect(token);

    const result = await client.callTool({ name: "list_secrets", arguments: {} });
    const text = textOf(result);
    expect(text).toContain("db-prod");
    expect(text).not.toContain("api-key");

    const denied = await client.callTool({
      name: "get_secret_info",
      arguments: { handle: "secret://api-key" },
    });
    expect(denied.isError).toBe(true);
  });

  it("a garbage token cannot initialize (real JWT verification on the wire)", async () => {
    await expect(connect("not.a.token")).rejects.toThrow();
  });

  it("a revoked token is cut off mid-session on the next request", async () => {
    const token = engine.createToken("it-revoked", ["admin", "list", "read"]);
    const client = await connect(token);
    const ok = await client.callTool({ name: "list_secrets", arguments: {} });
    expect(ok.isError ?? false).toBe(false);

    const [, payloadB64] = token.split(".");
    const payload = JSON.parse(Buffer.from(payloadB64 as string, "base64url").toString("utf8")) as {
      jti: string;
      exp: number;
    };
    engine.revokeToken(payload.jti, payload.exp);

    await expect(client.callTool({ name: "list_secrets", arguments: {} })).rejects.toThrow();
  });

  it("a captured session id carries no authority: a different valid token is rejected", async () => {
    const tokenA = engine.createToken("it-owner", ["admin", "list", "read"]);
    const tokenB = engine.createToken("it-thief", ["admin", "list", "read"]);

    // Raw initialize with token A to capture the session id.
    const init = await rawRpc(server.port, {
      authorization: `Bearer ${tokenA}`,
    });
    expect(init.status).toBe(200);
    const sessionId = init.sessionId as string;
    expect(sessionId).toBeTruthy();

    const listBody = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" });

    // Token B (valid, different identity) replaying the session id is refused —
    // the session is pinned to token A's SHA-256 fingerprint.
    const hijack = await rawRpc(
      server.port,
      { authorization: `Bearer ${tokenB}`, "mcp-session-id": sessionId },
      listBody,
    );
    expect(hijack.status).toBeGreaterThanOrEqual(400);

    // The rightful owner keeps working on the same session.
    const owner = await rawRpc(
      server.port,
      { authorization: `Bearer ${tokenA}`, "mcp-session-id": sessionId },
      listBody,
    );
    expect(owner.status).toBe(200);
  });
});

function rawRpc(
  port: number,
  headers: Record<string, string>,
  body?: string,
): Promise<{ status: number; sessionId?: string }> {
  const initBody = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "raw-integration-client", version: "1.0.0" },
    },
  });
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/mcp",
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          ...headers,
        },
      },
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
    req.end(body ?? initBody);
  });
}
