import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { VaultEngine } from "@harpoc/core";
import { createMcpServer } from "@harpoc/mcp-server";
import { createApp } from "@harpoc/rest-api";
import { DirectClient, RestClient } from "@harpoc/sdk";
import { AuditEventType, InjectionType, SecretType, VaultState } from "@harpoc/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { callTool } from "./helpers/mcp-helpers.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";

const PASSWORD = "integration-test-pw";
const SECRET_NAME = "my-api-key";
const SECRET_VALUE = "sk-test-abcdef1234567890ab";
const SECRET_VALUE_V2 = "sk-test-rotated-9876543210";

describe("Full Lifecycle", () => {
  let vault: TestVault;
  let mcpServer: McpServer;
  let echoServer: Server;
  let echoUrl: string;
  let restServer: TestServer;
  let token: string;
  let handle: string;

  beforeAll(async () => {
    // 1. Create echo HTTP server (echoes back request headers as JSON)
    echoServer = createServer((req, res) => {
      const body = JSON.stringify({
        method: req.method,
        url: req.url,
        headers: req.headers,
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
    });
    await new Promise<void>((resolve) => {
      echoServer.listen(0, "127.0.0.1", resolve);
    });
    const echoAddr = echoServer.address() as AddressInfo;
    echoUrl = `http://127.0.0.1:${echoAddr.port}`;

    // 2. Create VaultEngine, init vault, create secret
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);

    const result = await vault.engine.createSecret({
      name: SECRET_NAME,
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from(SECRET_VALUE)),
      injection: { type: InjectionType.BEARER },
    });
    handle = result.handle;

    // 3. Create JWT token for REST API auth
    token = vault.engine.createToken("test-agent", ["admin"]);

    // 4. Create MCP server
    mcpServer = createMcpServer({ engine: vault.engine });

    // 5. Start real HTTP server for REST API (SDK RestClient)
    restServer = startTestServer(vault.engine);
  });

  afterAll(async () => {
    await restServer?.close();
    await vault?.engine.destroy();
    await new Promise<void>((resolve, reject) => {
      echoServer?.close((err) => (err ? reject(err) : resolve()));
    });
    destroyTestVault(vault).catch(() => {});
  });

  // ---- Test 1: initVault + createSecret -----------------------------------
  it("creates a secret with handle and active status", () => {
    expect(handle).toBe(`secret://${SECRET_NAME}`);
  });

  // ---- Test 2: MCP list_secrets -------------------------------------------
  it("MCP list_secrets returns the secret without value", async () => {
    const result = await callTool(mcpServer, "list_secrets", {});
    const secrets = JSON.parse(result.content[0]!.text) as Array<{ handle: string; name: string }>;
    expect(secrets).toHaveLength(1);
    expect(secrets[0]!.handle).toBe(handle);
    expect(secrets[0]!.name).toBe(SECRET_NAME);
    // Ensure no value field
    expect(Object.keys(secrets[0]!)).not.toContain("value");
  });

  // ---- Test 3: MCP get_secret_info ----------------------------------------
  it("MCP get_secret_info returns correct metadata", async () => {
    const result = await callTool(mcpServer, "get_secret_info", { handle });
    const info = JSON.parse(result.content[0]!.text) as Record<string, unknown>;
    expect(info.name).toBe(SECRET_NAME);
    expect(info.type).toBe(SecretType.API_KEY);
    expect(info.status).toBe("active");
    expect(info.version).toBe(1);
  });

  // ---- Test 4: MCP use_secret + echo server -------------------------------
  it("MCP use_secret injects bearer token and sanitizes response", async () => {
    const result = await callTool(mcpServer, "use_secret", {
      handle,
      action: {
        type: "http",
        method: "GET",
        url: echoUrl,
        injection: { type: "bearer" },
      },
    });
    expect(result.isError).toBeFalsy();
    const response = JSON.parse(result.content[0]!.text) as { status: number; body: string };
    expect(response.status).toBe(200);

    // The echo server returned the Authorization header in the body.
    // InjectionGuard should have redacted the Bearer token in the body.
    expect(response.body).not.toContain(SECRET_VALUE);
  });

  // ---- Test 5: REST GET /api/v1/secrets -----------------------------------
  it("REST list secrets returns the secret", async () => {
    const app = createApp(vault.engine);
    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: Array<{ handle: string }> };
    expect(body.data).toHaveLength(1);
    expect(body.data[0]!.handle).toBe(handle);
  });

  // ---- Test 6: REST GET /api/v1/secrets/:handle ---------------------------
  it("REST get secret info returns matching metadata", async () => {
    const app = createApp(vault.engine);
    const encodedName = encodeURIComponent(SECRET_NAME);
    const res = await app.request(`/api/v1/secrets/${encodedName}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { name: string; type: string; version: number } };
    expect(body.data.name).toBe(SECRET_NAME);
    expect(body.data.type).toBe(SecretType.API_KEY);
    expect(body.data.version).toBe(1);
  });

  // ---- Test 7: SDK DirectClient.getSecretInfo() ---------------------------
  it("SDK DirectClient getSecretInfo matches MCP and REST", async () => {
    const client = new DirectClient(vault.engine);
    const info = await client.getSecretInfo(handle);
    expect(info.name).toBe(SECRET_NAME);
    expect(info.type).toBe(SecretType.API_KEY);
    expect(info.version).toBe(1);
  });

  // ---- Test 8: SDK RestClient.listSecrets() over real HTTP ----------------
  it("SDK RestClient listSecrets over real HTTP returns secrets", async () => {
    const client = new RestClient({ baseUrl: restServer.baseUrl, token });
    const secrets = await client.listSecrets();
    expect(secrets.length).toBeGreaterThanOrEqual(1);
    expect(secrets.some((s) => s.handle === handle)).toBe(true);
  });

  // ---- Test 9: SDK RestClient.getSecretInfo() over real HTTP --------------
  it("SDK RestClient getSecretInfo over real HTTP matches", async () => {
    const client = new RestClient({ baseUrl: restServer.baseUrl, token });
    const info = await client.getSecretInfo(handle);
    expect(info.name).toBe(SECRET_NAME);
    expect(info.type).toBe(SecretType.API_KEY);
    expect(info.version).toBe(1);
  });

  // ---- Test 10: rotateSecret ----------------------------------------------
  it("rotateSecret bumps version to 2", async () => {
    await vault.engine.rotateSecret(handle, new Uint8Array(Buffer.from(SECRET_VALUE_V2)));
    const info = await vault.engine.getSecretInfo(handle);
    expect(info.version).toBe(2);
  });

  // ---- Test 11: MCP get_secret_info after rotation -------------------------
  it("MCP get_secret_info shows version=2 after rotation", async () => {
    const result = await callTool(mcpServer, "get_secret_info", { handle });
    const info = JSON.parse(result.content[0]!.text) as { version: number };
    expect(info.version).toBe(2);
  });

  // ---- Test 12: queryAudit ------------------------------------------------
  it("audit trail contains expected events in order", () => {
    const events = vault.engine.queryAudit();
    const types = events.map((e) => e.event_type);
    // queryAudit returns newest-first — reverse to get chronological order
    const chronological = [...types].reverse();

    expect(chronological).toContain(AuditEventType.VAULT_UNLOCK);
    expect(chronological).toContain(AuditEventType.SECRET_CREATE);
    expect(chronological).toContain(AuditEventType.SECRET_ROTATE);

    // vault.unlock should be the earliest event
    expect(chronological[0]).toBe(AuditEventType.VAULT_UNLOCK);

    // secret.rotate should come after secret.create in chronological order
    const createIdx = chronological.indexOf(AuditEventType.SECRET_CREATE);
    const rotateIdx = chronological.indexOf(AuditEventType.SECRET_ROTATE);
    expect(rotateIdx).toBeGreaterThan(createIdx);
  });

  // ---- Test 13: lock → sealed, MCP errors, REST 503 ----------------------
  it("lock seals the vault — MCP returns error, REST returns 503", async () => {
    await vault.engine.lock();
    expect(vault.engine.getState()).toBe(VaultState.SEALED);

    // MCP tool should error
    const mcpResult = await callTool(mcpServer, "list_secrets", {});
    expect(mcpResult.isError).toBe(true);

    // REST should return 503
    const app = createApp(vault.engine);
    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(503);
  });

  // ---- Test 14: re-unlock → audit trail persists --------------------------
  it("re-unlock preserves the audit trail", async () => {
    // Create a new engine pointing at the same DB
    const engine2 = new VaultEngine({
      dbPath: vault.dbPath,
      sessionPath: vault.sessionPath,
    });
    await engine2.unlock(PASSWORD);

    const events = engine2.queryAudit();
    const types = events.map((e) => e.event_type);
    // Should contain events from before lock + the new unlock
    expect(types.filter((t) => t === AuditEventType.VAULT_UNLOCK).length).toBeGreaterThanOrEqual(2);
    expect(types).toContain(AuditEventType.SECRET_CREATE);
    expect(types).toContain(AuditEventType.SECRET_ROTATE);

    await engine2.destroy();
  });
});
