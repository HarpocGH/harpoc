import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "@harpoc/rest-api";
import { startMcpHttpServer } from "@harpoc/mcp-server";
import type { McpHttpServer } from "@harpoc/mcp-server";
import { AuditEventType, SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

const PASSWORD = "audit-attribution-pw";
const NODE = process.execPath;

/**
 * Credential-access audit attribution end-to-end (thesis §4.3.4 "by whom" /
 * "through which interface", alignment V2): a token-authenticated use_secret
 * over the real REST stack and the real MCP Streamable HTTP wire must leave a
 * SUCCESS row carrying the requesting principal in the plaintext columns, the
 * session id, and the interface in the encrypted detail — with the HMAC chain
 * and a pre-existing anchor still verifying (attribution is append-time).
 */
describe("credential-access audit attribution end-to-end", () => {
  let vault: TestVault;
  let app: ReturnType<typeof createApp>;
  let mcpServer: McpHttpServer;
  let secretId: string;
  const clients: Client[] = [];

  const USE_ACTION = {
    type: "process",
    command: NODE,
    args: ["-e", "process.exit(0)"],
    env_var: "SECRET",
  };

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    await vault.engine.createSecret({
      name: "attr-key",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("attr-value")),
    });
    secretId = await vault.engine.resolveSecretId("secret://attr-key");
    await vault.engine.setInjectionPolicy(
      "secret://attr-key",
      { url_allowlist: [], command_allowlist: [NODE], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    app = createApp(vault.engine);
    mcpServer = await startMcpHttpServer({ engine: vault.engine, port: 0 });
  });

  afterAll(async () => {
    await mcpServer.close();
    await destroyTestVault(vault).catch(() => {});
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

  function useRows(): ReturnType<TestVault["engine"]["queryAudit"]> {
    return vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId });
  }

  it("REST: the use_secret success row is attributed to the principal, session and interface", async () => {
    const anchor = vault.engine.getAuditChainTail();
    const token = vault.engine.createToken("rest-agent", ["use"]);

    const res = await app.request("/api/v1/secrets/attr-key/use", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ action: USE_ACTION }),
    });
    expect(res.status).toBe(200);

    const row = useRows().find((r) => r.principal_id === "rest-agent");
    expect(row).toBeDefined();
    expect(row?.success).toBe(true);
    expect(row?.principal_type).toBe("agent");
    expect(row?.session_id).toEqual(expect.any(String));
    expect(row?.detail?.interface).toBe("rest");
    expect(row?.detail?.context).toBe("process");

    // Attribution is append-time: the chain stays green and a pre-use anchor
    // still verifies against the extended chain.
    const report = vault.engine.verifyAuditChain(anchor ? { anchor } : undefined);
    expect(report.valid).toBe(true);
  });

  it("MCP Streamable HTTP: the use_secret success row carries interface mcp-http", async () => {
    const token = vault.engine.createToken("mcp-agent", ["use"], 3600_000, {
      principalType: "tool",
    });

    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${mcpServer.port}${mcpServer.endpoint}`),
      { requestInit: { headers: { Authorization: `Bearer ${token}` } } },
    );
    const client = new Client({ name: "attr-it-client", version: "1.0.0" });
    await client.connect(transport);
    clients.push(client);

    const result = (await client.callTool({
      name: "use_secret",
      arguments: { handle: "secret://attr-key", action: USE_ACTION },
    })) as { isError?: boolean };
    expect(result.isError ?? false).toBe(false);

    const row = useRows().find((r) => r.principal_id === "mcp-agent");
    expect(row).toBeDefined();
    expect(row?.success).toBe(true);
    expect(row?.principal_type).toBe("tool");
    expect(row?.session_id).toEqual(expect.any(String));
    expect(row?.detail?.interface).toBe("mcp-http");

    expect(vault.engine.verifyAuditChain().valid).toBe(true);
  });

  it("trusted local path: a direct engine use stays principal-NULL with no interface (D4)", async () => {
    await vault.engine.useSecret("secret://attr-key", {
      type: "process",
      command: NODE,
      args: ["-e", "process.exit(0)"],
      env_var: "SECRET",
    });

    const locals = useRows().filter((r) => r.principal_id === null);
    expect(locals.length).toBeGreaterThan(0);
    for (const row of locals) {
      expect(row.principal_type).toBeNull();
      expect(row.detail && "interface" in (row.detail as object)).toBe(false);
    }
  });
});
