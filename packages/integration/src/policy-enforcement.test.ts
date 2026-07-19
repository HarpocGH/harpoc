import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "@harpoc/rest-api";
import { startMcpHttpServer } from "@harpoc/mcp-server";
import type { McpHttpServer } from "@harpoc/mcp-server";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

const PASSWORD = "policy-enforcement-pw";

/**
 * Engine-level per-secret policy enforcement end-to-end (thesis §4.6): real
 * VaultEngine, real signed tokens, stored access_policies rows — through the
 * full REST stack and the real MCP Streamable HTTP wire. Interface-layer
 * token scope passes in every case here; what grants or denies is the
 * stored per-principal policy row, checked by the engine.
 */
describe("per-secret access policy enforcement end-to-end", () => {
  let vault: TestVault;
  let app: ReturnType<typeof createApp>;
  let mcpServer: McpHttpServer;
  let dbProdId: string;
  const clients: Client[] = [];

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    await vault.engine.createSecret({
      name: "db-prod",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("s3cret-value")),
    });
    await vault.engine.createSecret({
      name: "open-key",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("open-value")),
    });
    await vault.engine.createSecret({
      name: "svc-key",
      type: SecretType.API_KEY,
      project: "api",
      value: new Uint8Array(Buffer.from("svc-value")),
    });
    dbProdId = await vault.engine.resolveSecretId("secret://db-prod");
    vault.engine.grantPolicy(
      {
        secretId: dbProdId,
        principalType: "agent",
        principalId: "allowed-agent",
        permissions: ["read", "use"],
      },
      "it-admin",
    );
    const svcId = await vault.engine.resolveSecretId("secret://api/svc-key");
    vault.engine.grantPolicy(
      { secretId: svcId, principalType: "project", principalId: "api", permissions: ["read"] },
      "it-admin",
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

  async function connectMcp(token: string): Promise<Client> {
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${mcpServer.port}${mcpServer.endpoint}`),
      { requestInit: { headers: { Authorization: `Bearer ${token}` } } },
    );
    const client = new Client({ name: "policy-it-client", version: "1.0.0" });
    await client.connect(transport);
    clients.push(client);
    return client;
  }

  function textOf(result: { content?: unknown }): string {
    const content = result.content as { type: string; text?: string }[] | undefined;
    return (content ?? []).map((c) => c.text ?? "").join("\n");
  }

  it("REST: the granted principal reads the gated secret; another principal is denied 403 and audited", async () => {
    const allowed = vault.engine.createToken("allowed-agent", ["read", "list"]);
    const denied = vault.engine.createToken("other-agent", ["read", "list"]);

    const ok = await app.request("/api/v1/secrets/db-prod/value", {
      headers: { authorization: `Bearer ${allowed}` },
    });
    expect(ok.status).toBe(200);
    const okBody = (await ok.json()) as { data: { value: string } };
    expect(Buffer.from(okBody.data.value, "base64").toString("utf8")).toBe("s3cret-value");

    const res = await app.request("/api/v1/secrets/db-prod/value", {
      headers: { authorization: `Bearer ${denied}` },
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.ACCESS_DENIED);

    const rows = vault.engine.queryAudit({
      eventType: AuditEventType.SECRET_READ,
      secretId: dbProdId,
    });
    const denial = rows.find((r) => !r.success && r.principal_id === "other-agent");
    expect(denial).toBeDefined();
    expect(denial?.principal_type).toBe("agent");
    expect(denial?.detail?.required_permission).toBe("read");
    expect(denial?.detail?.error).toBe(ErrorCode.ACCESS_DENIED);

    expect(vault.engine.verifyAuditChain().valid).toBe(true);
  });

  it("REST: a secret without policy rows stays open to any in-scope principal", async () => {
    const token = vault.engine.createToken("other-agent", ["read", "list"]);
    const res = await app.request("/api/v1/secrets/open-key/value", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
  });

  it("REST: a project grant matches through the token's project claim, not the subject", async () => {
    const projectToken = vault.engine.createToken("charlie", ["read", "list"], undefined, {
      project: "api",
    });
    const ok = await app.request("/api/v1/secrets/api%2Fsvc-key/value", {
      headers: { authorization: `Bearer ${projectToken}` },
    });
    expect(ok.status).toBe(200);

    // Same permission scope, no project claim — the derived project principal
    // is absent, and no other row matches: engine denies.
    const bare = vault.engine.createToken("charlie", ["read", "list"]);
    const res = await app.request("/api/v1/secrets/api%2Fsvc-key/value", {
      headers: { authorization: `Bearer ${bare}` },
    });
    expect(res.status).toBe(403);
  });

  it("MCP wire: use_secret is denied for an ungranted principal and passes the gate for the granted one", async () => {
    const action = {
      type: "process",
      command: "definitely-not-allowlisted",
      env_var: "SECRET",
    };

    const deniedClient = await connectMcp(vault.engine.createToken("other-agent", ["use", "list"]));
    const deniedResult = await deniedClient.callTool({
      name: "use_secret",
      arguments: { handle: "secret://db-prod", action },
    });
    expect(deniedResult.isError).toBe(true);
    expect(textOf(deniedResult)).toContain("Principal lacks 'use' permission");

    // The granted principal clears the policy gate and fails deterministically
    // one layer down, at the fail-safe command allowlist.
    const allowedClient = await connectMcp(
      vault.engine.createToken("allowed-agent", ["use", "list"]),
    );
    const allowedResult = await allowedClient.callTool({
      name: "use_secret",
      arguments: { handle: "secret://db-prod", action },
    });
    expect(allowedResult.isError).toBe(true);
    const text = textOf(allowedResult);
    expect(text).not.toContain("Principal lacks");
    expect(text).toContain("Command not in secret allowlist");
  });

  it("revoking the policy rows reopens the gate (presence semantics live)", async () => {
    const gatedId = (
      await vault.engine.createSecret({
        name: "temp-gated",
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from("temp-value")),
      })
    ).handle;
    expect(gatedId).toBeTruthy();
    const secretId = await vault.engine.resolveSecretId("secret://temp-gated");
    const policy = vault.engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "someone-else", permissions: ["read"] },
      "it-admin",
    );

    const token = vault.engine.createToken("other-agent", ["read", "list"]);
    const denied = await app.request("/api/v1/secrets/temp-gated/value", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(denied.status).toBe(403);

    vault.engine.revokePolicy(policy.id);

    const open = await app.request("/api/v1/secrets/temp-gated/value", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(open.status).toBe(200);
  });
});
