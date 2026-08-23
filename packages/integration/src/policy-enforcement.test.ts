import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "@harpoc/rest-api";
import { startMcpHttpServer } from "@harpoc/mcp-server";
import type { McpHttpServer } from "@harpoc/mcp-server";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
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
    registerAgents(
      vault.engine,
      "allowed-agent",
      "cfg-admin",
      "charlie",
      "other-agent",
      "someone-else",
      "w2-lister",
    );
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

  function textOf(result: unknown): string {
    const content = (result as { content?: unknown }).content as
      | { type: string; text?: string }[]
      | undefined;
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

  /**
   * W1: secret-scoped *configuration* was outside the gate — `allowed-agent`
   * holds read+use on db-prod (never rotate), so V1 already denies its rotate;
   * before this fix the same principal could still rewrite the allowlist that
   * bounds where the credential may be sent, and read the policy rows.
   */
  describe("secret-scoped configuration under the gate (W1)", () => {
    it("REST: a policy-denied-rotate principal cannot rewrite the allowlist", async () => {
      await vault.engine.setInjectionPolicy("secret://db-prod", {
        url_allowlist: ["https://api.example.com/*"],
      });

      // Token scope says rotate; the secret's policy row does not.
      const token = vault.engine.createToken("allowed-agent", ["read", "rotate", "list"]);
      const res = await app.request("/api/v1/secrets/db-prod/injection-policy", {
        method: "PUT",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({
          url_allowlist: ["https://evil.example/*"],
          response_mode: "full",
        }),
      });
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);

      // Read back through the trusted path: nothing was written.
      const stored = await vault.engine.getInjectionPolicy("secret://db-prod");
      expect(stored.url_allowlist).toEqual(["https://api.example.com/*"]);
      expect(stored.response_mode).toBe("filtered");

      const denial = vault.engine
        .queryAudit({ eventType: AuditEventType.POLICY_GRANT, secretId: dbProdId })
        .find((r) => !r.success && r.principal_id === "allowed-agent");
      expect(denial?.detail?.policy).toBe("injection");
      expect(denial?.detail?.required_permission).toBe("rotate");
      expect(denial?.detail?.interface).toBe("rest");
      expect(vault.engine.verifyAuditChain().valid).toBe(true);
    });

    it("REST: config and policy reads follow the read grant", async () => {
      const granted = vault.engine.createToken("allowed-agent", ["read", "list"]);
      const other = vault.engine.createToken("other-agent", ["read", "list"]);

      for (const path of ["injection-policy", "mcp-server", "connection-config", "policies"]) {
        const ok = await app.request(`/api/v1/secrets/db-prod/${path}`, {
          headers: { authorization: `Bearer ${granted}` },
        });
        expect(ok.status, `granted ${path}`).toBe(200);

        const denied = await app.request(`/api/v1/secrets/db-prod/${path}`, {
          headers: { authorization: `Bearer ${other}` },
        });
        expect(denied.status, `denied ${path}`).toBe(403);
      }
    });

    it("REST: a rotate grant opens the config mutation for that principal only", async () => {
      await vault.engine.createSecret({
        name: "cfg-gated",
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from("cfg-value")),
      });
      const secretId = await vault.engine.resolveSecretId("secret://cfg-gated");
      vault.engine.grantPolicy(
        { secretId, principalType: "agent", principalId: "cfg-admin", permissions: ["rotate"] },
        "it-admin",
      );

      const admin = vault.engine.createToken("cfg-admin", ["rotate", "list"]);
      const ok = await app.request("/api/v1/secrets/cfg-gated/connection-config", {
        method: "PUT",
        headers: { authorization: `Bearer ${admin}`, "content-type": "application/json" },
        body: JSON.stringify({ database: { tls_mode: "require" } }),
      });
      expect(ok.status).toBe(200);
      expect(await vault.engine.getConnectionConfig("secret://cfg-gated")).toMatchObject({
        database: { tls_mode: "require" },
      });

      const outsider = vault.engine.createToken("other-agent", ["rotate", "list"]);
      const denied = await app.request("/api/v1/secrets/cfg-gated/connection-config", {
        method: "DELETE",
        headers: { authorization: `Bearer ${outsider}` },
      });
      expect(denied.status).toBe(403);
      expect(await vault.engine.getConnectionConfig("secret://cfg-gated")).toBeDefined();
    });

    it("REST: policy administration on a gated secret requires an admin grant", async () => {
      const token = vault.engine.createToken("other-agent", ["admin", "list"]);
      const res = await app.request("/api/v1/secrets/db-prod/policies", {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({
          principal_type: "agent",
          principal_id: "other-agent",
          permissions: ["use"],
        }),
      });
      expect(res.status).toBe(403);
      expect(
        vault.engine.listPolicies(dbProdId).some((p) => p.principal_id === "other-agent"),
      ).toBe(false);
    });

    it("MCP wire: no configuration tool exists on the agent surface", async () => {
      const client = await connectMcp(vault.engine.createToken("allowed-agent", ["admin", "list"]));
      const names = (await client.listTools()).tools.map((t) => t.name);

      // Configuration stays on the trusted admin path (CLI/REST) — the agent
      // interface never gained a surface for it, so the engine gate above is
      // the whole story for MCP.
      expect(names).not.toContain("set_injection_policy");
      expect(names.filter((n) => /policy|allowlist|connection|mcp_server/.test(n))).toEqual([]);
    });
  });

  /**
   * W2: enumeration was outside the gate — `db-prod` is read-denied to
   * `other-agent` (403 above), yet its complete metadata row still came back
   * from every listing surface, which is the payload `get_secret_info`
   * refuses. Enumeration now follows the `list` permission.
   */
  describe("enumeration under the gate (W2)", () => {
    let w2GatedId: string;

    beforeAll(async () => {
      await vault.engine.createSecret({
        name: "w2-gated",
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from("w2-value")),
        expiresAt: Date.now() + 2 * 24 * 60 * 60 * 1000,
      });
      await vault.engine.createSecret({
        name: "w2-open",
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from("w2-open-value")),
      });
      w2GatedId = await vault.engine.resolveSecretId("secret://w2-gated");
      vault.engine.grantPolicy(
        {
          secretId: w2GatedId,
          principalType: "agent",
          principalId: "w2-lister",
          permissions: ["list"],
        },
        "it-admin",
      );
    });

    async function restList(token: string): Promise<string[]> {
      const res = await app.request("/api/v1/secrets", {
        headers: { authorization: `Bearer ${token}` },
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { data: Array<{ name: string }> };
      return body.data.map((s) => s.name);
    }

    it("REST: the read-denied secret is no longer enumerable, the open one still is", async () => {
      const other = vault.engine.createToken("other-agent", ["read", "list"]);

      const info = await app.request("/api/v1/secrets/db-prod", {
        headers: { authorization: `Bearer ${other}` },
      });
      expect(info.status).toBe(403);

      const names = await restList(other);
      expect(names).not.toContain("db-prod");
      expect(names).not.toContain("w2-gated");
      expect(names).toContain("w2-open");
    });

    it("REST: the `list` grant — and only it — restores the row", async () => {
      const lister = vault.engine.createToken("w2-lister", ["read", "list"]);
      expect(await restList(lister)).toContain("w2-gated");

      // allowed-agent holds read+use on db-prod but never `list`.
      const readUse = vault.engine.createToken("allowed-agent", ["read", "list"]);
      expect(await restList(readUse)).not.toContain("db-prod");
    });

    it("REST: /health/expiring drops the gated secret for an ungranted principal", async () => {
      const other = vault.engine.createToken("other-agent", ["list"]);
      const res = await app.request("/api/v1/health/expiring?days=7", {
        headers: { authorization: `Bearer ${other}` },
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { data: Array<{ name: string }> };
      expect(body.data.map((s) => s.name)).not.toContain("w2-gated");

      const lister = vault.engine.createToken("w2-lister", ["list"]);
      const ok = await app.request("/api/v1/health/expiring?days=7", {
        headers: { authorization: `Bearer ${lister}` },
      });
      const okBody = (await ok.json()) as { data: Array<{ name: string }> };
      expect(okBody.data.map((s) => s.name)).toContain("w2-gated");
    });

    it("MCP wire: list_secrets and check_secret_health follow the same gate", async () => {
      const deniedClient = await connectMcp(vault.engine.createToken("other-agent", ["list"]));
      const listed = textOf(await deniedClient.callTool({ name: "list_secrets", arguments: {} }));
      expect(listed).not.toContain("w2-gated");
      expect(listed).not.toContain("db-prod");
      expect(listed).toContain("w2-open");

      const health = textOf(
        await deniedClient.callTool({ name: "check_secret_health", arguments: {} }),
      );
      expect(health).not.toContain("w2-gated");

      const listerClient = await connectMcp(vault.engine.createToken("w2-lister", ["list"]));
      const granted = textOf(await listerClient.callTool({ name: "list_secrets", arguments: {} }));
      expect(granted).toContain("w2-gated");
    });

    it("the trusted local path still enumerates everything, silently and with a valid chain", async () => {
      // Minted first: token creation is itself an audited mutation.
      const other = vault.engine.createToken("other-agent", ["list"]);
      const before = vault.engine.queryAudit({}).length;

      const local = vault.engine.listSecrets().map((s) => s.name);
      expect(local).toContain("w2-gated");
      expect(local).toContain("db-prod");

      await restList(other);

      // Enumeration — permitted or filtered — writes no audit row.
      expect(vault.engine.queryAudit({}).length).toBe(before);
      expect(vault.engine.verifyAuditChain().valid).toBe(true);
    });
  });
});
