import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createMcpServer } from "@harpoc/mcp-server";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  AgentStatus,
  AuditEventType,
  ErrorCode,
  IssuedTokenStatus,
  SecretType,
} from "@harpoc/shared";
import type { Agent, AccessPolicy, IssuedToken } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { callTool, parseToolResult } from "./helpers/mcp-helpers.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";

const PASSWORD = "agent-governance-integration-pw";

interface DataBody<T> {
  data: T;
}

interface ErrorBody {
  error: string;
  message: string;
}

interface MatrixResult {
  policy: AccessPolicy | null;
  gated_before: boolean;
  gated_after: boolean;
}

function jtiOf(token: string): string {
  const payload = JSON.parse(
    Buffer.from(token.split(".")[1] as string, "base64url").toString("utf8"),
  ) as { jti: string };
  return payload.jti;
}

/**
 * Agent governance (v1.4) end to end: a real VaultEngine, the real Hono server
 * over a real socket, and the stdio MCP server in process — the first
 * token-bearing stdio harness in this package (`launchToken` rather than
 * `allowTokenless`, which is what makes the per-call revocation recheck
 * observable). One vault for every scenario; each owns its own agents and
 * secrets so the presence gate one scenario flips is invisible to the others.
 */
describe("agent governance end to end", () => {
  let vault: TestVault;
  let server: TestServer;
  let adminToken: string;

  const api = async (path: string, init?: RequestInit): Promise<Response> =>
    fetch(`${server.baseUrl}/api/v1${path}`, init);

  const authHeaders = (token: string): Record<string, string> => ({
    authorization: `Bearer ${token}`,
  });

  const jsonHeaders = (token: string): Record<string, string> => ({
    ...authHeaders(token),
    "content-type": "application/json",
  });

  const bodyOf = async <T>(res: Response): Promise<T> => (await res.json()) as T;

  async function createSecret(name: string): Promise<string> {
    await vault.engine.createSecret({
      name,
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from(`value-of-${name}`)),
    });
    return vault.engine.resolveSecretId(`secret://${name}`);
  }

  beforeAll(async () => {
    vault = createTestVault(mkdtempSync(join(tmpdir(), "harpoc-agov-")));
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "gov-admin");
    adminToken = vault.engine.createToken("gov-admin", ["admin"]);
    server = startTestServer(vault.engine);
  });

  afterAll(async () => {
    await server?.close();
    await destroyTestVault(vault).catch(() => {});
  });

  // -------------------------------------------------------------------------
  // (1) Lifecycle across REST + stdio MCP
  // -------------------------------------------------------------------------
  describe("agent lifecycle across REST and the stdio MCP server", () => {
    let firstToken: string;
    let secondToken: string;
    let mcp: McpServer;

    it("registers over REST, mints a token and serves both surfaces", async () => {
      const registered = await api("/agents", {
        method: "POST",
        headers: jsonHeaders(adminToken),
        body: JSON.stringify({ name: "ci-bot", description: "lifecycle fixture" }),
      });
      expect(registered.status).toBe(201);
      const agent = (await bodyOf<DataBody<Agent>>(registered)).data;
      expect(agent.name).toBe("ci-bot");
      expect(agent.status).toBe(AgentStatus.ACTIVE);

      firstToken = vault.engine.createToken("ci-bot", ["use", "list", "read"]);

      const listed = await api("/secrets", { headers: authHeaders(firstToken) });
      expect(listed.status).toBe(200);

      mcp = createMcpServer({ engine: vault.engine, launchToken: firstToken });
      const tools = await callTool(mcp, "list_secrets", {});
      expect(tools.isError ?? false).toBe(false);
      expect(Array.isArray(parseToolResult(tools, "list_secrets"))).toBe(true);
    });

    it("deactivation revokes the live token on both surfaces", async () => {
      const res = await api("/agents/ci-bot/deactivate", {
        method: "POST",
        headers: authHeaders(adminToken),
      });
      expect(res.status).toBe(200);
      expect((await bodyOf<DataBody<{ revoked_tokens: number }>>(res)).data.revoked_tokens).toBe(1);

      const denied = await api("/secrets", { headers: authHeaders(firstToken) });
      expect(denied.status).toBe(401);
      expect((await bodyOf<ErrorBody>(denied)).error).toBe(ErrorCode.TOKEN_REVOKED);

      // Same server object, still live: the ScopeGuard re-consults the
      // revocation store per call, so the next tool call is refused.
      const refused = await callTool(mcp, "list_secrets", {});
      expect(refused.isError).toBe(true);
      expect(refused.content[0]?.text ?? "").toContain("Token revoked");
    });

    it("reactivation does not resurrect the revoked token, and a fresh one works", async () => {
      const activated = await api("/agents/ci-bot/activate", {
        method: "POST",
        headers: authHeaders(adminToken),
      });
      expect(activated.status).toBe(200);
      expect((await bodyOf<DataBody<Agent>>(activated)).data.status).toBe(AgentStatus.ACTIVE);

      const stillDenied = await api("/secrets", { headers: authHeaders(firstToken) });
      expect(stillDenied.status).toBe(401);
      expect((await bodyOf<ErrorBody>(stillDenied)).error).toBe(ErrorCode.TOKEN_REVOKED);
      expect((await callTool(mcp, "list_secrets", {})).isError).toBe(true);

      secondToken = vault.engine.createToken("ci-bot", ["use", "list", "read"]);
      const allowed = await api("/secrets", { headers: authHeaders(secondToken) });
      expect(allowed.status).toBe(200);

      const freshMcp = createMcpServer({ engine: vault.engine, launchToken: secondToken });
      expect((await callTool(freshMcp, "list_secrets", {})).isError ?? false).toBe(false);
    });

    it("leaves the lifecycle in the issued-token registry and the audit trail", () => {
      const rows = vault.engine.listIssuedTokens({ agent: "ci-bot", status: "all" });
      expect(rows).toHaveLength(2);
      expect(rows.every((row: IssuedToken) => row.agent === "ci-bot")).toBe(true);

      const first = rows.find((row) => row.jti === jtiOf(firstToken));
      const second = rows.find((row) => row.jti === jtiOf(secondToken));
      expect(first?.status).toBe(IssuedTokenStatus.REVOKED);
      expect(first?.revoked_at).not.toBeNull();
      expect(second?.status).toBe(IssuedTokenStatus.ACTIVE);
      expect(second?.revoked_at).toBeNull();

      const registered = vault.engine
        .queryAudit({ eventType: AuditEventType.AGENT_REGISTER })
        .filter((event) => event.detail?.name === "ci-bot");
      expect(registered).toHaveLength(1);
      expect(registered[0]?.success).toBe(true);

      const created = vault.engine
        .queryAudit({ eventType: AuditEventType.TOKEN_CREATE })
        .filter((event) => event.detail?.subject === "ci-bot");
      expect(created).toHaveLength(2);
      expect((created.map((event) => event.detail?.jti) as string[]).sort()).toEqual(
        [jtiOf(firstToken), jtiOf(secondToken)].sort(),
      );

      const revoked = vault.engine
        .queryAudit({ eventType: AuditEventType.TOKEN_REVOKE })
        .filter((event) => event.detail?.jti === jtiOf(firstToken));
      expect(revoked).toHaveLength(1);
      expect(revoked[0]?.detail?.reason).toBe("agent_deactivated");

      const deactivated = vault.engine
        .queryAudit({ eventType: AuditEventType.AGENT_DEACTIVATE })
        .filter((event) => event.detail?.name === "ci-bot");
      expect(deactivated).toHaveLength(1);
      expect(deactivated[0]?.detail?.revoked_tokens).toBe(1);

      expect(vault.engine.verifyAuditChain().valid).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // (2) Unregistered agent principal refused over REST
  // -------------------------------------------------------------------------
  describe("grants naming an unregistered agent are refused over REST", () => {
    let handle: string;

    beforeAll(async () => {
      await createSecret("grant-target");
      handle = "grant-target";
    });

    it("refuses an unregistered agent principal with 404 AGENT_NOT_FOUND", async () => {
      const res = await api(`/secrets/${handle}/policies`, {
        method: "POST",
        headers: jsonHeaders(adminToken),
        body: JSON.stringify({
          principal_type: "agent",
          principal_id: "nobody",
          permissions: ["read"],
        }),
      });
      expect(res.status).toBe(404);
      const failure = await bodyOf<ErrorBody>(res);
      expect(failure.error).toBe(ErrorCode.AGENT_NOT_FOUND);
      expect(failure.message).toContain("nobody");
    });

    it("accepts a tool principal, which the registry does not govern", async () => {
      const res = await api(`/secrets/${handle}/policies`, {
        method: "POST",
        headers: jsonHeaders(adminToken),
        body: JSON.stringify({
          principal_type: "tool",
          principal_id: "x",
          permissions: ["read"],
        }),
      });
      expect(res.status).toBe(201);
      const policy = (await bodyOf<DataBody<AccessPolicy>>(res)).data;
      expect(policy.principal_type).toBe("tool");
      expect(policy.principal_id).toBe("x");
    });
  });

  // -------------------------------------------------------------------------
  // (3) Matrix flip observable through the value path
  // -------------------------------------------------------------------------
  describe("permission-matrix flips are observable on the value path", () => {
    let secretId: string;
    let readerToken: string;
    const handle = "matrix-key";

    const setCell = async (
      agent: string,
      permissions: string[],
      token = adminToken,
    ): Promise<Response> =>
      api(`/agents/${agent}/secrets/${handle}/permissions`, {
        method: "PUT",
        headers: jsonHeaders(token),
        body: JSON.stringify({ permissions }),
      });

    const readValue = async (): Promise<Response> =>
      api(`/secrets/${handle}/value`, { headers: authHeaders(readerToken) });

    beforeAll(async () => {
      secretId = await createSecret(handle);
      registerAgents(vault.engine, "reader", "other");
      readerToken = vault.engine.createToken("reader", ["read"]);
    });

    it("reads the value while the secret is ungated", async () => {
      expect((await readValue()).status).toBe(200);
    });

    it("the first cell write gates the secret and locks the reader out", async () => {
      const res = await setCell("other", ["read"]);
      expect(res.status).toBe(200);
      const flip = (await bodyOf<DataBody<MatrixResult>>(res)).data;
      expect(flip.gated_before).toBe(false);
      expect(flip.gated_after).toBe(true);
      expect(flip.policy?.principal_id).toBe("other");

      const denied = await readValue();
      expect(denied.status).toBe(403);
      expect((await bodyOf<ErrorBody>(denied)).error).toBe(ErrorCode.ACCESS_DENIED);
    });

    it("the gate then applies to the matrix editor itself, as grantPolicy's does", async () => {
      // Design § 5.3: the per-secret `admin` check runs exactly as in
      // grantPolicy — "first grant on a policy-free secret ungated by
      // construction". Once the cell write above gated the secret, the REST
      // admin token is a token-derived caller like any other and needs its own
      // grant; the trusted local path (no caller) is what can still write one.
      const refused = await setCell("reader", ["read"]);
      expect(refused.status).toBe(403);
      const failure = await bodyOf<ErrorBody>(refused);
      expect(failure.error).toBe(ErrorCode.ACCESS_DENIED);
      // The engine's per-secret check, not the interface's token-scope one.
      expect(failure.message).toBe(
        "Access denied: Principal lacks 'admin' permission on this secret",
      );
      const denials = vault.engine
        .queryAudit({ eventType: AuditEventType.POLICY_GRANT, success: false })
        .filter((event) => event.secret_id === secretId && event.detail?.via === "matrix");
      expect(denials).toHaveLength(1);
      expect(denials[0]?.detail?.required_permission).toBe("admin");

      const seeded = vault.engine.setAgentPermissions(
        "gov-admin",
        secretId,
        ["admin"],
        undefined,
        "integration-test",
      );
      expect(seeded.gated_before).toBe(true);
      expect(seeded.gated_after).toBe(true);
    });

    it("granting the reader its cell restores the value read", async () => {
      const res = await setCell("reader", ["read"]);
      expect(res.status).toBe(200);
      const flip = (await bodyOf<DataBody<MatrixResult>>(res)).data;
      expect(flip.gated_before).toBe(true);
      expect(flip.gated_after).toBe(true);

      expect((await readValue()).status).toBe(200);
    });

    it("clearing every cell ungates the secret and the reader reads without a grant", async () => {
      for (const agent of ["reader", "other"]) {
        const cleared = await setCell(agent, []);
        expect(cleared.status).toBe(200);
        const flip = (await bodyOf<DataBody<MatrixResult>>(cleared)).data;
        expect(flip.policy).toBeNull();
        expect(flip.gated_after).toBe(true);
      }

      const last = await setCell("gov-admin", []);
      expect(last.status).toBe(200);
      const flip = (await bodyOf<DataBody<MatrixResult>>(last)).data;
      expect(flip.gated_before).toBe(true);
      expect(flip.gated_after).toBe(false);

      const listed = await api("/agents/reader/policies", { headers: authHeaders(adminToken) });
      expect(listed.status).toBe(200);
      expect((await bodyOf<DataBody<unknown[]>>(listed)).data).toHaveLength(0);

      expect((await readValue()).status).toBe(200);
    });
  });

  // -------------------------------------------------------------------------
  // (4) Delete cascade
  // -------------------------------------------------------------------------
  describe("deleting an agent cascades over tokens and grants", () => {
    let doomedToken: string;

    beforeAll(async () => {
      const first = await createSecret("cascade-a");
      const second = await createSecret("cascade-b");
      registerAgents(vault.engine, "doomed");
      for (const secretId of [first, second]) {
        vault.engine.grantPolicy(
          {
            secretId,
            principalType: "agent",
            principalId: "doomed",
            permissions: ["read"],
          },
          "integration-test",
        );
      }
      doomedToken = vault.engine.createToken("doomed", ["read"]);
    });

    it("revokes the live token, removes both grants and forgets the agent", async () => {
      expect(vault.engine.listAgentPolicies("doomed")).toHaveLength(2);

      const res = await api("/agents/doomed", {
        method: "DELETE",
        headers: authHeaders(adminToken),
      });
      expect(res.status).toBe(200);
      expect(
        (await bodyOf<DataBody<{ revoked_tokens: number; removed_grants: number }>>(res)).data,
      ).toEqual({ revoked_tokens: 1, removed_grants: 2 });

      const gone = await api("/agents/doomed", { headers: authHeaders(adminToken) });
      expect(gone.status).toBe(404);
      expect((await bodyOf<ErrorBody>(gone)).error).toBe(ErrorCode.AGENT_NOT_FOUND);

      const withToken = await api("/secrets", { headers: authHeaders(doomedToken) });
      expect(withToken.status).toBe(401);
      expect((await bodyOf<ErrorBody>(withToken)).error).toBe(ErrorCode.TOKEN_REVOKED);
    });

    it("keeps the issued-token row with a null agent and revoked status", async () => {
      const res = await api("/tokens?status=all", { headers: authHeaders(adminToken) });
      expect(res.status).toBe(200);
      const rows = (await bodyOf<DataBody<IssuedToken[]>>(res)).data;

      const row = rows.find((entry) => entry.jti === jtiOf(doomedToken));
      expect(row).toBeDefined();
      expect(row?.subject).toBe("doomed");
      expect(row?.agent).toBeNull();
      expect(row?.status).toBe(IssuedTokenStatus.REVOKED);
      expect(row?.revoked_at).not.toBeNull();
    });

    it("audits the deletion with the counts it performed", () => {
      const deleted = vault.engine
        .queryAudit({ eventType: AuditEventType.AGENT_DELETE })
        .filter((event) => event.detail?.name === "doomed");
      expect(deleted).toHaveLength(1);
      expect(deleted[0]?.detail?.revoked_tokens).toBe(1);
      expect(deleted[0]?.detail?.removed_grants).toBe(2);

      const revocations = vault.engine
        .queryAudit({ eventType: AuditEventType.POLICY_REVOKE })
        .filter((event) => event.detail?.reason === "agent_deleted");
      expect(revocations).toHaveLength(2);

      expect(vault.engine.verifyAuditChain().valid).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // (5) Admin gate on every governance surface
  // -------------------------------------------------------------------------
  describe("governance surfaces are admin-gated", () => {
    let readToken: string;

    beforeAll(async () => {
      await createSecret("gate-key");
      registerAgents(vault.engine, "onlooker");
      readToken = vault.engine.createToken("onlooker", ["read", "list"]);
    });

    it("refuses the agent registry, the token registry and the matrix cell", async () => {
      const agents = await api("/agents", { headers: authHeaders(readToken) });
      expect(agents.status).toBe(403);
      expect((await bodyOf<ErrorBody>(agents)).error).toBe(ErrorCode.ACCESS_DENIED);

      const tokens = await api("/tokens", { headers: authHeaders(readToken) });
      expect(tokens.status).toBe(403);
      expect((await bodyOf<ErrorBody>(tokens)).error).toBe(ErrorCode.ACCESS_DENIED);

      const cell = await api("/agents/onlooker/secrets/gate-key/permissions", {
        method: "PUT",
        headers: jsonHeaders(readToken),
        body: JSON.stringify({ permissions: ["read"] }),
      });
      expect(cell.status).toBe(403);
      expect((await bodyOf<ErrorBody>(cell)).error).toBe(ErrorCode.ACCESS_DENIED);

      // Refused at the interface, before the engine: no cell was written.
      expect(vault.engine.listAgentPolicies("onlooker")).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // (6) R7: an admin-scoped user token is exempt from the per-secret gate
  // -------------------------------------------------------------------------
  describe("an admin-scoped user token is exempt from the per-secret gate", () => {
    const handle = "r7-gated";
    let userAdminToken: string;
    let agentAdminToken: string;

    const setCell = async (
      agent: string,
      permissions: string[],
      token: string,
    ): Promise<Response> =>
      api(`/agents/${agent}/secrets/${handle}/permissions`, {
        method: "PUT",
        headers: jsonHeaders(token),
        body: JSON.stringify({ permissions }),
      });

    const listedNames = async (token: string): Promise<string[]> => {
      const res = await api("/secrets", { headers: authHeaders(token) });
      expect(res.status).toBe(200);
      return (await bodyOf<DataBody<{ name: string }[]>>(res)).data.map((secret) => secret.name);
    };

    beforeAll(async () => {
      const secretId = await createSecret(handle);
      registerAgents(vault.engine, "r7-cell", "r7-admin");
      // Trusted local path (no caller): the secret is gated before any token
      // touches it, so what the assertions below observe is the exemption and
      // not a first-cell-on-an-ungated-secret pass.
      const gated = vault.engine.setAgentPermissions(
        "r7-cell",
        secretId,
        ["read"],
        undefined,
        "integration-test",
      );
      expect(gated.gated_after).toBe(true);

      userAdminToken = vault.engine.createToken("web-ui", ["admin"], 60_000, {
        principalType: "user",
      });
      agentAdminToken = vault.engine.createToken("r7-admin", ["admin"]);
    });

    it("writes a matrix cell on the gated secret it holds no grant on (was 403)", async () => {
      const res = await setCell("r7-cell", ["read", "use"], userAdminToken);
      expect(res.status).toBe(200);
      const flip = (await bodyOf<DataBody<MatrixResult>>(res)).data;
      expect(flip.gated_before).toBe(true);
      expect(flip.gated_after).toBe(true);
      expect(flip.policy?.principal_id).toBe("r7-cell");
      expect([...(flip.policy?.permissions ?? [])].sort()).toEqual(["read", "use"]);
    });

    it("still enumerates the gated secret (the W2 half of the same exemption)", async () => {
      expect(await listedNames(userAdminToken)).toContain(handle);
    });

    it("leaves an agent-typed admin token refused and blind — gating is unchanged", async () => {
      const refused = await setCell("r7-cell", ["read"], agentAdminToken);
      expect(refused.status).toBe(403);
      const failure = await bodyOf<ErrorBody>(refused);
      expect(failure.error).toBe(ErrorCode.ACCESS_DENIED);
      // The engine's per-secret check, not the interface's token-scope one.
      expect(failure.message).toBe(
        "Access denied: Principal lacks 'admin' permission on this secret",
      );

      expect(await listedNames(agentAdminToken)).not.toContain(handle);

      // The refusal wrote nothing: the user-admin cell above still stands.
      const policies = vault.engine.listAgentPolicies("r7-cell");
      expect(policies).toHaveLength(1);
      expect([...(policies[0]?.permissions ?? [])].sort()).toEqual(["read", "use"]);
    });
  });
});
