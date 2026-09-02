import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ErrorCode, injectionPolicyInputSchema } from "@harpoc/shared";
import type { OAuthTokenStatus, SetAgentPermissionsInput } from "@harpoc/shared";
import { RestClient } from "./rest-client.js";

const BASE_URL = "http://localhost:3000";
const TOKEN = "test-jwt-token";

const FULL_POLICY = {
  url_allowlist: [] as string[],
  command_allowlist: ["gh"],
  env_allowlist: [] as string[],
  host_allowlist: [] as string[],
  response_mode: "filtered" as const,
  response_header_allowlist: [] as string[],
  network_isolation: false,
  fs_isolation: false,
  smtp_recipient_allowlist: [] as string[],
  imap_read_only: false,
};

let client: RestClient;
let fetchSpy: ReturnType<typeof vi.fn>;

function mockFetchResponse(data: unknown, status = 200) {
  fetchSpy.mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    json: async () => (status >= 200 && status < 300 ? { data } : data),
  });
}

beforeEach(() => {
  fetchSpy = vi.fn();
  vi.stubGlobal("fetch", fetchSpy);
  client = new RestClient({ baseUrl: BASE_URL, token: TOKEN });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("RestClient", () => {
  describe("listSecrets", () => {
    it("sends GET /api/v1/secrets", async () => {
      mockFetchResponse([]);
      const result = await client.listSecrets();

      expect(result).toEqual([]);
      expect(fetchSpy).toHaveBeenCalledWith(
        `${BASE_URL}/api/v1/secrets`,
        expect.objectContaining({ method: "GET" }),
      );
    });

    it("includes project query param", async () => {
      mockFetchResponse([]);
      await client.listSecrets("myproj");

      expect(fetchSpy).toHaveBeenCalledWith(
        `${BASE_URL}/api/v1/secrets?project=myproj`,
        expect.anything(),
      );
    });
  });

  describe("getSecretInfo", () => {
    it("sends GET /api/v1/secrets/:handle", async () => {
      const info = { handle: "secret://key", name: "key" };
      mockFetchResponse(info);
      const result = await client.getSecretInfo("secret://key");

      expect(result).toEqual(info);
      expect(fetchSpy).toHaveBeenCalledWith(`${BASE_URL}/api/v1/secrets/key`, expect.anything());
    });

    it("encodes project/name handles", async () => {
      mockFetchResponse({});
      await client.getSecretInfo("secret://proj/key");

      expect(fetchSpy).toHaveBeenCalledWith(
        `${BASE_URL}/api/v1/secrets/proj%2Fkey`,
        expect.anything(),
      );
    });
  });

  describe("getSecretValue", () => {
    it("returns Uint8Array from base64 response", async () => {
      const b64 = Buffer.from("secret-val").toString("base64");
      mockFetchResponse({ value: b64 });
      const result = await client.getSecretValue("secret://key");

      expect(Buffer.from(result).toString()).toBe("secret-val");
    });
  });

  describe("createSecret", () => {
    it("sends POST with body", async () => {
      const response = { handle: "secret://k", status: "created", message: "OK" };
      mockFetchResponse(response);

      const result = await client.createSecret({ name: "k", type: "api_key", expires_at: 123 });
      expect(result).toEqual(response);

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/secrets`);
      expect(call[1].method).toBe("POST");
      const body = JSON.parse(call[1].body as string);
      expect(body.name).toBe("k");
      expect(body.expires_at).toBe(123);
    });

    it("encodes value as base64", async () => {
      mockFetchResponse({});
      await client.createSecret({
        name: "k",
        type: "api_key",
        value: new Uint8Array([1, 2, 3]),
      });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string);
      expect(body.value).toBe(Buffer.from([1, 2, 3]).toString("base64"));
    });
  });

  describe("rotateSecret", () => {
    it("sends POST with base64 value", async () => {
      mockFetchResponse({ rotated: true });
      await client.rotateSecret("secret://k", new Uint8Array([4, 5, 6]));

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/rotate");
      const body = JSON.parse(call[1].body as string);
      expect(body.value).toBe(Buffer.from([4, 5, 6]).toString("base64"));
    });
  });

  describe("revokeSecret", () => {
    it("sends DELETE with confirm=true", async () => {
      mockFetchResponse({ revoked: true });
      await client.revokeSecret("secret://k");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k?confirm=true");
      expect(call[1].method).toBe("DELETE");
    });
  });

  describe("useSecret", () => {
    it("posts the action to the /use endpoint", async () => {
      mockFetchResponse({ type: "http", status: 200, body: "ok" });
      await client.useSecret("secret://k", {
        type: "http",
        method: "GET",
        url: "https://api.example.com",
        timeout_ms: 5000,
        injection: { type: "bearer" },
        follow_redirects: "none",
      });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/use");
      const body = JSON.parse(call[1].body as string);
      expect(body.action.type).toBe("http");
      expect(body.action.timeout_ms).toBe(5000);
      expect(body.action.follow_redirects).toBe("none");
    });

    it("posts a process action", async () => {
      mockFetchResponse({ type: "process", exit_code: 0, stdout: "", stderr: "" });
      await client.useSecret("secret://k", {
        type: "process",
        command: "gh",
        args: ["api"],
        env_var: "GH_TOKEN",
      });
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string);
      expect(body.action.type).toBe("process");
      expect(body.action.command).toBe("gh");
    });
  });

  describe("injection policy", () => {
    it("setInjectionPolicy sends PUT with the allowlists", async () => {
      mockFetchResponse({ updated: true });
      await client.setInjectionPolicy("secret://k", {
        ...FULL_POLICY,
        url_allowlist: ["https://api.github.com/*"],
        command_allowlist: ["gh"],
      });
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/injection-policy");
      expect(call[1].method).toBe("PUT");
      const body = JSON.parse(call[1].body as string);
      expect(body.command_allowlist).toEqual(["gh"]);
    });

    it("setInjectionPolicy forwards response_mode and response_header_allowlist", async () => {
      mockFetchResponse({ updated: true });
      await client.setInjectionPolicy("secret://k", {
        ...FULL_POLICY,
        response_mode: "status_only",
        response_header_allowlist: ["Content-Type"],
      });
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string);
      expect(body.response_mode).toBe("status_only");
      expect(body.response_header_allowlist).toEqual(["Content-Type"]);
    });

    it("setInjectionPolicy forwards network_isolation in the body", async () => {
      mockFetchResponse({ updated: true });
      await client.setInjectionPolicy("secret://k", {
        ...FULL_POLICY,
        network_isolation: true,
      });
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string);
      expect(body.network_isolation).toBe(true);
    });

    it("setInjectionPolicy forwards fs_isolation in the body", async () => {
      mockFetchResponse({ updated: true });
      await client.setInjectionPolicy("secret://k", {
        ...FULL_POLICY,
        fs_isolation: true,
      });
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string);
      expect(body.fs_isolation).toBe(true);
    });

    it("compile-time pin: setInjectionPolicy takes the whole policy — a partial is refused by the type (R3)", async () => {
      mockFetchResponse({ updated: true });
      // @ts-expect-error — InjectionPolicy requires every field
      await client.setInjectionPolicy("secret://k", { url_allowlist: [] });
      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });

    it("setInjectionPolicy sends every policy field on every call — nothing is left for a server default", async () => {
      mockFetchResponse({ updated: true });
      await client.setInjectionPolicy("secret://k", FULL_POLICY);
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string) as Record<string, unknown>;
      expect(Object.keys(body).sort()).toEqual(
        [...Object.keys(injectionPolicyInputSchema.shape), "acknowledge_interpreters"].sort(),
      );
    });

    it("setInjectionPolicy forwards the v1.3 mail fields", async () => {
      mockFetchResponse({ updated: true });
      await client.setInjectionPolicy("secret://k", {
        ...FULL_POLICY,
        smtp_recipient_allowlist: ["*@corp.example"],
        imap_read_only: true,
      });
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string);
      expect(body.smtp_recipient_allowlist).toEqual(["*@corp.example"]);
      expect(body.imap_read_only).toBe(true);
    });

    it("setInjectionPolicy serializes every injectionPolicyInputSchema key when supplied (drift pin)", async () => {
      mockFetchResponse({ updated: true });
      const full = {
        url_allowlist: ["https://a.example/*"],
        command_allowlist: ["gh"],
        env_allowlist: ["CI"],
        host_allowlist: ["db.example:5432"],
        response_mode: "full" as const,
        response_header_allowlist: ["x-request-id"],
        network_isolation: true,
        fs_isolation: true,
        smtp_recipient_allowlist: ["*@corp.example"],
        imap_read_only: true,
      };
      await client.setInjectionPolicy("secret://k", full);
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string) as Record<string, unknown>;
      for (const key of Object.keys(injectionPolicyInputSchema.shape)) {
        expect(body, key).toHaveProperty(key);
      }
    });

    it("setInjectionPolicy defaults acknowledge_interpreters to false in the body", async () => {
      mockFetchResponse({ updated: true });
      await client.setInjectionPolicy("secret://k", FULL_POLICY);
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string);
      expect(body.acknowledge_interpreters).toBe(false);
    });

    it("setInjectionPolicy carries the interpreter acknowledgement in the body", async () => {
      mockFetchResponse({ updated: true });
      await client.setInjectionPolicy(
        "secret://k",
        { ...FULL_POLICY, command_allowlist: ["python"] },
        { acknowledge_interpreters: true },
      );
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string);
      expect(body.acknowledge_interpreters).toBe(true);
    });

    it("getInjectionPolicy sends GET", async () => {
      mockFetchResponse({ url_allowlist: [], command_allowlist: ["gh"], env_allowlist: [] });
      const policy = await client.getInjectionPolicy("secret://k");
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/injection-policy");
      expect(policy.command_allowlist).toEqual(["gh"]);
    });

    it("setMcpServerConfig sends PUT with the config", async () => {
      mockFetchResponse({ updated: true });
      await client.setMcpServerConfig("secret://k", {
        server_name: "github-mcp",
        transport: "stdio",
        command: "node",
        args: ["server.js"],
        env_var: "GITHUB_TOKEN",
      });
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/mcp-server");
      expect(call[1].method).toBe("PUT");
      const body = JSON.parse(call[1].body as string);
      expect(body.server_name).toBe("github-mcp");
      expect(body.env_var).toBe("GITHUB_TOKEN");
    });

    it("getMcpServerConfig sends GET and maps null to undefined", async () => {
      mockFetchResponse(null);
      const config = await client.getMcpServerConfig("secret://k");
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/mcp-server");
      expect(config).toBeUndefined();
    });
  });

  describe("policies", () => {
    it("grantPolicy sends POST", async () => {
      mockFetchResponse({ id: "p1" });
      await client.grantPolicy("secret://k", {
        principal_type: "agent",
        principal_id: "a1",
        permissions: ["read"],
      });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/policies");
      const body = JSON.parse(call[1].body as string);
      expect(body.principal_type).toBe("agent");
    });

    it("revokePolicy sends DELETE", async () => {
      mockFetchResponse({ revoked: true });
      await client.revokePolicy("secret://k", "p1");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/policies/p1");
      expect(call[1].method).toBe("DELETE");
    });

    it("listPolicies sends GET", async () => {
      mockFetchResponse([]);
      await client.listPolicies("secret://k");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/policies");
      expect(call[1].method).toBe("GET");
    });
  });

  describe("queryAudit", () => {
    it("sends GET with query params", async () => {
      mockFetchResponse([]);
      await client.queryAudit({
        secretId: "uuid-1",
        eventType: "secret.read",
        limit: 10,
      });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("secret_id=uuid-1");
      expect(call[0]).toContain("event_type=secret.read");
      expect(call[0]).toContain("limit=10");
    });

    it("sends GET without params when options omitted", async () => {
      mockFetchResponse([]);
      await client.queryAudit();

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/audit`);
    });

    it("forwards success, principalType and principalId", async () => {
      mockFetchResponse([]);
      await client.queryAudit({ success: false, principalType: "agent", principalId: "x" });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(
        `${BASE_URL}/api/v1/audit?success=false&principal_type=agent&principal_id=x`,
      );
    });

    it("sends no principal_id param for an empty-string principalId (server rejects empty)", async () => {
      mockFetchResponse([]);
      await client.queryAudit({ principalId: "" });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/audit`);
    });
  });

  describe("agent governance", () => {
    it("registerAgent sends POST /api/v1/agents", async () => {
      mockFetchResponse({ id: "agent-1", name: "deploy-bot" }, 201);
      const input = { name: "deploy-bot", description: "d" };
      await client.registerAgent(input);

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/agents`);
      expect(call[1].method).toBe("POST");
      expect(JSON.parse(call[1].body as string)).toEqual(input);
    });

    it("listAgents sends GET /api/v1/agents without params when status omitted", async () => {
      mockFetchResponse([]);
      await client.listAgents();

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/agents`);
      expect(call[1].method).toBe("GET");
    });

    it("listAgents sends GET /api/v1/agents?status=", async () => {
      mockFetchResponse([]);
      await client.listAgents("all");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/agents?status=all`);
    });

    it("getAgent sends GET /api/v1/agents/:name", async () => {
      mockFetchResponse({ id: "agent-1", name: "deploy-bot" });
      await client.getAgent("deploy-bot");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/agents/deploy-bot`);
      expect(call[1].method).toBe("GET");
    });

    it("getAgent encodeURIComponent's the name", async () => {
      mockFetchResponse({ id: "agent-1", name: "a b" });
      await client.getAgent("a b");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/agents/${encodeURIComponent("a b")}`);
    });

    it("updateAgent sends PUT /api/v1/agents/:name with the body", async () => {
      mockFetchResponse({ id: "agent-1", name: "deploy-bot", description: "updated" });
      const input = { description: "updated" };
      await client.updateAgent("deploy-bot", input);

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/agents/deploy-bot`);
      expect(call[1].method).toBe("PUT");
      expect(JSON.parse(call[1].body as string)).toEqual(input);
    });

    it("deactivateAgent sends a bodyless POST", async () => {
      mockFetchResponse({ revoked_tokens: 2 });
      const result = await client.deactivateAgent("deploy-bot");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/agents/deploy-bot/deactivate`);
      expect(call[1].method).toBe("POST");
      expect(call[1].body).toBeUndefined();
      expect(result).toEqual({ revoked_tokens: 2 });
    });

    it("activateAgent sends a bodyless POST", async () => {
      mockFetchResponse({ id: "agent-1", name: "deploy-bot" });
      await client.activateAgent("deploy-bot");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/agents/deploy-bot/activate`);
      expect(call[1].method).toBe("POST");
      expect(call[1].body).toBeUndefined();
    });

    it("deleteAgent sends DELETE /api/v1/agents/:name", async () => {
      mockFetchResponse({ revoked_tokens: 1, removed_grants: 3 });
      const result = await client.deleteAgent("deploy-bot");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/agents/deploy-bot`);
      expect(call[1].method).toBe("DELETE");
      expect(result).toEqual({ revoked_tokens: 1, removed_grants: 3 });
    });

    it("listAgentPolicies sends GET /api/v1/agents/:name/policies", async () => {
      mockFetchResponse([]);
      await client.listAgentPolicies("deploy-bot");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/agents/deploy-bot/policies`);
      expect(call[1].method).toBe("GET");
    });

    it("setAgentPermissions sends PUT to the encoded handle path with the body", async () => {
      mockFetchResponse({ policy: null, gated_before: false, gated_after: false });
      const input: SetAgentPermissionsInput = { permissions: ["read"] };
      await client.setAgentPermissions("deploy-bot", "secret://proj/key", input);

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(
        `${BASE_URL}/api/v1/agents/deploy-bot/secrets/${encodeURIComponent("proj/key")}/permissions`,
      );
      expect(call[1].method).toBe("PUT");
      expect(JSON.parse(call[1].body as string)).toEqual(input);
    });

    it("setAgentPermissions strips the secret:// prefix via encodeHandle", async () => {
      mockFetchResponse({ policy: null, gated_before: false, gated_after: false });
      await client.setAgentPermissions("deploy-bot", "secret://key", { permissions: [] });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/agents/deploy-bot/secrets/key/permissions`);
    });
  });

  describe("issued tokens", () => {
    it("listTokens sends GET /api/v1/tokens without params when omitted", async () => {
      mockFetchResponse([]);
      await client.listTokens();

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/tokens`);
      expect(call[1].method).toBe("GET");
    });

    it("listTokens encodes the agent and status query params", async () => {
      mockFetchResponse([]);
      await client.listTokens({ agent: "a b", status: "all" });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const url = new URL(call[0]);
      expect(url.pathname).toBe("/api/v1/tokens");
      expect(url.searchParams.get("agent")).toBe("a b");
      expect(url.searchParams.get("status")).toBe("all");
    });

    it("sends no agent param for an empty-string agent (server rejects empty)", async () => {
      mockFetchResponse([]);
      await client.listTokens({ agent: "", status: "all" });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/tokens?status=all`);
    });

    it("revokeToken sends DELETE /api/v1/tokens/:jti", async () => {
      mockFetchResponse({ revoked: true });
      await client.revokeToken("jti-1");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/tokens/jti-1`);
      expect(call[1].method).toBe("DELETE");
    });

    it("revokeToken encodeURIComponent's the jti", async () => {
      mockFetchResponse({ revoked: true });
      await client.revokeToken("a/b");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/tokens/${encodeURIComponent("a/b")}`);
    });
  });

  describe("getHealth", () => {
    it("sends GET /api/v1/health", async () => {
      mockFetchResponse({ state: "unlocked", version: "1.0.0" });
      const result = await client.getHealth();

      expect(result.state).toBe("unlocked");
      expect(result.version).toBe("1.0.0");
    });
  });

  describe("oauth", () => {
    it("startOAuthFlow posts the input verbatim to /api/v1/oauth/authorize", async () => {
      mockFetchResponse(
        {
          handle: "secret://gh",
          status: "authorized",
          message: "Client credentials flow completed for github",
        },
        201,
      );

      const input = {
        name: "gh",
        provider: "github" as const,
        grant_type: "client_credentials" as const,
        client_id: "cid",
        client_secret: "csec",
        token_endpoint_auth_method: "client_secret_basic" as const,
        scopes: ["repo"],
        project: "proj",
      };
      const result = await client.startOAuthFlow(input);

      expect(result).toEqual({
        handle: "secret://gh",
        status: "authorized",
        message: "Client credentials flow completed for github",
      });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/oauth/authorize`);
      expect(call[1].method).toBe("POST");
      expect(JSON.parse(call[1].body as string)).toEqual(input);
    });

    it("startOAuthFlow returns the device-code fields the route sends", async () => {
      mockFetchResponse(
        {
          handle: "secret://gh",
          status: "pending_authorization",
          auth_url: "https://github.com/login/device",
          user_code: "ABCD-1234",
          message: "Please visit https://github.com/login/device and enter code: ABCD-1234",
        },
        201,
      );

      const result = await client.startOAuthFlow({
        name: "gh",
        provider: "github",
        grant_type: "device_code",
        client_id: "cid",
      });

      expect(result.status).toBe("pending_authorization");
      expect(result.user_code).toBe("ABCD-1234");
      expect(result.auth_url).toBe("https://github.com/login/device");
    });

    it("getOAuthStatus sends GET /api/v1/oauth/:handle/status", async () => {
      const status: OAuthTokenStatus = {
        secret_id: "uuid-1",
        provider: "github",
        has_access_token: true,
        access_token_expires_at: 4000,
        has_refresh_token: true,
        last_refreshed_at: 3000,
        refresh_status: "ok",
        token_endpoint_auth_method: "client_secret_post",
      };
      mockFetchResponse(status);

      const result = await client.getOAuthStatus("secret://gh");

      expect(result).toEqual(status);
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/oauth/gh/status`);
      expect(call[1].method).toBe("GET");
    });

    it("refreshOAuthToken posts to the refresh route and returns expires_at", async () => {
      mockFetchResponse({ refreshed: true, expires_at: 1234 });

      const result = await client.refreshOAuthToken("secret://proj/gh");

      expect(result).toBe(1234);
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/oauth/proj%2Fgh/refresh`);
      expect(call[1].method).toBe("POST");
    });

    it("refreshOAuthToken returns null when the route reports no expiry", async () => {
      mockFetchResponse({ refreshed: true, expires_at: null });
      expect(await client.refreshOAuthToken("secret://gh")).toBeNull();
    });
  });

  describe("certificates", () => {
    it("importCertificate posts { name, ...input } and maps secret_id to secretId", async () => {
      mockFetchResponse({ handle: "secret://web", secret_id: "uuid-1" }, 201);

      const result = await client.importCertificate("web", {
        private_key_pem: "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----",
        chain_pem: "-----BEGIN CERTIFICATE-----\ni\n-----END CERTIFICATE-----",
        project: "proj",
        auto_renew: true,
        renew_before_days: 14,
      });

      expect(result).toEqual({ handle: "secret://web", secretId: "uuid-1" });
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/certificates/import`);
      expect(call[1].method).toBe("POST");
      expect(JSON.parse(call[1].body as string)).toEqual({
        name: "web",
        private_key_pem: "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----",
        chain_pem: "-----BEGIN CERTIFICATE-----\ni\n-----END CERTIFICATE-----",
        project: "proj",
        auto_renew: true,
        renew_before_days: 14,
      });
    });

    // auto_renew / renew_before_days carry schema defaults, so the caller may
    // omit them — and the client must not invent values the route would then
    // treat as a deliberate choice.
    it("importCertificate omits the defaulted fields the caller left out", async () => {
      mockFetchResponse({ handle: "secret://web", secret_id: "uuid-1" }, 201);

      await client.importCertificate("web", {
        private_key_pem: "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----",
      });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string) as Record<string, unknown>;
      expect(Object.keys(body).sort()).toEqual(["certificate_pem", "name", "private_key_pem"]);
      expect("auto_renew" in body).toBe(false);
      expect("renew_before_days" in body).toBe(false);
    });

    it("generateCsr posts { name, ...input } and maps csr_pem to csrPem", async () => {
      mockFetchResponse(
        { handle: "secret://web", csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nr\n" },
        201,
      );

      const result = await client.generateCsr("web", {
        subject: "web.example.com",
        sans: ["www.example.com"],
        algorithm: "rsa",
        bits: 4096,
        project: "proj",
      });

      expect(result).toEqual({
        handle: "secret://web",
        csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nr\n",
      });
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/certificates/csr`);
      expect(JSON.parse(call[1].body as string)).toEqual({
        name: "web",
        subject: "web.example.com",
        sans: ["www.example.com"],
        algorithm: "rsa",
        bits: 4096,
        project: "proj",
      });
    });

    it("renewCertificate posts to the renew route with no body (B23/B24)", async () => {
      const status = {
        secret_id: "uuid-1",
        subject: "CN=web.example.com",
        issuer: "CN=Test CA",
        not_before: 1000,
        not_after: 2000,
        auto_renew: true,
        renewal_status: "ok",
      };
      mockFetchResponse(status);

      const result = await client.renewCertificate("secret://web");

      expect(result).toEqual(status);
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/certificates/web/renew`);
      expect(call[1].method).toBe("POST");
      expect(call[1].body).toBeUndefined();
      expect((call[1].headers as Record<string, string>)["content-type"]).toBeUndefined();
    });

    it("getCertificateStatus sends GET /api/v1/certificates/:handle/status", async () => {
      mockFetchResponse({ secret_id: "uuid-1", renewal_status: "expiring_soon" });

      const result = await client.getCertificateStatus("secret://web");

      expect(result.renewal_status).toBe("expiring_soon");
      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/certificates/web/status`);
      expect(call[1].method).toBe("GET");
    });
  });

  describe("error handling", () => {
    it("maps error responses to VaultError with correct code", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({ error: ErrorCode.SECRET_NOT_FOUND, message: "Not found" }),
      });

      await expect(client.getSecretInfo("secret://missing")).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.SECRET_NOT_FOUND, message: "Not found" }),
      );
    });

    it("maps 401 responses to VaultError", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: ErrorCode.TOKEN_EXPIRED, message: "Token expired" }),
      });

      await expect(client.listSecrets()).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.TOKEN_EXPIRED }),
      );
    });

    it("maps 503 responses to VaultError", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: async () => ({ error: ErrorCode.VAULT_LOCKED, message: "Vault is locked" }),
      });

      await expect(client.listSecrets()).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.VAULT_LOCKED }),
      );
    });

    it("falls back to INTERNAL_ERROR when error field is missing", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => ({ message: "Something broke" }),
      });

      await expect(client.listSecrets()).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.INTERNAL_ERROR }),
      );
    });

    it("sets Authorization header on all requests", async () => {
      mockFetchResponse([]);
      await client.listSecrets();

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const headers = call[1].headers as Record<string, string>;
      expect(headers.authorization).toBe(`Bearer ${TOKEN}`);
    });
  });
});

describe("request timeout (code review Low O0)", () => {
  it("aborts a request against a server that never responds", async () => {
    vi.unstubAllGlobals(); // this test needs the real fetch against a real hung server

    const { createServer } = await import("node:http");
    const hung = createServer(() => {
      // never respond
    });
    await new Promise<void>((resolve) => {
      hung.listen(0, "127.0.0.1", () => resolve());
    });
    const { port } = hung.address() as { port: number };

    const slowClient = new RestClient({
      baseUrl: `http://127.0.0.1:${port}`,
      token: "t",
      timeoutMs: 250,
    });

    try {
      await expect(slowClient.listSecrets()).rejects.toMatchObject({
        code: ErrorCode.INTERNAL_ERROR,
        message: expect.stringContaining("timed out"),
      });
    } finally {
      hung.closeAllConnections();
      hung.close();
    }
  });
});
