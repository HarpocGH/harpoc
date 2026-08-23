import { describe, expect, it, vi } from "vitest";
import { ApiError, createApiClient } from "./client";

type FetchMock = ReturnType<typeof vi.fn>;

function stubFetch(status: number, body: unknown) {
  return vi.fn(
    async () => new Response(JSON.stringify(body), { status }),
  ) as unknown as typeof fetch;
}

function callOf(fetchFn: typeof fetch, index = 0): { url: string; init: RequestInit } {
  const call = (fetchFn as unknown as FetchMock).mock.calls[index] as [
    string,
    RequestInit | undefined,
  ];
  return { url: call[0], init: call[1] ?? {} };
}

function headersOf(init: RequestInit): Record<string, string> {
  return (init.headers ?? {}) as Record<string, string>;
}

describe("api client", () => {
  it("sends the Bearer token and unwraps the data envelope", async () => {
    const fetchFn = stubFetch(200, { data: [{ name: "k1" }] });
    const api = createApiClient(() => "jwt-1", fetchFn);
    const secrets = await api.listSecrets();
    expect(secrets).toEqual([{ name: "k1" }]);
    expect(headersOf(callOf(fetchFn).init)["Authorization"]).toBe("Bearer jwt-1");
  });

  it("omits the Authorization header when no token is held", async () => {
    const fetchFn = stubFetch(200, { data: [] });
    const api = createApiClient(() => null, fetchFn);
    await api.listSecrets();
    expect(headersOf(callOf(fetchFn).init)["Authorization"]).toBeUndefined();
  });

  it("maps error envelopes to ApiError with status and code", async () => {
    const api = createApiClient(
      () => "jwt-1",
      stubFetch(403, { error: "ACCESS_DENIED", message: "no" }),
    );
    await expect(api.listSecrets()).rejects.toMatchObject({ status: 403, code: "ACCESS_DENIED" });
    await expect(api.listSecrets()).rejects.toBeInstanceOf(ApiError);
  });

  it("falls back to UNKNOWN when the error body is not JSON", async () => {
    const fetchFn = vi.fn(
      async () => new Response("<html>502</html>", { status: 502, statusText: "Bad Gateway" }),
    ) as unknown as typeof fetch;
    const api = createApiClient(() => "t", fetchFn);
    await expect(api.listSecrets()).rejects.toMatchObject({ status: 502, code: "UNKNOWN" });
  });

  it("builds the audit query string including success", async () => {
    const fetchFn = stubFetch(200, { data: [] });
    const api = createApiClient(() => "t", fetchFn);
    await api.queryAudit({ event_type: "secret.use", success: false, limit: 50 });
    // URLSearchParams preserves insertion order = the filter object's key order.
    expect(callOf(fetchFn).url).toBe("/api/v1/audit?event_type=secret.use&success=false&limit=50");
  });

  it("omits undefined audit filters and the empty query string", async () => {
    const fetchFn = stubFetch(200, { data: [] });
    const api = createApiClient(() => "t", fetchFn);
    await api.queryAudit({});
    expect(callOf(fetchFn).url).toBe("/api/v1/audit");
  });

  it("verifyAuditChain POSTs to /api/v1/audit/verify", async () => {
    const fetchFn = stubFetch(200, {
      data: { valid: true, checked: 1, legacy: 0, first_broken_id: null },
    });
    const api = createApiClient(() => "t", fetchFn);
    const report = await api.verifyAuditChain();
    expect(report.valid).toBe(true);
    expect(callOf(fetchFn).url).toBe("/api/v1/audit/verify");
    expect(callOf(fetchFn).init.method).toBe("POST");
    // The verify route reads no body; sending one would only invite a framing error.
    expect(callOf(fetchFn).init.body).toBeUndefined();
  });

  it("expiringReport merges the sibling aggregate keys", async () => {
    const api = createApiClient(
      () => "t",
      stubFetch(200, {
        data: [],
        oauth_refresh_needed: [{ handle: "secret://o1" }],
        certificates_nearing_renewal: [],
      }),
    );
    const report = await api.expiringReport();
    expect(report.oauth_refresh_needed).toHaveLength(1);
  });

  it("expiringReport defaults to a 7-day window and honors an explicit one", async () => {
    const fetchFn = stubFetch(200, { data: [] });
    const api = createApiClient(() => "t", fetchFn);
    await api.expiringReport();
    await api.expiringReport(30);
    expect(callOf(fetchFn, 0).url).toBe("/api/v1/health/expiring?days=7");
    expect(callOf(fetchFn, 1).url).toBe("/api/v1/health/expiring?days=30");
  });

  it("defaults the sibling aggregates to empty arrays when absent", async () => {
    const api = createApiClient(() => "t", stubFetch(200, { data: [] }));
    const report = await api.expiringReport();
    expect(report.oauth_refresh_needed).toEqual([]);
    expect(report.certificates_nearing_renewal).toEqual([]);
  });

  it("strips a secret:// prefix from handles in paths", async () => {
    const fetchFn = stubFetch(200, { data: {} });
    const api = createApiClient(() => "t", fetchFn);
    await api.getSecret("secret://my-key");
    expect(callOf(fetchFn).url).toBe("/api/v1/secrets/my-key");
  });

  it("percent-encodes the project separator of a scoped handle", async () => {
    const fetchFn = stubFetch(200, { data: {} });
    const api = createApiClient(() => "t", fetchFn);
    await api.getSecret("secret://myproj/test-key");
    // The REST routes match a single :handle segment — rest-api's own tests
    // address project-scoped secrets as `myproj%2Ftest-key`.
    expect(callOf(fetchFn).url).toBe("/api/v1/secrets/myproj%2Ftest-key");
  });

  it("passes an optional project filter to the list route", async () => {
    const fetchFn = stubFetch(200, { data: [] });
    const api = createApiClient(() => "t", fetchFn);
    await api.listSecrets("myproj");
    expect(callOf(fetchFn).url).toBe("/api/v1/secrets?project=myproj");
  });

  it("createSecret posts the create route's own field names", async () => {
    const fetchFn = stubFetch(201, {
      data: { handle: "secret://k1", status: "created", message: "" },
    });
    const api = createApiClient(() => "t", fetchFn);
    const created = await api.createSecret({
      name: "k1",
      type: "api_key",
      project: "myproj",
      value: "c2VjcmV0",
      expires_at: 1234,
    });
    const { url, init } = callOf(fetchFn);
    expect(url).toBe("/api/v1/secrets");
    expect(init.method).toBe("POST");
    expect(headersOf(init)["Content-Type"]).toBe("application/json");
    expect(JSON.parse(init.body as string)).toEqual({
      name: "k1",
      type: "api_key",
      project: "myproj",
      value: "c2VjcmV0",
      expires_at: 1234,
    });
    expect(created.handle).toBe("secret://k1");
  });

  it("rotateSecret posts the base64 value under the key the route parses", async () => {
    const fetchFn = stubFetch(200, { data: { rotated: true } });
    const api = createApiClient(() => "t", fetchFn);
    await api.rotateSecret("secret://k1", "bmV3");
    const { url, init } = callOf(fetchFn);
    expect(url).toBe("/api/v1/secrets/k1/rotate");
    expect(JSON.parse(init.body as string)).toEqual({ value: "bmV3" });
  });

  it("deleteSecret sends the confirm=true the route demands", async () => {
    const fetchFn = stubFetch(200, { data: { revoked: true } });
    const api = createApiClient(() => "t", fetchFn);
    await api.deleteSecret("secret://k1");
    const { url, init } = callOf(fetchFn);
    expect(url).toBe("/api/v1/secrets/k1?confirm=true");
    expect(init.method).toBe("DELETE");
  });

  it("putInjectionPolicy PUTs the policy body", async () => {
    const fetchFn = stubFetch(200, { data: { updated: true } });
    const api = createApiClient(() => "t", fetchFn);
    await api.putInjectionPolicy("secret://k1", {
      url_allowlist: ["https://api.example.com"],
      acknowledge_interpreters: true,
    });
    const { url, init } = callOf(fetchFn);
    expect(url).toBe("/api/v1/secrets/k1/injection-policy");
    expect(init.method).toBe("PUT");
    expect(headersOf(init)["Content-Type"]).toBe("application/json");
    expect(JSON.parse(init.body as string)).toEqual({
      url_allowlist: ["https://api.example.com"],
      acknowledge_interpreters: true,
    });
  });

  it("reads the policy, oauth and certificate detail routes", async () => {
    const fetchFn = stubFetch(200, { data: [] });
    const api = createApiClient(() => "t", fetchFn);
    await api.getInjectionPolicy("secret://k1");
    await api.getAccessPolicies("secret://k1");
    await api.getOAuthStatus("secret://gh-app");
    await api.getCertificateStatus("secret://my-cert");
    await api.health();
    expect([0, 1, 2, 3, 4].map((i) => callOf(fetchFn, i).url)).toEqual([
      "/api/v1/secrets/k1/injection-policy",
      "/api/v1/secrets/k1/policies",
      "/api/v1/oauth/gh-app/status",
      "/api/v1/certificates/my-cert/status",
      "/api/v1/health",
    ]);
  });

  it("exposes no value-fetch method", () => {
    const api = createApiClient(() => "t", stubFetch(200, { data: {} }));
    expect(Object.keys(api).some((k) => k.toLowerCase().includes("value"))).toBe(false);
  });
});

// The shell cannot learn that a token went stale from `GET /health` — that route
// is mounted ahead of authMiddleware and never 401s. The session signals
// therefore ride on every call, and the client is the one seam every call passes
// through.
describe("api client session signals", () => {
  it("calls onUnauthorized on a 401, and still throws", async () => {
    const onUnauthorized = vi.fn();
    const api = createApiClient(
      () => "stale",
      stubFetch(401, { error: "UNAUTHORIZED", message: "bad token" }),
      onUnauthorized,
    );
    await expect(api.listSecrets()).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it("does not call onUnauthorized on a non-401 failure", async () => {
    const onUnauthorized = vi.fn();
    const api = createApiClient(
      () => "t",
      stubFetch(500, { error: "INTERNAL", message: "boom" }),
      onUnauthorized,
    );
    await expect(api.listSecrets()).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("calls onSealed when the error envelope names VAULT_LOCKED", async () => {
    const onSealed = vi.fn();
    const api = createApiClient(
      () => "t",
      stubFetch(423, { error: "VAULT_LOCKED", message: "Vault is locked" }),
      undefined,
      onSealed,
    );
    await expect(api.listSecrets()).rejects.toBeInstanceOf(ApiError);
    expect(onSealed).toHaveBeenCalledTimes(1);
  });

  it("keys the sealed signal on the error code, not the status", async () => {
    const onSealed = vi.fn();
    const api = createApiClient(
      () => "t",
      stubFetch(423, { error: "RATE_LIMIT_EXCEEDED", message: "slow down" }),
      undefined,
      onSealed,
    );
    await expect(api.listSecrets()).rejects.toBeInstanceOf(ApiError);
    expect(onSealed).not.toHaveBeenCalled();
  });

  it("fires neither signal on a successful call", async () => {
    const onUnauthorized = vi.fn();
    const onSealed = vi.fn();
    const api = createApiClient(() => "t", stubFetch(200, { data: [] }), onUnauthorized, onSealed);
    await api.listSecrets();
    expect(onUnauthorized).not.toHaveBeenCalled();
    expect(onSealed).not.toHaveBeenCalled();
  });

  it("stays callable when neither signal is supplied", async () => {
    const api = createApiClient(() => "t", stubFetch(401, { error: "UNAUTHORIZED", message: "x" }));
    await expect(api.listSecrets()).rejects.toBeInstanceOf(ApiError);
  });
});

// The v1.4 agent-governance surface. Every assertion here is about the wire:
// the path a method addresses, the verb it uses and the body it sends — the
// three things a page cannot check for itself.
describe("api client agent governance", () => {
  it("listAgents omits the status filter when absent and sends it when given", async () => {
    const fetchFn = stubFetch(200, { data: [] });
    const api = createApiClient(() => "t", fetchFn);
    await api.listAgents();
    await api.listAgents("all");
    expect(callOf(fetchFn, 0).url).toBe("/api/v1/agents");
    expect(callOf(fetchFn, 1).url).toBe("/api/v1/agents?status=all");
  });

  it("getAgent reads the agent route with an encoded name segment", async () => {
    const fetchFn = stubFetch(200, { data: { name: "ci-bot" } });
    const api = createApiClient(() => "t", fetchFn);
    await api.getAgent("ci-bot");
    expect(callOf(fetchFn).url).toBe("/api/v1/agents/ci-bot");
  });

  it("keeps a hostile name inside its own path segment", async () => {
    // A valid agent name is [a-zA-Z0-9_-]+, so encoding never alters one. The
    // encode is the guard against everything else reaching the router as path
    // structure rather than as a name.
    const fetchFn = stubFetch(200, { data: {} });
    const api = createApiClient(() => "t", fetchFn);
    await api.getAgent("../secrets");
    expect(callOf(fetchFn).url).toBe("/api/v1/agents/..%2Fsecrets");
  });

  it("registerAgent POSTs the input body", async () => {
    const fetchFn = stubFetch(201, { data: { name: "ci-bot" } });
    const api = createApiClient(() => "t", fetchFn);
    const created = await api.registerAgent({ name: "ci-bot", owner: "platform" });
    const { url, init } = callOf(fetchFn);
    expect(url).toBe("/api/v1/agents");
    expect(init.method).toBe("POST");
    expect(headersOf(init)["Content-Type"]).toBe("application/json");
    expect(JSON.parse(init.body as string)).toEqual({ name: "ci-bot", owner: "platform" });
    expect(created.name).toBe("ci-bot");
  });

  it("updateAgent PUTs the input body and returns the updated agent", async () => {
    const fetchFn = stubFetch(200, { data: { name: "ci-bot", owner: "sre" } });
    const api = createApiClient(() => "t", fetchFn);
    const updated = await api.updateAgent("ci-bot", { description: "d", owner: "sre" });
    const { url, init } = callOf(fetchFn);
    expect(url).toBe("/api/v1/agents/ci-bot");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body as string)).toEqual({ description: "d", owner: "sre" });
    expect(updated.owner).toBe("sre");
  });

  it("deactivateAgent POSTs bodyless and returns the revoked count", async () => {
    const fetchFn = stubFetch(200, { data: { revoked_tokens: 3 } });
    const api = createApiClient(() => "t", fetchFn);
    const result = await api.deactivateAgent("ci-bot");
    const { url, init } = callOf(fetchFn);
    expect(url).toBe("/api/v1/agents/ci-bot/deactivate");
    expect(init.method).toBe("POST");
    // The route reads no body; sending one would only invite a framing error.
    expect(init.body).toBeUndefined();
    expect(result.revoked_tokens).toBe(3);
  });

  it("activateAgent POSTs bodyless and returns the agent", async () => {
    const fetchFn = stubFetch(200, { data: { name: "ci-bot", status: "active" } });
    const api = createApiClient(() => "t", fetchFn);
    const agent = await api.activateAgent("ci-bot");
    const { url, init } = callOf(fetchFn);
    expect(url).toBe("/api/v1/agents/ci-bot/activate");
    expect(init.method).toBe("POST");
    expect(init.body).toBeUndefined();
    expect(agent.status).toBe("active");
  });

  it("deleteAgent DELETEs and returns both cascade counts", async () => {
    const fetchFn = stubFetch(200, { data: { revoked_tokens: 2, removed_grants: 5 } });
    const api = createApiClient(() => "t", fetchFn);
    const result = await api.deleteAgent("ci-bot");
    const { url, init } = callOf(fetchFn);
    expect(url).toBe("/api/v1/agents/ci-bot");
    expect(init.method).toBe("DELETE");
    expect(result).toEqual({ revoked_tokens: 2, removed_grants: 5 });
  });

  it("listAgentPolicies reads the agent's grants", async () => {
    const fetchFn = stubFetch(200, { data: [] });
    const api = createApiClient(() => "t", fetchFn);
    await api.listAgentPolicies("ci-bot");
    expect(callOf(fetchFn).url).toBe("/api/v1/agents/ci-bot/policies");
  });

  it("setAgentPermissions PUTs the matrix cell, handle-encoded like every other secret path", async () => {
    const fetchFn = stubFetch(200, {
      data: { policy: null, gated_before: false, gated_after: false },
    });
    const api = createApiClient(() => "t", fetchFn);
    const result = await api.setAgentPermissions("ci-bot", "secret://myproj/test-key", {
      permissions: ["read", "use"],
      expires_at: 1234,
    });
    const { url, init } = callOf(fetchFn);
    expect(url).toBe("/api/v1/agents/ci-bot/secrets/myproj%2Ftest-key/permissions");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body as string)).toEqual({
      permissions: ["read", "use"],
      expires_at: 1234,
    });
    expect(result.gated_after).toBe(false);
  });

  it("listTokens builds the status and agent filters", async () => {
    const fetchFn = stubFetch(200, { data: [] });
    const api = createApiClient(() => "t", fetchFn);
    await api.listTokens();
    await api.listTokens({ agent: "ci-bot" });
    await api.listTokens({ status: "revoked", agent: "ci-bot" });
    expect([0, 1, 2].map((i) => callOf(fetchFn, i).url)).toEqual([
      "/api/v1/tokens",
      "/api/v1/tokens?agent=ci-bot",
      "/api/v1/tokens?status=revoked&agent=ci-bot",
    ]);
  });

  it("revokeToken DELETEs the jti route with an encoded segment", async () => {
    const fetchFn = stubFetch(200, { data: { revoked: true } });
    const api = createApiClient(() => "t", fetchFn);
    await api.revokeToken("a/b+c");
    const { url, init } = callOf(fetchFn);
    expect(url).toBe("/api/v1/tokens/a%2Fb%2Bc");
    expect(init.method).toBe("DELETE");
  });

  it("passes the principal filters to the audit route", async () => {
    const fetchFn = stubFetch(200, { data: [] });
    const api = createApiClient(() => "t", fetchFn);
    await api.queryAudit({ principal_type: "agent", principal_id: "ci-bot", limit: 50 });
    expect(callOf(fetchFn).url).toBe(
      "/api/v1/audit?principal_type=agent&principal_id=ci-bot&limit=50",
    );
  });

  it("drops an empty-string filter rather than sending a value the API refuses", async () => {
    // `principal_id=` is a 400 (min-length 1), and an empty string is what a
    // cleared input or an absent query param reads as at every call site.
    const fetchFn = stubFetch(200, { data: [] });
    const api = createApiClient(() => "t", fetchFn);
    await api.queryAudit({ principal_type: "agent", principal_id: "", limit: 50 });
    expect(callOf(fetchFn).url).toBe("/api/v1/audit?principal_type=agent&limit=50");
  });
});
