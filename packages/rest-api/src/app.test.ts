import { describe, it, expect, vi } from "vitest";
import { ErrorCode, VaultError, VaultState, HARPOC_VERSION } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { OAuthManager, defaultOpenBrowser } from "@harpoc/oauth-proxy";
import { createApp, createDefaultOAuthManager } from "./app.js";
import { silenceAuditLines } from "@harpoc/test-utils";

silenceAuditLines();

const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
};

// Hono's in-process `app.request` sends no Host header; a default-built app
// checks one (R33/D9), so every request below carries the loopback Host.
const HOST = { host: "localhost" };

function createMockEngine() {
  return {
    getState: vi.fn().mockReturnValue(VaultState.UNLOCKED),
    verifyToken: vi.fn().mockReturnValue(MOCK_TOKEN),
    auditScopeRefusal: vi.fn(),
    listSecrets: vi.fn().mockReturnValue([]),
    createSecret: vi.fn().mockResolvedValue({
      handle: "secret://k",
      status: "created",
      message: "Secret created",
    }),
    getSecretInfo: vi.fn().mockResolvedValue({
      handle: "secret://k",
      name: "k",
      type: "api_key",
      project: null,
      status: "active",
      version: 1,
      createdAt: 1000,
      updatedAt: 1000,
      expiresAt: null,
      rotatedAt: null,
    }),
    getSecretValue: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3])),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    useSecret: vi.fn().mockResolvedValue({ status: 200 }),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-1"),
    listPolicies: vi.fn().mockReturnValue([
      {
        id: "p1",
        secret_id: "uuid-1",
        principal_type: "agent",
        principal_id: "a1",
        permissions: ["read"],
        created_at: Date.now(),
        expires_at: null,
        created_by: "test-agent",
      },
    ]),
    grantPolicy: vi.fn().mockReturnValue({
      id: "p1",
      secret_id: "uuid-1",
      principal_type: "agent",
      principal_id: "a1",
      permissions: ["read"],
      created_at: Date.now(),
      expires_at: null,
      created_by: "test-agent",
    }),
    revokePolicy: vi.fn(),
    queryAudit: vi.fn().mockReturnValue([]),
    listAgents: vi.fn().mockReturnValue([]),
    listIssuedTokens: vi.fn().mockReturnValue([]),
    auditGovernanceRefusal: vi.fn(),
    // Only reached through the default OAuth manager: a real manager calls
    // this first, before any network leg.
    createOAuthSecret: vi.fn().mockRejectedValue(VaultError.invalidInput("stub engine")),
  };
}

describe("createApp integration", () => {
  it("health endpoint works without auth", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/health", { headers: HOST });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.state).toBe("unlocked");
    expect(body.data.version).toBe(HARPOC_VERSION);
  });

  it("protected routes require auth", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/secrets", { headers: HOST });
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.INVALID_TOKEN);
  });

  // The governance prefixes are their own `app.use(...)` registrations: without
  // them the mounted routes answer unauthenticated, since the routers read
  // `c.get("token")` rather than verifying one themselves.
  it.each(["/api/v1/agents", "/api/v1/tokens"])(
    "the %s mount is behind the auth middleware",
    async (path) => {
      const engine = createMockEngine();
      const app = createApp(engine as never);

      const res = await app.request(path, { headers: HOST });
      expect(res.status).toBe(401);
      expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.INVALID_TOKEN);
      expect(
        (await app.request(path, { headers: { ...HOST, authorization: "Bearer valid-jwt" } }))
          .status,
      ).toBe(200);
    },
  );

  it("protected routes work with valid auth", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/secrets", {
      headers: { ...HOST, authorization: "Bearer valid" },
    });
    expect(res.status).toBe(200);
  });

  it("secret CRUD flow works end-to-end", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);
    const headers = { ...HOST, authorization: "Bearer valid", "content-type": "application/json" };

    // Create
    const createRes = await app.request("/api/v1/secrets", {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "k", type: "api_key" }),
    });
    expect(createRes.status).toBe(201);

    // Read info
    const infoRes = await app.request("/api/v1/secrets/k", {
      headers: { ...HOST, authorization: "Bearer valid" },
    });
    expect(infoRes.status).toBe(200);

    // Read value
    const valueRes = await app.request("/api/v1/secrets/k/value", {
      headers: { ...HOST, authorization: "Bearer valid" },
    });
    expect(valueRes.status).toBe(200);

    // Rotate
    const rotateRes = await app.request("/api/v1/secrets/k/rotate", {
      method: "POST",
      headers,
      body: JSON.stringify({ value: Buffer.from("new").toString("base64") }),
    });
    expect(rotateRes.status).toBe(200);

    // Revoke
    const revokeRes = await app.request("/api/v1/secrets/k?confirm=true", {
      method: "DELETE",
      headers: { ...HOST, authorization: "Bearer valid" },
    });
    expect(revokeRes.status).toBe(200);
  });

  it("policy flow works through app", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);
    const headers = { ...HOST, authorization: "Bearer valid", "content-type": "application/json" };

    // Grant
    const grantRes = await app.request("/api/v1/secrets/k/policies", {
      method: "POST",
      headers,
      body: JSON.stringify({
        principal_type: "agent",
        principal_id: "a1",
        permissions: ["read"],
      }),
    });
    expect(grantRes.status).toBe(201);

    // List
    const listRes = await app.request("/api/v1/secrets/k/policies", {
      headers: { ...HOST, authorization: "Bearer valid" },
    });
    expect(listRes.status).toBe(200);

    // Revoke
    const revokeRes = await app.request("/api/v1/secrets/k/policies/p1", {
      method: "DELETE",
      headers: { ...HOST, authorization: "Bearer valid" },
    });
    expect(revokeRes.status).toBe(200);
  });

  it("audit query works through app", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/audit", {
      headers: { ...HOST, authorization: "Bearer valid" },
    });
    expect(res.status).toBe(200);
  });

  it("serves the OAuth routes through a default manager when none is injected", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/oauth/authorize", {
      method: "POST",
      headers: { ...HOST, authorization: "Bearer valid", "content-type": "application/json" },
      body: JSON.stringify({
        name: "gh-app",
        provider: "github",
        grant_type: "client_credentials",
        client_id: "cid",
        client_secret: "csecret",
      }),
    });

    // The default manager's first engine call. An unset context var would throw
    // a TypeError and answer 500 INTERNAL_ERROR instead of the stub's own code.
    expect(engine.createOAuthSecret).toHaveBeenCalled();
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.INVALID_INPUT);
  });

  it("VAULT_LOCKED errors return 503", async () => {
    const engine = createMockEngine();
    engine.verifyToken.mockImplementation(() => {
      throw VaultError.vaultLocked();
    });
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/secrets", {
      headers: { ...HOST, authorization: "Bearer valid" },
    });
    expect(res.status).toBe(503);
  });
});

describe("listener host allowlist (R11/D61)", () => {
  it("refuses a Host outside the set on every route, health included", async () => {
    const app = createApp(createMockEngine() as never, {
      allowedHostSet: new Set(["vault.example"]),
    });
    const res = await app.request("/api/v1/health", {
      headers: { host: "evil.example:3000" },
    });
    expect(res.status).toBe(421);
    expect(((await res.json()) as { error: string }).error).toBe("MISDIRECTED_REQUEST");
    expect(
      (
        await app.request("/api/v1/health", {
          headers: { host: "vault.example:3000" },
        })
      ).status,
    ).toBe(200);
  });

  /**
   * Inverted 2026-09-06 (R33/D9). An embedder that passed no set used to get
   * no Host check at all; it now gets the loopback set, so an app built the
   * default way refuses a rebinding Host exactly as the listener `startServer`
   * builds does. The opt-out is explicit and empty.
   */
  it("without a set, a non-loopback Host is refused 421", async () => {
    const app = createApp(createMockEngine() as never);
    const res = await app.request("/api/v1/health", {
      headers: { host: "anything.example" },
    });
    expect(res.status).toBe(421);
    expect(((await res.json()) as { error: string }).error).toBe("MISDIRECTED_REQUEST");
  });

  it("without a set, Host: localhost is served — every harness caller's Host", async () => {
    const app = createApp(createMockEngine() as never);
    // Hono's in-process `app.request` carries no Host header at all, so the
    // real callers that matter are the loopback listeners — integration's
    // `rest-helpers.ts` and e2e's `surfaces/rest.ts` — which send
    // `127.0.0.1:<port>`.
    expect((await app.request("/api/v1/health", { headers: { host: "localhost" } })).status).toBe(
      200,
    );
    expect(
      (await app.request("/api/v1/health", { headers: { host: "127.0.0.1:3000" } })).status,
    ).toBe(200);
  });

  it("an explicit empty set checks nothing (the documented opt-out)", async () => {
    const app = createApp(createMockEngine() as never, { allowedHostSet: new Set<string>() });
    expect(
      (await app.request("/api/v1/health", { headers: { host: "anything.example" } })).status,
    ).toBe(200);
  });
});

describe("governance requires an unscoped token (R11/N12)", () => {
  it.each(["/api/v1/agents", "/api/v1/tokens"])(
    "%s refuses a project-claimed admin token before the engine is reached",
    async (path) => {
      const engine = createMockEngine();
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, project: "acme" });
      const app = createApp(engine as never);
      const res = await app.request(path, {
        headers: { ...HOST, authorization: "Bearer valid-jwt" },
      });
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: string; message: string };
      expect(body.error).toBe("ACCESS_DENIED");
      expect(body.message).toBe("Access denied: governance requires an unscoped admin token");
      expect(engine.listAgents).not.toHaveBeenCalled();
      expect(engine.listIssuedTokens).not.toHaveBeenCalled();
    },
  );

  it("a project-claimed token still reaches the secrets routes", async () => {
    const engine = createMockEngine();
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, project: "acme" });
    const app = createApp(engine as never);
    const res = await app.request("/api/v1/secrets", {
      headers: { ...HOST, authorization: "Bearer valid-jwt" },
    });
    expect(res.status).toBe(200);
  });

  /**
   * D4: the middleware refuses before the engine's own governance assertion
   * can, so without this call a project-scoped probe of the governance surface
   * left no trace at all — `access.denied` had no product writer. One row
   * whichever layer refuses.
   */
  it.each(["/api/v1/agents", "/api/v1/tokens"])(
    "%s writes one access.denied row before the 403 (D4)",
    async (path) => {
      const engine = createMockEngine();
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, project: "acme" });
      const app = createApp(engine as never);

      const res = await app.request(path, {
        headers: { ...HOST, authorization: "Bearer valid-jwt" },
      });

      expect(res.status).toBe(403);
      expect(engine.auditGovernanceRefusal).toHaveBeenCalledTimes(1);
      expect(engine.auditGovernanceRefusal).toHaveBeenCalledWith(
        {
          principal_type: "agent",
          principal_id: "test-agent",
          project: "acme",
          interface: "rest",
          admin_scope: true,
        },
        `GET ${path}`,
      );
    },
  );
});

describe("governance refuses a secrets-claimed admin token (S3)", () => {
  const ROUTES: Array<[string, string, string[]]> = [
    ["/api/v1/agents", '["db-*"]', ["db-*"]],
    ["/api/v1/agents", '["*"]', ["*"]],
    ["/api/v1/tokens", '["db-*"]', ["db-*"]],
    ["/api/v1/tokens", '["*"]', ["*"]],
  ];

  it.each(ROUTES)(
    "%s refuses a secrets: %s admin token 403 before the engine is reached, with one access.denied row",
    async (path, _claim, secrets) => {
      const engine = createMockEngine();
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets });
      const app = createApp(engine as never);
      const res = await app.request(path, {
        headers: { ...HOST, authorization: "Bearer valid-jwt" },
      });
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: string; message: string };
      expect(body.error).toBe("ACCESS_DENIED");
      expect(body.message).toBe("Access denied: governance requires an unscoped admin token");
      expect(engine.listAgents).not.toHaveBeenCalled();
      expect(engine.listIssuedTokens).not.toHaveBeenCalled();
      expect(engine.auditGovernanceRefusal).toHaveBeenCalledTimes(1);
      expect(engine.auditGovernanceRefusal).toHaveBeenCalledWith(
        {
          principal_type: "agent",
          principal_id: "test-agent",
          secrets,
          interface: "rest",
          admin_scope: true,
        },
        `GET ${path}`,
      );
    },
  );

  it("POST /api/v1/agents refuses a secrets-claimed token before the body is read: a malformed body answers 403, not 400", async () => {
    const engine = { ...createMockEngine(), registerAgent: vi.fn() };
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets: ["db-*"] });
    const app = createApp(engine as never);
    const res = await app.request("/api/v1/agents", {
      method: "POST",
      headers: { ...HOST, authorization: "Bearer valid-jwt", "content-type": "application/json" },
      body: "{not json",
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("ACCESS_DENIED");
    expect(engine.registerAgent).not.toHaveBeenCalled();
    expect(engine.auditGovernanceRefusal).toHaveBeenCalledTimes(1);
    expect(engine.auditGovernanceRefusal.mock.calls[0]?.[1]).toBe("POST /api/v1/agents");
  });

  it("the permission-matrix cell refuses a name-scoped admin token whose pattern matches the handle (TC-7)", async () => {
    const engine = {
      ...createMockEngine(),
      setAgentPermissions: vi.fn().mockReturnValue({ agent: "deploy-bot", permissions: ["read"] }),
    };
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets: ["db-*"] });
    const app = createApp(engine as never);
    const path = "/api/v1/agents/deploy-bot/secrets/db-main/permissions";
    const res = await app.request(path, {
      method: "PUT",
      headers: { ...HOST, authorization: "Bearer valid-jwt", "content-type": "application/json" },
      body: JSON.stringify({ permissions: ["read"] }),
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("ACCESS_DENIED");
    expect(engine.resolveSecretId).not.toHaveBeenCalled();
    expect(engine.setAgentPermissions).not.toHaveBeenCalled();
    expect(engine.auditGovernanceRefusal).toHaveBeenCalledTimes(1);
    expect(engine.auditGovernanceRefusal.mock.calls[0]?.[1]).toBe(`PUT ${path}`);
  });

  it("a secrets-claimed token still reaches the secrets routes (control)", async () => {
    const engine = createMockEngine();
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets: ["db-*"] });
    const app = createApp(engine as never);
    const res = await app.request("/api/v1/secrets", {
      headers: { ...HOST, authorization: "Bearer valid-jwt" },
    });
    expect(res.status).toBe(200);
    expect(engine.auditGovernanceRefusal).not.toHaveBeenCalled();
  });

  it.each(["/api/v1/agents", "/api/v1/tokens"])(
    "%s admits a token whose secrets claim is empty: an empty list is no claim (control)",
    async (path) => {
      const engine = createMockEngine();
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets: [] });
      const app = createApp(engine as never);
      const res = await app.request(path, {
        headers: { ...HOST, authorization: "Bearer valid-jwt" },
      });
      expect(res.status).toBe(200);
      expect(engine.auditGovernanceRefusal).not.toHaveBeenCalled();
    },
  );
});

describe("createDefaultOAuthManager", () => {
  it("builds the REST-shaped manager an owner can dispose", () => {
    const engine = createMockEngine();
    const manager = createDefaultOAuthManager(engine as never);

    expect(manager).toBeInstanceOf(OAuthManager);
    // The dispose seam the owner (CLI `server start --rest`) calls on shutdown.
    expect(typeof manager.cancelPendingFlows).toBe("function");

    const internals = manager as unknown as {
      callbackPort: number;
      openBrowser: (url: string) => Promise<void>;
    };
    // Concurrent and re-POSTed flows would EADDRINUSE-collide on a fixed port.
    expect(internals.callbackPort).toBe(0);
    // REST never runs the browser leg (D2): the client follows auth_url itself.
    expect(internals.openBrowser).not.toBe(defaultOpenBrowser);
  });

  it("reports a background flow failure on stderr", () => {
    const manager = createDefaultOAuthManager(createMockEngine() as never);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const internals = manager as unknown as {
      onBackgroundFlowError: (secretId: string, err: unknown) => void;
    };
    internals.onBackgroundFlowError("secret-1", new Error("provider offline"));

    expect(errorSpy).toHaveBeenCalledWith(
      "[harpoc] OAuth background flow failed (secret-1): provider offline",
    );
    errorSpy.mockRestore();
  });
});
