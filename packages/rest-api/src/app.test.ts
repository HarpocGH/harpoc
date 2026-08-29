import { describe, it, expect, vi } from "vitest";
import { ErrorCode, VaultError, VaultState, VAULT_VERSION } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { OAuthManager, defaultOpenBrowser } from "@harpoc/oauth-proxy";
import { createApp, createDefaultOAuthManager } from "./app.js";

const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
};

function createMockEngine() {
  return {
    getState: vi.fn().mockReturnValue(VaultState.UNLOCKED),
    verifyToken: vi.fn().mockReturnValue(MOCK_TOKEN),
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
    // Only reached through the default OAuth manager: a real manager calls
    // this first, before any network leg.
    createOAuthSecret: vi.fn().mockRejectedValue(VaultError.invalidInput("stub engine")),
  };
}

describe("createApp integration", () => {
  it("health endpoint works without auth", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/health");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.state).toBe("unlocked");
    expect(body.data.version).toBe(VAULT_VERSION);
  });

  it("protected routes require auth", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/secrets");
    expect(res.status).toBe(401);
  });

  // The governance prefixes are their own `app.use(...)` registrations: without
  // them the mounted routes answer unauthenticated, since the routers read
  // `c.get("token")` rather than verifying one themselves.
  it.each(["/api/v1/agents", "/api/v1/tokens"])(
    "the %s mount is behind the auth middleware",
    async (path) => {
      const engine = createMockEngine();
      const app = createApp(engine as never);

      expect((await app.request(path)).status).toBe(401);
      expect(
        (await app.request(path, { headers: { authorization: "Bearer valid-jwt" } })).status,
      ).toBe(200);
    },
  );

  it("protected routes work with valid auth", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: "Bearer valid" },
    });
    expect(res.status).toBe(200);
  });

  it("secret CRUD flow works end-to-end", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);
    const headers = { authorization: "Bearer valid", "content-type": "application/json" };

    // Create
    const createRes = await app.request("/api/v1/secrets", {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "k", type: "api_key" }),
    });
    expect(createRes.status).toBe(201);

    // Read info
    const infoRes = await app.request("/api/v1/secrets/k", {
      headers: { authorization: "Bearer valid" },
    });
    expect(infoRes.status).toBe(200);

    // Read value
    const valueRes = await app.request("/api/v1/secrets/k/value", {
      headers: { authorization: "Bearer valid" },
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
      headers: { authorization: "Bearer valid" },
    });
    expect(revokeRes.status).toBe(200);
  });

  it("policy flow works through app", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);
    const headers = { authorization: "Bearer valid", "content-type": "application/json" };

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
      headers: { authorization: "Bearer valid" },
    });
    expect(listRes.status).toBe(200);

    // Revoke
    const revokeRes = await app.request("/api/v1/secrets/k/policies/p1", {
      method: "DELETE",
      headers: { authorization: "Bearer valid" },
    });
    expect(revokeRes.status).toBe(200);
  });

  it("audit query works through app", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/audit", {
      headers: { authorization: "Bearer valid" },
    });
    expect(res.status).toBe(200);
  });

  it("serves the OAuth routes through a default manager when none is injected", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/oauth/authorize", {
      method: "POST",
      headers: { authorization: "Bearer valid", "content-type": "application/json" },
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
      headers: { authorization: "Bearer valid" },
    });
    expect(res.status).toBe(503);
  });
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
