import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { OAuthProviderConfig, VaultApiToken } from "@harpoc/shared";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { RateLimiter } from "../middleware/rate-limit.js";
import { createApp } from "../app.js";
import { createOAuthRoutes } from "./oauth.js";
import type { HarpocEnv } from "../types.js";

const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["list", "read", "create", "rotate", "revoke", "use"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
};

const EXPECTED_CALLER = {
  principal_type: "agent",
  principal_id: "test-agent",
  interface: "rest",
};

const GITHUB_TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token";

const OAUTH_STATUS = {
  secret_id: "secret-uuid-1",
  provider: "github",
  has_access_token: true,
  access_token_expires_at: 1_700_000_000_000,
  has_refresh_token: true,
  last_refreshed_at: 1_699_000_000_000,
  refresh_status: "ok",
  token_endpoint_auth_method: "client_secret_post",
};

function createMockEngine() {
  return {
    verifyToken: vi.fn().mockReturnValue(MOCK_TOKEN),
    resolveSecretId: vi.fn().mockResolvedValue("secret-uuid-1"),
    getOAuthTokenStatus: vi.fn().mockReturnValue(OAUTH_STATUS),
    refreshOAuthToken: vi.fn().mockResolvedValue(1_700_000_003_600),
    // Only reached by the default-manager wiring test; a real OAuthManager
    // calls this first, before any network leg.
    createOAuthSecret: vi.fn().mockRejectedValue(VaultError.invalidInput("stub engine")),
  };
}

/**
 * A promise that never settles: a route that awaited a background flow's
 * `completion` would hang the request instead of answering 201.
 */
function neverSettles(): Promise<void> {
  return new Promise<void>(() => {});
}

function createMockOAuthManager() {
  return {
    startClientCredentials: vi.fn().mockResolvedValue({
      handle: "secret://gh-app",
      status: "authorized",
      message: "Client credentials flow completed for github",
    }),
    startDeviceCode: vi.fn().mockResolvedValue({
      handle: "secret://gh-dev",
      status: "pending_authorization",
      auth_url: "https://github.com/login/device",
      user_code: "WDJB-MJHT",
      message: "Please visit https://github.com/login/device and enter code: WDJB-MJHT",
      completion: neverSettles(),
    }),
    startAuthorizationCodeDeferred: vi.fn().mockResolvedValue({
      handle: "secret://gh-web",
      secretId: "secret-uuid-web",
      authUrl: "https://github.com/login/oauth/authorize?client_id=cid&state=st",
      completion: neverSettles(),
    }),
  };
}

let app: Hono<HarpocEnv>;
let engine: ReturnType<typeof createMockEngine>;
let oauthManager: ReturnType<typeof createMockOAuthManager>;
let limiter: RateLimiter;

beforeEach(() => {
  engine = createMockEngine();
  oauthManager = createMockOAuthManager();
  limiter = new RateLimiter();
  app = new Hono<HarpocEnv>();
  app.onError(errorHandler);
  app.use("*", async (c, next) => {
    c.set("engine", engine as never);
    c.set("limiter", limiter);
    c.set("oauthManager", oauthManager as never);
    await next();
  });
  app.use("/api/v1/oauth/*", authMiddleware);
  app.route("/api/v1/oauth", createOAuthRoutes());
});

const AUTH = { authorization: "Bearer valid-jwt" };
const JSON_HEADERS = { ...AUTH, "content-type": "application/json" };

function authorize(body: unknown): Response | Promise<Response> {
  return app.request("/api/v1/oauth/authorize", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });
}

const CLIENT_CREDENTIALS_BODY = {
  name: "gh-app",
  provider: "github",
  grant_type: "client_credentials",
  client_id: "cid",
  client_secret: "csecret",
};

const DEVICE_CODE_BODY = {
  name: "gh-dev",
  provider: "github",
  grant_type: "device_code",
  client_id: "cid",
};

const AUTH_CODE_BODY = {
  name: "gh-web",
  provider: "github",
  grant_type: "authorization_code",
  client_id: "cid",
};

describe("POST /api/v1/oauth/authorize — client_credentials", () => {
  it("returns 201 with the authorized flow result", async () => {
    const res = await authorize(CLIENT_CREDENTIALS_BODY);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.data.status).toBe("authorized");
    expect(body.data.handle).toBe("secret://gh-app");
    // This is the one branch that passes the manager's result through
    // unshaped (`c.json({ data: result }, 201)`) rather than building the
    // response field by field, so nothing stops a stray manager field (e.g.
    // an internal secretId) from leaking onto the wire except this pin.
    expect(Object.keys(body.data).sort()).toEqual(["handle", "message", "status"]);
  });

  it("calls the manager with (name, config, project, rest caller)", async () => {
    const res = await authorize({ ...CLIENT_CREDENTIALS_BODY, project: "myproj" });
    expect(res.status).toBe(201);

    const call = oauthManager.startClientCredentials.mock.calls[0] as unknown[];
    expect(call[0]).toBe("gh-app");
    const config = call[1] as OAuthProviderConfig;
    expect(config.token_endpoint).toBe(GITHUB_TOKEN_ENDPOINT);
    expect(config.client_id).toBe("cid");
    expect(config.client_secret).toBe("csecret");
    expect(call[2]).toBe("myproj");
    expect(call[3]).toEqual(EXPECTED_CALLER);
  });

  it("rejects a client_credentials flow without a client_secret (manager untouched)", async () => {
    const res = await authorize({
      name: "gh-app",
      provider: "github",
      grant_type: "client_credentials",
      client_id: "cid",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
    expect(body.message).toContain("client_secret");
    expect(oauthManager.startClientCredentials).not.toHaveBeenCalled();
  });
});

describe("POST /api/v1/oauth/authorize — device_code", () => {
  it("returns 201 with auth_url and user_code", async () => {
    const res = await authorize(DEVICE_CODE_BODY);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.data.handle).toBe("secret://gh-dev");
    expect(body.data.status).toBe("pending_authorization");
    expect(body.data.auth_url).toBe("https://github.com/login/device");
    expect(body.data.user_code).toBe("WDJB-MJHT");
    expect(oauthManager.startDeviceCode).toHaveBeenCalledWith(
      "gh-dev",
      expect.objectContaining({ device_authorization_endpoint: expect.any(String) }),
      undefined,
      EXPECTED_CALLER,
    );
  });

  // The background poll's `completion` promise serializes as `{}` and its
  // resolution is not the client's to await: the response is built field by
  // field, never by spreading the manager's result.
  it("never serializes the completion promise", async () => {
    const res = await authorize(DEVICE_CODE_BODY);
    const body = (await res.json()) as { data: Record<string, unknown> };
    expect(Object.keys(body.data)).not.toContain("completion");
  });
});

describe("POST /api/v1/oauth/authorize — authorization_code (D2: background flow)", () => {
  it("returns 201 pending_authorization with the auth URL without awaiting completion", async () => {
    const res = await authorize(AUTH_CODE_BODY);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.data.handle).toBe("secret://gh-web");
    expect(body.data.status).toBe("pending_authorization");
    expect(body.data.auth_url).toBe(
      "https://github.com/login/oauth/authorize?client_id=cid&state=st",
    );
    expect(typeof body.data.message).toBe("string");
    expect(oauthManager.startAuthorizationCodeDeferred).toHaveBeenCalledWith(
      "gh-web",
      expect.objectContaining({ auth_endpoint: "https://github.com/login/oauth/authorize" }),
      undefined,
      EXPECTED_CALLER,
    );
  });

  it("the pending message points at a reachable completion signal", async () => {
    // refresh_status "ok" is unreachable for providers that issue no refresh
    // token; has_access_token flips on every successful flow.
    const res = await authorize(AUTH_CODE_BODY);
    const body = (await res.json()) as { data: { message: string } };
    expect(body.data.message).toContain("has_access_token");
    expect(body.data.message).not.toContain("refresh_status");
  });

  // The secretId is an internal vault identifier and `completion` a promise:
  // neither belongs on the wire, so the response body is assembled field by
  // field rather than spread from AuthorizationCodeStart.
  it("serializes neither secretId nor completion", async () => {
    const res = await authorize(AUTH_CODE_BODY);
    const body = (await res.json()) as { data: Record<string, unknown> };
    expect(Object.keys(body.data)).not.toContain("secretId");
    expect(Object.keys(body.data)).not.toContain("completion");
    expect(JSON.stringify(body)).not.toContain("secret-uuid-web");
  });
});

describe("POST /api/v1/oauth/authorize — validation and scope", () => {
  it("rejects a body missing required fields", async () => {
    const res = await authorize({ name: "gh-app" });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
    expect(oauthManager.startClientCredentials).not.toHaveBeenCalled();
  });

  // `authorize()` always stringifies, so the bodyless request is built by hand.
  it("a bodyless POST is a descriptive 400, not a generic 500", async () => {
    const res = await app.request("/api/v1/oauth/authorize", {
      method: "POST",
      headers: JSON_HEADERS,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
    expect(body.message).toBe("Request body must be valid JSON");
    // No body named a grant type, so no dispatch arm may have run.
    expect(oauthManager.startClientCredentials).not.toHaveBeenCalled();
    expect(oauthManager.startDeviceCode).not.toHaveBeenCalled();
    expect(oauthManager.startAuthorizationCodeDeferred).not.toHaveBeenCalled();
  });

  it("rejects an unknown provider", async () => {
    const res = await authorize({ ...CLIENT_CREDENTIALS_BODY, provider: "notaprovider" });
    expect(res.status).toBe(400);
  });

  it("rejects a token without the create scope (403, manager untouched)", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read", "rotate"] });
    const res = await authorize(CLIENT_CREDENTIALS_BODY);
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.ACCESS_DENIED);
    expect(oauthManager.startClientCredentials).not.toHaveBeenCalled();
  });

  it("rejects a cross-project request from a project-scoped token", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, project: "other" });
    const res = await authorize({ ...CLIENT_CREDENTIALS_BODY, project: "myproj" });
    expect(res.status).toBe(403);
    expect(oauthManager.startClientCredentials).not.toHaveBeenCalled();
  });

  it("rejects a secret name outside the token's name patterns", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets: ["db-*"] });
    const res = await authorize(CLIENT_CREDENTIALS_BODY);
    expect(res.status).toBe(403);
    expect(oauthManager.startClientCredentials).not.toHaveBeenCalled();
  });

  // The manager caps concurrently pending authorization-code flows (D3): each
  // holds a loopback listener for the whole callback window, so an unbounded
  // `create`-scoped caller could pin sockets at will. The refusal is a plain
  // VaultError travelling the existing error handler — no route branch.
  it("surfaces the pending-flow cap refusal as 429 RATE_LIMIT_EXCEEDED", async () => {
    oauthManager.startAuthorizationCodeDeferred.mockRejectedValueOnce(
      new VaultError(ErrorCode.RATE_LIMIT_EXCEEDED, "Too many pending authorization flows"),
    );

    const res = await authorize(AUTH_CODE_BODY);

    expect(res.status).toBe(429);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe(ErrorCode.RATE_LIMIT_EXCEEDED);
    expect(body.message).toContain("Too many pending authorization flows");
  });

  it("maps an OAuth flow failure to its VaultError status", async () => {
    oauthManager.startClientCredentials.mockRejectedValueOnce(
      VaultError.oauthFlowFailed("token endpoint returned 400"),
    );
    const res = await authorize(CLIENT_CREDENTIALS_BODY);
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.OAUTH_FLOW_FAILED);
  });
});

describe("GET /api/v1/oauth/:handle/status", () => {
  it("returns the token status for the resolved secret id", async () => {
    const res = await app.request("/api/v1/oauth/gh-app/status", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual(OAUTH_STATUS);
    expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://gh-app");
    expect(engine.getOAuthTokenStatus).toHaveBeenCalledWith("secret-uuid-1", EXPECTED_CALLER);
  });

  it("charges the per-secret rate limiter", async () => {
    const checkSecret = vi.spyOn(limiter, "checkSecret");
    await app.request("/api/v1/oauth/gh-app/status", { headers: AUTH });
    expect(checkSecret).toHaveBeenCalledWith("secret-uuid-1");
  });

  it("requires the read scope (403, engine untouched)", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["create"] });
    const res = await app.request("/api/v1/oauth/gh-app/status", { headers: AUTH });
    expect(res.status).toBe(403);
    expect(engine.getOAuthTokenStatus).not.toHaveBeenCalled();
  });

  it("resolves a project-qualified handle", async () => {
    await app.request("/api/v1/oauth/myproj%2Fgh-app/status", { headers: AUTH });
    expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://myproj/gh-app");
  });

  it("propagates OAUTH_NOT_CONFIGURED as its mapped status", async () => {
    engine.getOAuthTokenStatus.mockImplementation(() => {
      throw VaultError.oauthNotConfigured();
    });
    const res = await app.request("/api/v1/oauth/gh-app/status", { headers: AUTH });
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.OAUTH_NOT_CONFIGURED);
  });
});

describe("POST /api/v1/oauth/:handle/refresh", () => {
  it("refreshes the token and returns the new expiry", async () => {
    const res = await app.request("/api/v1/oauth/gh-app/refresh", {
      method: "POST",
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual({ refreshed: true, expires_at: 1_700_000_003_600 });
    expect(engine.refreshOAuthToken).toHaveBeenCalledWith("secret-uuid-1", EXPECTED_CALLER);
  });

  it("charges the per-secret rate limiter", async () => {
    const checkSecret = vi.spyOn(limiter, "checkSecret");
    await app.request("/api/v1/oauth/gh-app/refresh", { method: "POST", headers: AUTH });
    expect(checkSecret).toHaveBeenCalledWith("secret-uuid-1");
  });

  it("requires the rotate scope (403, engine untouched)", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read", "create"] });
    const res = await app.request("/api/v1/oauth/gh-app/refresh", {
      method: "POST",
      headers: AUTH,
    });
    expect(res.status).toBe(403);
    expect(engine.refreshOAuthToken).not.toHaveBeenCalled();
  });

  it("enforces the token's name patterns (403, engine untouched)", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets: ["db-*"] });
    const res = await app.request("/api/v1/oauth/gh-app/refresh", {
      method: "POST",
      headers: AUTH,
    });
    expect(res.status).toBe(403);
    expect(engine.refreshOAuthToken).not.toHaveBeenCalled();
  });

  it("returns a null expiry when the provider sends no expires_in", async () => {
    engine.refreshOAuthToken.mockResolvedValueOnce(null);
    const res = await app.request("/api/v1/oauth/gh-app/refresh", {
      method: "POST",
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual({ refreshed: true, expires_at: null });
  });
});

describe("createApp OAuth wiring", () => {
  it("mounts the routes and serves the injected manager from context", async () => {
    const appEngine = createMockEngine();
    const injected = createMockOAuthManager();
    const wired = createApp(appEngine as never, {
      oauthManager: injected as never,
      certManager: {} as never,
    });

    const res = await wired.request("/api/v1/oauth/authorize", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(CLIENT_CREDENTIALS_BODY),
    });
    expect(res.status).toBe(201);
    expect(injected.startClientCredentials).toHaveBeenCalledTimes(1);
  });

  it("requires auth on the mounted OAuth routes", async () => {
    const appEngine = createMockEngine();
    const injected = createMockOAuthManager();
    const wired = createApp(appEngine as never, {
      oauthManager: injected as never,
      certManager: {} as never,
    });

    const status = await wired.request("/api/v1/oauth/gh-app/status");
    expect(status.status).toBe(401);

    // The `/*` middleware pattern must cover the single-segment authorize path
    // too — an unguarded route would read an unset `token` from context.
    const authorized = await wired.request("/api/v1/oauth/authorize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(CLIENT_CREDENTIALS_BODY),
    });
    expect(authorized.status).toBe(401);
    expect(injected.startClientCredentials).not.toHaveBeenCalled();
  });

  it("constructs its own OAuth manager when none is injected", async () => {
    const appEngine = createMockEngine();
    const wired = createApp(appEngine as never);

    const res = await wired.request("/api/v1/oauth/authorize", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(CLIENT_CREDENTIALS_BODY),
    });

    // The default manager's first engine call. An unset context var would throw
    // a TypeError and answer 500 INTERNAL_ERROR instead of the stub's own code.
    expect(appEngine.createOAuthSecret).toHaveBeenCalled();
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.INVALID_INPUT);
  });
});
