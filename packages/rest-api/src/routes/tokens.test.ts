import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import type { IssuedToken, VaultApiToken } from "@harpoc/shared";
import { VaultError } from "@harpoc/shared";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { createTokenRoutes } from "./tokens.js";
import type { HarpocEnv } from "../types.js";

const ADMIN_TOKEN: VaultApiToken = {
  sub: "admin-agent",
  vault_id: "vault-1",
  scope: ["admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-admin",
};

const READ_TOKEN: VaultApiToken = {
  ...ADMIN_TOKEN,
  sub: "read-agent",
  scope: ["read"],
  jti: "jti-read",
};

const MOCK_ISSUED_TOKEN: IssuedToken = {
  jti: "jti-1",
  subject: "deploy-bot",
  principal_type: "agent",
  agent: "deploy-bot",
  scope: ["read", "use"],
  project: null,
  secrets: null,
  label: "ci runner",
  issued_at: 1000,
  expires_at: 2000,
  revoked_at: null,
  status: "active",
};

/** The caller every route must thread into the engine (`callerFromToken(token, "rest")`). */
const ADMIN_CALLER = {
  principal_type: "agent",
  principal_id: "admin-agent",
  interface: "rest",
  // R7 (v1.4.1): callerFromToken marks every admin-scoped token. The mark
  // exempts user-type callers only — this agent-type caller stays gated.
  admin_scope: true,
};

function createMockEngine(token: VaultApiToken = ADMIN_TOKEN) {
  return {
    verifyToken: vi.fn().mockReturnValue(token),
    listIssuedTokens: vi.fn().mockReturnValue([MOCK_ISSUED_TOKEN]),
    revokeToken: vi.fn(),
  };
}

function buildApp(engineForApp: ReturnType<typeof createMockEngine>): Hono<HarpocEnv> {
  const instance = new Hono<HarpocEnv>();
  instance.onError(errorHandler);
  instance.use("*", async (c, next) => {
    c.set("engine", engineForApp as never);
    await next();
  });
  instance.use("/api/v1/tokens/*", authMiddleware);
  instance.route("/api/v1/tokens", createTokenRoutes());
  return instance;
}

let app: Hono<HarpocEnv>;
let engine: ReturnType<typeof createMockEngine>;

beforeEach(() => {
  engine = createMockEngine();
  app = buildApp(engine);
});

const AUTH = { authorization: "Bearer valid-jwt" };

describe("GET /api/v1/tokens", () => {
  it("lists issued tokens", async () => {
    const res = await app.request("/api/v1/tokens", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toHaveLength(1);
    expect(body.data[0].jti).toBe("jti-1");
    expect(engine.listIssuedTokens).toHaveBeenCalledWith({}, ADMIN_CALLER);
  });

  it("forwards ?status= and ?agent=", async () => {
    await app.request("/api/v1/tokens?status=all&agent=deploy-bot", { headers: AUTH });
    expect(engine.listIssuedTokens).toHaveBeenCalledWith(
      { status: "all", agent: "deploy-bot" },
      ADMIN_CALLER,
    );
  });

  it("rejects an unknown ?status= value before the engine call", async () => {
    const res = await app.request("/api/v1/tokens?status=live", { headers: AUTH });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("SCHEMA_VALIDATION_ERROR");
    expect(engine.listIssuedTokens).not.toHaveBeenCalled();
  });

  it("rejects a malformed ?agent= value before the engine call", async () => {
    const res = await app.request("/api/v1/tokens?agent=bad%20name", { headers: AUTH });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("SCHEMA_VALIDATION_ERROR");
    expect(engine.listIssuedTokens).not.toHaveBeenCalled();
  });

  it("maps AGENT_NOT_FOUND to 404", async () => {
    engine.listIssuedTokens.mockImplementation(() => {
      throw VaultError.agentNotFound("ghost");
    });
    const res = await app.request("/api/v1/tokens?agent=ghost", { headers: AUTH });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toBe("AGENT_NOT_FOUND");
  });

  it("requires admin scope before the engine call", async () => {
    engine = createMockEngine(READ_TOKEN);
    app = buildApp(engine);
    const res = await app.request("/api/v1/tokens", { headers: AUTH });
    expect(res.status).toBe(403);
    expect(engine.listIssuedTokens).not.toHaveBeenCalled();
  });

  it("requires auth", async () => {
    const res = await app.request("/api/v1/tokens");
    expect(res.status).toBe(401);
  });
});

describe("DELETE /api/v1/tokens/:jti", () => {
  it("revokes the token", async () => {
    const res = await app.request("/api/v1/tokens/jti-1", { method: "DELETE", headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual({ revoked: true });
    expect(engine.revokeToken).toHaveBeenCalledWith("jti-1", undefined, ADMIN_CALLER);
  });

  /**
   * No expiry argument — the engine floors the denylist entry at
   * `MAX_TOKEN_TTL_MS`, which outlives every mintable token; the registry
   * row's expiry is not consulted. The caller follows it so the `token.revoke`
   * row names the principal that asked for the revocation (R6).
   */
  it("passes no expiry and attributes the revocation to the caller", async () => {
    await app.request("/api/v1/tokens/jti-1", { method: "DELETE", headers: AUTH });
    expect(engine.revokeToken.mock.calls[0]).toEqual(["jti-1", undefined, ADMIN_CALLER]);
  });

  it("decodes a percent-encoded jti", async () => {
    await app.request("/api/v1/tokens/jti%2F1", { method: "DELETE", headers: AUTH });
    expect(engine.revokeToken).toHaveBeenCalledWith("jti/1", undefined, ADMIN_CALLER);
  });

  it("requires admin scope before the engine call", async () => {
    engine = createMockEngine(READ_TOKEN);
    app = buildApp(engine);
    const res = await app.request("/api/v1/tokens/jti-1", { method: "DELETE", headers: AUTH });
    expect(res.status).toBe(403);
    expect(engine.revokeToken).not.toHaveBeenCalled();
  });

  it("requires auth", async () => {
    const res = await app.request("/api/v1/tokens/jti-1", { method: "DELETE" });
    expect(res.status).toBe(401);
  });
});
