import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { authMiddleware } from "./auth.js";
import { errorHandler } from "./error-handler.js";
import type { HarpocEnv } from "../types.js";

const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["read", "list"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
};

function createTestApp(verifyResult: VaultApiToken | VaultError) {
  const engine = {
    verifyToken: vi.fn().mockImplementation(() => {
      if (verifyResult instanceof VaultError) throw verifyResult;
      return verifyResult;
    }),
  };

  const app = new Hono<HarpocEnv>();
  app.onError(errorHandler);
  app.use("*", async (c, next) => {
    c.set("engine", engine as never);
    await next();
  });
  app.use("*", authMiddleware);
  app.get("/test", (c) => {
    const token = c.get("token");
    return c.json({ sub: token.sub });
  });

  return { app, engine };
}

describe("authMiddleware", () => {
  it("sets token in context on valid auth", async () => {
    const { app } = createTestApp(MOCK_TOKEN);

    const res = await app.request("/test", {
      headers: { authorization: "Bearer valid-jwt" },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.sub).toBe("test-agent");
  });

  it("returns 401 when Authorization header is missing", async () => {
    const { app } = createTestApp(MOCK_TOKEN);

    const res = await app.request("/test");
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe(ErrorCode.INVALID_TOKEN);
  });

  it("returns 401 for malformed Authorization header", async () => {
    const { app } = createTestApp(MOCK_TOKEN);

    const res = await app.request("/test", {
      headers: { authorization: "Basic abc123" },
    });

    expect(res.status).toBe(401);
  });

  it("returns 401 for expired token", async () => {
    const { app } = createTestApp(VaultError.tokenExpired());

    const res = await app.request("/test", {
      headers: { authorization: "Bearer expired-jwt" },
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe(ErrorCode.TOKEN_EXPIRED);
  });

  it("returns 401 for revoked token", async () => {
    const { app } = createTestApp(VaultError.tokenRevoked());

    const res = await app.request("/test", {
      headers: { authorization: "Bearer revoked-jwt" },
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe(ErrorCode.TOKEN_REVOKED);
  });

  it("passes the raw token string to engine.verifyToken", async () => {
    const { app, engine } = createTestApp(MOCK_TOKEN);

    await app.request("/test", {
      headers: { authorization: "Bearer my-jwt-value" },
    });

    expect(engine.verifyToken).toHaveBeenCalledWith("my-jwt-value");
  });
});
