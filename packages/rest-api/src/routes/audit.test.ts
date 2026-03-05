import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import type { VaultApiToken } from "@harpoc/shared";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { createAuditRoutes } from "./audit.js";
import type { HarpocEnv } from "../types.js";

const ADMIN_TOKEN: VaultApiToken = {
  sub: "admin-agent",
  vault_id: "vault-1",
  scope: ["admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-admin",
};

const NON_ADMIN_TOKEN: VaultApiToken = {
  ...ADMIN_TOKEN,
  scope: ["read", "list"],
};

function createMockEngine(token: VaultApiToken = ADMIN_TOKEN) {
  return {
    verifyToken: vi.fn().mockReturnValue(token),
    queryAudit: vi.fn().mockReturnValue([
      {
        id: 1,
        timestamp: 1000,
        event_type: "vault.unlock",
        secret_id: null,
        principal_type: null,
        principal_id: null,
        detail: { action: "unlock" },
        ip_address: null,
        session_id: "sess-1",
        success: true,
      },
    ]),
  };
}

let app: Hono<HarpocEnv>;
let engine: ReturnType<typeof createMockEngine>;

beforeEach(() => {
  engine = createMockEngine();
  app = new Hono<HarpocEnv>();
  app.onError(errorHandler);
  app.use("*", async (c, next) => {
    c.set("engine", engine as never);
    await next();
  });
  app.use("/api/v1/audit", authMiddleware);
  app.route("/api/v1/audit", createAuditRoutes());
});

const AUTH = { authorization: "Bearer valid-jwt" };

describe("audit routes", () => {
  it("GET /api/v1/audit returns audit events", async () => {
    const res = await app.request("/api/v1/audit", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toHaveLength(1);
    expect(body.data[0].event_type).toBe("vault.unlock");
  });

  it("passes query params to engine.queryAudit", async () => {
    const uuid = "01234567-89ab-cdef-0123-456789abcdef";
    await app.request(
      `/api/v1/audit?secret_id=${uuid}&event_type=secret.read&since=1000&until=2000&limit=10`,
      { headers: AUTH },
    );

    expect(engine.queryAudit).toHaveBeenCalledWith({
      secretId: uuid,
      eventType: "secret.read",
      since: 1000,
      until: 2000,
      limit: 10,
    });
  });

  it("requires admin scope", async () => {
    engine = createMockEngine(NON_ADMIN_TOKEN);
    app = new Hono<HarpocEnv>();
    app.onError(errorHandler);
    app.use("*", async (c, next) => {
      c.set("engine", engine as never);
      await next();
    });
    app.use("/api/v1/audit", authMiddleware);
    app.route("/api/v1/audit", createAuditRoutes());

    const res = await app.request("/api/v1/audit", { headers: AUTH });
    expect(res.status).toBe(403);
  });

  it("handles omitted query params", async () => {
    await app.request("/api/v1/audit", { headers: AUTH });

    expect(engine.queryAudit).toHaveBeenCalledWith({
      secretId: undefined,
      eventType: undefined,
      since: undefined,
      until: undefined,
      limit: undefined,
    });
  });
});
