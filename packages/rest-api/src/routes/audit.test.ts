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
    verifyAuditChain: vi.fn().mockReturnValue({
      valid: true,
      checked: 12,
      legacy: 2,
      firstBrokenId: null,
      tail: { lastId: 14, timestamp: 999, rowHmac: new Uint8Array([1]) },
    }),
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
  app.use("/api/v1/audit/*", authMiddleware);
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

    expect(engine.queryAudit).toHaveBeenCalledWith(
      {
        secretId: uuid,
        eventType: "secret.read",
        since: 1000,
        until: 2000,
        limit: 10,
      },
      // Unrestricted admin token: no scope filter is applied (L10).
      undefined,
    );
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

    expect(engine.queryAudit).toHaveBeenCalledWith(
      {
        secretId: undefined,
        eventType: undefined,
        since: undefined,
        until: undefined,
        limit: undefined,
      },
      undefined,
    );
  });

  // L10: the route enforced the permission dimension only, so a project- or
  // name-pattern-scoped admin token read audit detail for every secret in the
  // vault — with `?secret_id=` as a targeted oracle.
  it("passes a name-pattern-scoped token's scope to the engine", async () => {
    const scoped: VaultApiToken = { ...ADMIN_TOKEN, secrets: ["db-*"] };
    engine = createMockEngine(scoped);
    app = new Hono<HarpocEnv>();
    app.onError(errorHandler);
    app.use("*", async (c, next) => {
      c.set("engine", engine as never);
      await next();
    });
    app.use("/api/v1/audit", authMiddleware);
    app.route("/api/v1/audit", createAuditRoutes());

    await app.request("/api/v1/audit", { headers: AUTH });

    expect(engine.queryAudit).toHaveBeenCalledWith(expect.anything(), { secrets: ["db-*"] });
  });

  it("passes a project-scoped token's scope to the engine", async () => {
    const scoped: VaultApiToken = { ...ADMIN_TOKEN, project: "finance" };
    engine = createMockEngine(scoped);
    app = new Hono<HarpocEnv>();
    app.onError(errorHandler);
    app.use("*", async (c, next) => {
      c.set("engine", engine as never);
      await next();
    });
    app.use("/api/v1/audit", authMiddleware);
    app.route("/api/v1/audit", createAuditRoutes());

    await app.request("/api/v1/audit?secret_id=01234567-89ab-cdef-0123-456789abcdef", {
      headers: AUTH,
    });

    expect(engine.queryAudit).toHaveBeenCalledWith(expect.anything(), { project: "finance" });
  });

  it("passes success=false to engine.queryAudit", async () => {
    await app.request("/api/v1/audit?success=false", { headers: AUTH });
    expect(engine.queryAudit).toHaveBeenCalledWith(
      expect.objectContaining({ success: false }),
      undefined,
    );
  });

  it("passes success=true to engine.queryAudit", async () => {
    await app.request("/api/v1/audit?success=true", { headers: AUTH });
    expect(engine.queryAudit).toHaveBeenCalledWith(
      expect.objectContaining({ success: true }),
      undefined,
    );
  });

  it("rejects a non-boolean success value", async () => {
    const res = await app.request("/api/v1/audit?success=maybe", { headers: AUTH });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("SCHEMA_VALIDATION_ERROR");
  });

  it("forwards the principal filter to engine.queryAudit", async () => {
    await app.request("/api/v1/audit?principal_type=agent&principal_id=deploy-bot", {
      headers: AUTH,
    });
    expect(engine.queryAudit).toHaveBeenCalledWith(
      expect.objectContaining({ principalType: "agent", principalId: "deploy-bot" }),
      undefined,
    );
  });

  it("forwards principal_id alone", async () => {
    await app.request("/api/v1/audit?principal_id=deploy-bot", { headers: AUTH });
    expect(engine.queryAudit).toHaveBeenCalledWith(
      expect.objectContaining({ principalType: undefined, principalId: "deploy-bot" }),
      undefined,
    );
  });

  it("rejects an unknown principal_type", async () => {
    const res = await app.request("/api/v1/audit?principal_type=robot", { headers: AUTH });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("SCHEMA_VALIDATION_ERROR");
    expect(engine.queryAudit).not.toHaveBeenCalled();
  });

  it("rejects an empty principal_id", async () => {
    const res = await app.request("/api/v1/audit?principal_id=", { headers: AUTH });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("SCHEMA_VALIDATION_ERROR");
    expect(engine.queryAudit).not.toHaveBeenCalled();
  });
});

describe("POST /api/v1/audit/verify", () => {
  it("returns the verification report in snake_case without the tail", async () => {
    const res = await app.request("/api/v1/audit/verify", { method: "POST", headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual({ valid: true, checked: 12, legacy: 2, first_broken_id: null });
    expect(body.data.tail).toBeUndefined();
  });

  it("requires admin scope", async () => {
    engine = createMockEngine(NON_ADMIN_TOKEN);
    // rebuild app exactly as beforeEach does, with the non-admin engine
    app = new Hono<HarpocEnv>();
    app.onError(errorHandler);
    app.use("*", async (c, next) => {
      c.set("engine", engine as never);
      await next();
    });
    app.use("/api/v1/audit/*", authMiddleware);
    app.route("/api/v1/audit", createAuditRoutes());

    const res = await app.request("/api/v1/audit/verify", { method: "POST", headers: AUTH });
    expect(res.status).toBe(403);
  });

  it("requires auth", async () => {
    const res = await app.request("/api/v1/audit/verify", { method: "POST" });
    expect(res.status).toBe(401);
  });
});
