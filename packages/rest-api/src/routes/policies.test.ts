import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import type { VaultApiToken, AccessPolicy } from "@harpoc/shared";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { createPolicyRoutes } from "./policies.js";
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
  sub: "read-agent",
  vault_id: "vault-1",
  scope: ["read"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-read",
};

const MOCK_POLICY: AccessPolicy = {
  id: "policy-1",
  secret_id: "secret-uuid-1",
  principal_type: "agent",
  principal_id: "agent-1",
  permissions: ["read", "use"],
  created_at: Date.now(),
  expires_at: null,
  created_by: "admin-agent",
};

function createMockEngine(token: VaultApiToken = ADMIN_TOKEN) {
  return {
    verifyToken: vi.fn().mockReturnValue(token),
    resolveSecretId: vi.fn().mockResolvedValue("secret-uuid-1"),
    listPolicies: vi.fn().mockReturnValue([MOCK_POLICY]),
    grantPolicy: vi.fn().mockReturnValue(MOCK_POLICY),
    revokePolicy: vi.fn(),
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
  app.use("/api/v1/secrets/*", authMiddleware);
  app.route("/api/v1/secrets", createPolicyRoutes());
});

const AUTH = { authorization: "Bearer valid-jwt" };

describe("policy routes", () => {
  describe("GET /api/v1/secrets/:handle/policies", () => {
    it("lists policies for a secret", async () => {
      const res = await app.request("/api/v1/secrets/test-key/policies", { headers: AUTH });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toHaveLength(1);
      expect(body.data[0].id).toBe("policy-1");
      expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://test-key");
    });

    it("requires read scope", async () => {
      engine = createMockEngine({ ...ADMIN_TOKEN, scope: ["create"] });
      app = new Hono<HarpocEnv>();
      app.onError(errorHandler);
      app.use("*", async (c, next) => {
        c.set("engine", engine as never);
        await next();
      });
      app.use("/api/v1/secrets/*", authMiddleware);
      app.route("/api/v1/secrets", createPolicyRoutes());

      const res = await app.request("/api/v1/secrets/test-key/policies", { headers: AUTH });
      expect(res.status).toBe(403);
    });
  });

  describe("POST /api/v1/secrets/:handle/policies", () => {
    it("grants a policy", async () => {
      const res = await app.request("/api/v1/secrets/test-key/policies", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          principal_type: "agent",
          principal_id: "agent-1",
          permissions: ["read", "use"],
        }),
      });
      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.id).toBe("policy-1");
    });

    it("requires admin scope", async () => {
      engine = createMockEngine(READ_TOKEN);
      app = new Hono<HarpocEnv>();
      app.onError(errorHandler);
      app.use("*", async (c, next) => {
        c.set("engine", engine as never);
        await next();
      });
      app.use("/api/v1/secrets/*", authMiddleware);
      app.route("/api/v1/secrets", createPolicyRoutes());

      const res = await app.request("/api/v1/secrets/test-key/policies", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          principal_type: "agent",
          principal_id: "agent-1",
          permissions: ["read"],
        }),
      });
      expect(res.status).toBe(403);
    });

    it("rejects with missing required fields", async () => {
      const res = await app.request("/api/v1/secrets/test-key/policies", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ principal_type: "agent" }),
      });
      expect(res.status).toBe(400);
    });
  });

  describe("DELETE /api/v1/secrets/:handle/policies/:policyId", () => {
    it("revokes a policy", async () => {
      const res = await app.request("/api/v1/secrets/test-key/policies/policy-1", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(200);
      expect(engine.revokePolicy).toHaveBeenCalledWith("policy-1");
    });

    it("returns 404 for unknown policy", async () => {
      const res = await app.request("/api/v1/secrets/test-key/policies/unknown", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(404);
    });

    it("returns 404 for policy belonging to a different secret (IDOR prevention)", async () => {
      // listPolicies returns MOCK_POLICY with id "policy-1" for secret "secret-uuid-1"
      // Trying to delete "other-policy-id" through this secret should fail
      const res = await app.request("/api/v1/secrets/test-key/policies/other-policy-id", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.error).toBe("POLICY_NOT_FOUND");
    });
  });
});
