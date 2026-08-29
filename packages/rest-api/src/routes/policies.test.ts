import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import type { VaultApiToken, AccessPolicy } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
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
  principal_type: "agent",
};

const READ_TOKEN: VaultApiToken = {
  sub: "read-agent",
  vault_id: "vault-1",
  scope: ["read"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-read",
  principal_type: "agent",
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

    it("refuses an agent principal_id that is not a valid agent name (C34)", async () => {
      const res = await app.request("/api/v1/secrets/test-key/policies", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          principal_type: "agent",
          principal_id: "a b",
          permissions: ["read"],
        }),
      });
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe("SCHEMA_VALIDATION_ERROR");
      expect(engine.grantPolicy).not.toHaveBeenCalled();
    });
  });

  describe("DELETE /api/v1/secrets/:handle/policies/:policyId", () => {
    it("revokes a policy", async () => {
      const res = await app.request("/api/v1/secrets/test-key/policies/policy-1", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(200);
      expect(engine.revokePolicy).toHaveBeenCalledWith(
        "policy-1",
        expect.objectContaining({ principal_id: "admin-agent" }),
      );
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

      const res = await app.request("/api/v1/secrets/test-key/policies/policy-1", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(403);
      expect(engine.revokePolicy).not.toHaveBeenCalled();
    });
  });

  // W1: the policy surface itself is engine-gated (read for the listing,
  // admin for grant/revoke) — the routes must therefore hand over the caller.
  describe("engine-level policy enforcement wiring", () => {
    const EXPECTED_CALLER = {
      principal_type: "agent",
      principal_id: "admin-agent",
      interface: "rest",
      // R7 (v1.4.1): callerFromToken marks every admin-scoped token. The mark
      // exempts user-type callers only — this agent-type caller stays gated.
      admin_scope: true,
    };

    it("GET passes the token-derived caller to listPolicies", async () => {
      await app.request("/api/v1/secrets/test-key/policies", { headers: AUTH });
      expect(engine.listPolicies).toHaveBeenCalledWith("secret-uuid-1", EXPECTED_CALLER);
    });

    it("POST passes the caller to grantPolicy", async () => {
      await app.request("/api/v1/secrets/test-key/policies", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          principal_type: "agent",
          principal_id: "agent-1",
          permissions: ["read"],
        }),
      });
      expect(engine.grantPolicy).toHaveBeenCalledWith(
        expect.objectContaining({ secretId: "secret-uuid-1" }),
        "admin-agent",
        EXPECTED_CALLER,
      );
    });

    it("an engine ACCESS_DENIED maps to 403", async () => {
      engine.listPolicies.mockImplementation(() => {
        throw VaultError.accessDenied("Principal lacks 'read' permission on this secret");
      });
      const res = await app.request("/api/v1/secrets/test-key/policies", { headers: AUTH });
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe(ErrorCode.ACCESS_DENIED);
    });
  });
});
