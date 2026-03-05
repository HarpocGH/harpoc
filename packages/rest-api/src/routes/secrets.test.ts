import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { RateLimiter } from "../middleware/rate-limit.js";
import { createSecretRoutes } from "./secrets.js";
import type { HarpocEnv } from "../types.js";

const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["list", "read", "create", "rotate", "revoke", "use"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
};

function createMockEngine() {
  return {
    verifyToken: vi.fn().mockReturnValue(MOCK_TOKEN),
    listSecrets: vi.fn().mockReturnValue([
      {
        handle: "secret://test-key",
        name: "test-key",
        type: "api_key",
        project: null,
        status: "active",
        version: 1,
        createdAt: 1000,
        updatedAt: 1000,
        expiresAt: null,
        rotatedAt: null,
      },
    ]),
    createSecret: vi.fn().mockResolvedValue({
      handle: "secret://new-key",
      status: "created",
      message: "Secret created",
    }),
    getSecretInfo: vi.fn().mockResolvedValue({
      handle: "secret://test-key",
      name: "test-key",
      type: "api_key",
      project: null,
      status: "active",
      version: 1,
      createdAt: 1000,
      updatedAt: 1000,
      expiresAt: null,
      rotatedAt: null,
    }),
    getSecretValue: vi.fn().mockResolvedValue(new Uint8Array([72, 101, 108, 108, 111])),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    useSecret: vi.fn().mockResolvedValue({
      status: 200,
      headers: { "content-type": "application/json" },
      body: '{"ok":true}',
    }),
    resolveSecretId: vi.fn().mockResolvedValue("secret-uuid-1"),
  };
}

let app: Hono<HarpocEnv>;
let engine: ReturnType<typeof createMockEngine>;

beforeEach(() => {
  engine = createMockEngine();
  app = new Hono<HarpocEnv>();
  app.onError(errorHandler);
  const limiter = new RateLimiter();
  app.use("*", async (c, next) => {
    c.set("engine", engine as never);
    c.set("limiter", limiter);
    await next();
  });
  app.use("/api/v1/secrets", authMiddleware);
  app.use("/api/v1/secrets/*", authMiddleware);
  app.route("/api/v1/secrets", createSecretRoutes());
});

const AUTH = { authorization: "Bearer valid-jwt" };

describe("secret routes", () => {
  describe("GET /api/v1/secrets", () => {
    it("lists secrets", async () => {
      const res = await app.request("/api/v1/secrets", { headers: AUTH });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toHaveLength(1);
      expect(body.data[0].name).toBe("test-key");
    });

    it("passes project query param to engine", async () => {
      await app.request("/api/v1/secrets?project=myproj", { headers: AUTH });
      expect(engine.listSecrets).toHaveBeenCalledWith("myproj");
    });

    it("rejects without auth", async () => {
      const res = await app.request("/api/v1/secrets");
      expect(res.status).toBe(401);
    });

    it("rejects if token lacks list scope", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read"] });
      const res = await app.request("/api/v1/secrets", { headers: AUTH });
      expect(res.status).toBe(403);
    });
  });

  describe("POST /api/v1/secrets", () => {
    it("creates a secret", async () => {
      const res = await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ name: "new-key", type: "api_key" }),
      });
      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.handle).toBe("secret://new-key");
    });

    it("creates a secret with base64 value", async () => {
      const value = Buffer.from("my-secret-value").toString("base64");
      await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ name: "new-key", type: "api_key", value }),
      });

      const call = engine.createSecret.mock.calls[0] as Array<{ value?: Uint8Array }>;
      expect(call[0].value).toBeInstanceOf(Uint8Array);
      expect(Buffer.from(call[0].value as Uint8Array).toString()).toBe("my-secret-value");
    });

    it("rejects if token lacks create scope", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read"] });
      const res = await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ name: "new-key", type: "api_key" }),
      });
      expect(res.status).toBe(403);
    });
  });

  describe("GET /api/v1/secrets/:handle", () => {
    it("returns secret info", async () => {
      const res = await app.request("/api/v1/secrets/test-key", { headers: AUTH });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.name).toBe("test-key");
      expect(engine.getSecretInfo).toHaveBeenCalledWith("secret://test-key");
    });

    it("returns 404 for unknown secret", async () => {
      engine.getSecretInfo.mockRejectedValue(VaultError.secretNotFound("unknown"));
      const res = await app.request("/api/v1/secrets/unknown", { headers: AUTH });
      expect(res.status).toBe(404);
    });
  });

  describe("GET /api/v1/secrets/:handle/value", () => {
    it("returns secret value as base64", async () => {
      const res = await app.request("/api/v1/secrets/test-key/value", { headers: AUTH });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.value).toBe(Buffer.from("Hello").toString("base64"));
    });
  });

  describe("DELETE /api/v1/secrets/:handle", () => {
    it("revokes secret with confirm=true", async () => {
      const res = await app.request("/api/v1/secrets/test-key?confirm=true", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(200);
      expect(engine.revokeSecret).toHaveBeenCalledWith("secret://test-key");
    });

    it("rejects without confirm=true", async () => {
      const res = await app.request("/api/v1/secrets/test-key", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe(ErrorCode.INVALID_INPUT);
    });

    it("rejects if token lacks revoke scope", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read"] });
      const res = await app.request("/api/v1/secrets/test-key?confirm=true", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(403);
    });
  });

  describe("POST /api/v1/secrets/:handle/rotate", () => {
    it("rotates a secret", async () => {
      const value = Buffer.from("new-value").toString("base64");
      const res = await app.request("/api/v1/secrets/test-key/rotate", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ value }),
      });
      expect(res.status).toBe(200);
      expect(engine.rotateSecret).toHaveBeenCalled();

      const call = engine.rotateSecret.mock.calls[0] as [string, Uint8Array];
      expect(call[0]).toBe("secret://test-key");
      expect(Buffer.from(call[1]).toString()).toBe("new-value");
    });

    it("rejects without value", async () => {
      const res = await app.request("/api/v1/secrets/test-key/rotate", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
    });
  });

  describe("POST /api/v1/secrets/:handle/use", () => {
    it("executes HTTP request with injected secret", async () => {
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          request: { method: "GET", url: "https://api.example.com/data" },
          injection: { type: "bearer" },
        }),
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.status).toBe(200);
    });

    it("passes timeout_ms and follow_redirects correctly", async () => {
      await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          request: { method: "GET", url: "https://api.example.com", timeout_ms: 5000 },
          injection: { type: "bearer" },
          follow_redirects: "none",
        }),
      });

      const call = engine.useSecret.mock.calls[0] as unknown[];
      expect(call[0]).toBe("secret://test-key");
      expect((call[1] as { timeoutMs: number }).timeoutMs).toBe(5000);
      expect(call[3]).toBe("none");
    });
  });

  describe("POST /api/v1/secrets/:handle/use validation", () => {
    it("rejects invalid URL", async () => {
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          request: { method: "GET", url: "not-a-url" },
          injection: { type: "bearer" },
        }),
      });
      expect(res.status).toBe(400);
    });

    it("rejects timeout_ms exceeding 300000", async () => {
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          request: { method: "GET", url: "https://example.com", timeout_ms: 9007199254740991 },
          injection: { type: "bearer" },
        }),
      });
      expect(res.status).toBe(400);
    });

    it("rejects non-integer timeout_ms", async () => {
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          request: { method: "GET", url: "https://example.com", timeout_ms: 1.5 },
          injection: { type: "bearer" },
        }),
      });
      expect(res.status).toBe(400);
    });

    it("sanitizes credential patterns in response body", async () => {
      engine.useSecret.mockResolvedValue({
        status: 200,
        body: '{"error":"Invalid token: Bearer sk_live_abcdefghij1234567890"}',
      });
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          request: { method: "GET", url: "https://api.example.com/data" },
          injection: { type: "bearer" },
        }),
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.body).not.toContain("sk_live_abcdefghij1234567890");
      expect(body.data.body).toContain("[REDACTED]");
    });
  });

  describe("POST /api/v1/secrets create validation", () => {
    it("rejects non-numeric expires_at", async () => {
      const res = await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ name: "new-key", type: "api_key", expires_at: "never" }),
      });
      expect(res.status).toBe(400);
    });

    it("accepts valid numeric expires_at", async () => {
      const res = await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          name: "new-key",
          type: "api_key",
          expires_at: Date.now() + 86400000,
        }),
      });
      expect(res.status).toBe(201);
    });
  });

  describe("scope enforcement", () => {
    it("admin scope grants access to all operations", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["admin"] });

      const res = await app.request("/api/v1/secrets", { headers: AUTH });
      expect(res.status).toBe(200);

      const res2 = await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ name: "k", type: "api_key" }),
      });
      expect(res2.status).toBe(201);
    });
  });
});
