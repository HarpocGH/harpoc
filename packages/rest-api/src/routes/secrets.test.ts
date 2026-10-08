import { describe, it, expect, beforeEach } from "vitest";
import type { Hono } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import {
  AUTH,
  EXPECTED_CALLER,
  MOCK_TOKEN,
  NON_OBJECT_BODIES,
  buildSecretsApp,
  createMockEngine,
} from "./__fixtures__/secrets-app.js";

let app: Hono<HarpocEnv>;
let engine: ReturnType<typeof createMockEngine>;

beforeEach(() => {
  engine = createMockEngine();
  app = buildSecretsApp(engine);
});

describe("secret routes", () => {
  describe("GET /api/v1/secrets", () => {
    it("lists secrets", async () => {
      const res = await app.request("/api/v1/secrets", { headers: AUTH });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toHaveLength(1);
      expect(body.data[0].name).toBe("test-key");
      expect(engine.verifyToken).toHaveBeenCalledTimes(1);
    });

    it("passes project query param to engine", async () => {
      await app.request("/api/v1/secrets?project=myproj", { headers: AUTH });
      expect(engine.listSecrets).toHaveBeenCalledWith("myproj", expect.anything());
    });

    // W2: enumeration is engine-gated by the `list` permission, so the route
    // must hand over the caller — without it a policy-gated secret's metadata
    // row stays enumerable to any list-scoped token.
    it("passes the token-derived caller to listSecrets", async () => {
      await app.request("/api/v1/secrets", { headers: AUTH });
      expect(engine.listSecrets).toHaveBeenCalledWith(undefined, EXPECTED_CALLER);
    });

    it("rejects without auth", async () => {
      const res = await app.request("/api/v1/secrets");
      expect(res.status).toBe(401);
      expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.INVALID_TOKEN);
    });

    it("rejects if token lacks list scope", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read"] });
      const res = await app.request("/api/v1/secrets", { headers: AUTH });
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);
    });
  });

  describe("token secret-name patterns (thesis §4.7)", () => {
    it("filters the list by * patterns", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets: ["test-*"] });
      const res = await app.request("/api/v1/secrets", { headers: AUTH });
      const body = await res.json();
      expect(body.data).toHaveLength(1);

      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets: ["db-*"] });
      const res2 = await app.request("/api/v1/secrets", { headers: AUTH });
      const body2 = await res2.json();
      expect(body2.data).toHaveLength(0);
    });

    it("enforces patterns on individual secret access", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets: ["db-*"] });
      const denied = await app.request("/api/v1/secrets/test-key", { headers: AUTH });
      expect(denied.status).toBe(403);
      expect(((await denied.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);

      const allowed = await app.request("/api/v1/secrets/db-prod", { headers: AUTH });
      expect(allowed.status).toBe(200);
    });

    it("keeps exact-name scoping intact", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets: ["test-key"] });
      const allowed = await app.request("/api/v1/secrets/test-key", { headers: AUTH });
      expect(allowed.status).toBe(200);

      const denied = await app.request("/api/v1/secrets/test-key-2", { headers: AUTH });
      expect(denied.status).toBe(403);
      expect(((await denied.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);
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

      const call = engine.createSecret.mock.calls[0] as [{ value?: Uint8Array }];
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
      expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);
    });

    it("a bodyless POST is a descriptive 400, not a generic 500", async () => {
      const res = await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string; message: string };
      expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
      expect(body.message).toBe("Request body must be valid JSON");
      expect(engine.createSecret).not.toHaveBeenCalled();
    });
  });

  describe("GET /api/v1/secrets/:handle", () => {
    it("returns secret info", async () => {
      const res = await app.request("/api/v1/secrets/test-key", { headers: AUTH });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.name).toBe("test-key");
      expect(engine.getSecretInfo).toHaveBeenCalledWith("secret://test-key", EXPECTED_CALLER);
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
      expect(engine.revokeSecret).toHaveBeenCalledWith("secret://test-key", EXPECTED_CALLER);
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
      expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);
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

    // L7: `Buffer.from(x, "base64")` discards invalid characters silently, so a
    // malformed value irreversibly rotated the credential to garbage while the
    // route answered 200 {rotated:true}. The create route validated; this did not.
    it("rejects a non-base64 value before the engine is touched", async () => {
      for (const value of ["not base64!!", "***", "AA=A"]) {
        const res = await app.request("/api/v1/secrets/test-key/rotate", {
          method: "POST",
          headers: { ...AUTH, "content-type": "application/json" },
          body: JSON.stringify({ value }),
        });
        expect(res.status).toBe(400);
      }
      expect(engine.rotateSecret).not.toHaveBeenCalled();
    });

    it("rejects a non-string value", async () => {
      const res = await app.request("/api/v1/secrets/test-key/rotate", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ value: 42 }),
      });
      expect(res.status).toBe(400);
      expect(engine.rotateSecret).not.toHaveBeenCalled();
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

    it.each(NON_OBJECT_BODIES)(
      "refuses %s body with the framing message and never reaches the engine",
      async (_kind, raw) => {
        const res = await app.request("/api/v1/secrets", {
          method: "POST",
          headers: { ...AUTH, "content-type": "application/json" },
          body: raw,
        });
        expect(res.status).toBe(400);
        const body = (await res.json()) as { error: string; message: string };
        expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
        expect(body.message).toBe("Request body must be valid JSON");
        expect(engine.createSecret).not.toHaveBeenCalled();
      },
    );
  });
});
