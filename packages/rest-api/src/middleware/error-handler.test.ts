import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { errorHandler } from "./error-handler.js";
import type { HarpocEnv } from "../types.js";

function createTestApp(thrower: () => never) {
  const app = new Hono<HarpocEnv>();
  app.onError(errorHandler);
  app.get("/test", () => thrower());
  return app;
}

describe("errorHandler", () => {
  it("maps VaultError to JSON with correct status", async () => {
    const app = createTestApp(() => {
      throw VaultError.secretNotFound("mykey");
    });

    const res = await app.request("/test");
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toBe(ErrorCode.SECRET_NOT_FOUND);
    expect(body.message).toContain("mykey");
  });

  it("maps VAULT_LOCKED to 503 (not 423)", async () => {
    const app = createTestApp(() => {
      throw VaultError.vaultLocked();
    });

    const res = await app.request("/test");
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error).toBe(ErrorCode.VAULT_LOCKED);
  });

  it("maps ACCESS_DENIED to 403", async () => {
    const app = createTestApp(() => {
      throw VaultError.accessDenied("nope");
    });

    const res = await app.request("/test");
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe(ErrorCode.ACCESS_DENIED);
  });

  it("maps RATE_LIMIT_EXCEEDED to 429", async () => {
    const app = createTestApp(() => {
      throw new VaultError(ErrorCode.RATE_LIMIT_EXCEEDED, "Too many");
    });

    const res = await app.request("/test");
    expect(res.status).toBe(429);
  });

  it("maps unknown errors to 500 INTERNAL_ERROR", async () => {
    const app = createTestApp(() => {
      throw new Error("unexpected");
    });

    const res = await app.request("/test");
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe(ErrorCode.INTERNAL_ERROR);
    expect(body.message).toBe("Internal server error");
  });

  it("does not leak internal error details to response", async () => {
    const app = createTestApp(() => {
      throw new Error("sensitive db connection string: postgres://user:pass@host");
    });

    const res = await app.request("/test");
    const body = await res.json();
    expect(body.message).toBe("Internal server error");
    expect(body.message).not.toContain("postgres");
  });

  it("uses statusCode from VaultError for all error codes", async () => {
    const codeStatusPairs: [ErrorCode, number][] = [
      [ErrorCode.INVALID_PASSWORD, 401],
      [ErrorCode.TOKEN_EXPIRED, 401],
      [ErrorCode.TOKEN_REVOKED, 401],
      [ErrorCode.LOCKOUT_ACTIVE, 429],
      [ErrorCode.DUPLICATE_SECRET, 409],
      [ErrorCode.INVALID_INPUT, 400],
      [ErrorCode.SSRF_BLOCKED, 403],
      [ErrorCode.TIMEOUT, 504],
      [ErrorCode.DATABASE_ERROR, 500],
    ];

    for (const [code, expectedStatus] of codeStatusPairs) {
      const app = createTestApp(() => {
        throw new VaultError(code, `test ${code}`);
      });

      const res = await app.request("/test");
      expect(res.status).toBe(code === ErrorCode.VAULT_LOCKED ? 503 : expectedStatus);
      const body = await res.json();
      expect(body.error).toBe(code);
    }
  });

  it("includes details for actionable error codes like LOCKOUT_ACTIVE", async () => {
    const app = createTestApp(() => {
      throw new VaultError(ErrorCode.LOCKOUT_ACTIVE, "Locked out", {
        retry_after_ms: 30000,
      });
    });

    const res = await app.request("/test");
    expect(res.status).toBe(429);
    const body = await res.json();
    expect(body.error).toBe(ErrorCode.LOCKOUT_ACTIVE);
    expect(body.details).toEqual({ retry_after_ms: 30000 });
  });

  it("omits details when VaultError has no details", async () => {
    const app = createTestApp(() => {
      throw VaultError.accessDenied("forbidden");
    });

    const res = await app.request("/test");
    const body = await res.json();
    expect(body).not.toHaveProperty("details");
  });
});
