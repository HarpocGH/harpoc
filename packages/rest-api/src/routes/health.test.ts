import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import { VaultState, VAULT_VERSION } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { createHealthRoutes, createExpiringSecretsRoute } from "./health.js";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import type { HarpocEnv } from "../types.js";

const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
};

function createTestApp(
  state: string,
  secrets: Array<{
    expiresAt: number | null;
    status: string;
    name?: string;
    project?: string | null;
  }> = [],
  token: VaultApiToken = MOCK_TOKEN,
) {
  const engine = {
    getState: vi.fn().mockReturnValue(state),
    verifyToken: vi.fn().mockReturnValue(token),
    listSecrets: vi.fn().mockReturnValue(
      secrets.map((s, i) => ({
        handle: `secret://${s.name ?? `key${i}`}`,
        name: s.name ?? `key${i}`,
        type: "api_key",
        project: s.project ?? null,
        status: s.status,
        version: 1,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        expiresAt: s.expiresAt,
        rotatedAt: null,
      })),
    ),
  };

  const app = new Hono<HarpocEnv>();
  app.onError(errorHandler);
  app.use("*", async (c, next) => {
    c.set("engine", engine as never);
    await next();
  });
  app.route("/api/v1/health", createHealthRoutes());
  app.use("/api/v1/health/expiring", authMiddleware);
  app.route("/api/v1/health/expiring", createExpiringSecretsRoute());

  return { app, engine };
}

const AUTH = { authorization: "Bearer valid-jwt" };

describe("health routes", () => {
  it("GET /api/v1/health returns state and version", async () => {
    const { app } = createTestApp(VaultState.UNLOCKED);

    const res = await app.request("/api/v1/health");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.state).toBe("unlocked");
    expect(body.data.version).toBe(VAULT_VERSION);
  });

  it("GET /api/v1/health returns sealed state", async () => {
    const { app } = createTestApp(VaultState.SEALED);

    const res = await app.request("/api/v1/health");
    const body = await res.json();
    expect(body.data.state).toBe("sealed");
  });

  it("GET /api/v1/health/expiring requires auth", async () => {
    const { app } = createTestApp(VaultState.SEALED);

    const res = await app.request("/api/v1/health/expiring");
    expect(res.status).toBe(401);
  });

  it("GET /api/v1/health/expiring returns empty count when sealed", async () => {
    const { app } = createTestApp(VaultState.SEALED);

    const res = await app.request("/api/v1/health/expiring", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual({ count: 0 });
  });

  it("GET /api/v1/health/expiring returns secrets expiring within default 7 days", async () => {
    const now = Date.now();
    const threeDays = now + 3 * 24 * 60 * 60 * 1000;
    const tenDays = now + 10 * 24 * 60 * 60 * 1000;

    const { app } = createTestApp(VaultState.UNLOCKED, [
      { expiresAt: threeDays, status: "active" },
      { expiresAt: tenDays, status: "active" },
      { expiresAt: null, status: "active" },
    ]);

    const res = await app.request("/api/v1/health/expiring", { headers: AUTH });
    const body = await res.json();
    expect(body.data).toHaveLength(1);
    expect(body.data[0].name).toBe("key0");
  });

  it("GET /api/v1/health/expiring respects custom days param", async () => {
    const now = Date.now();
    const threeDays = now + 3 * 24 * 60 * 60 * 1000;

    const { app } = createTestApp(VaultState.UNLOCKED, [
      { expiresAt: threeDays, status: "active" },
    ]);

    const res = await app.request("/api/v1/health/expiring?days=1", { headers: AUTH });
    const body = await res.json();
    expect(body.data).toHaveLength(0);

    const res2 = await app.request("/api/v1/health/expiring?days=30", { headers: AUTH });
    const body2 = await res2.json();
    expect(body2.data).toHaveLength(1);
  });

  it("GET /api/v1/health/expiring excludes non-active secrets", async () => {
    const now = Date.now();
    const threeDays = now + 3 * 24 * 60 * 60 * 1000;

    const { app } = createTestApp(VaultState.UNLOCKED, [
      { expiresAt: threeDays, status: "revoked" },
    ]);

    const res = await app.request("/api/v1/health/expiring", { headers: AUTH });
    const body = await res.json();
    expect(body.data).toHaveLength(0);
  });

  it("GET /api/v1/health/expiring denies tokens without list permission", async () => {
    const now = Date.now();
    const { app } = createTestApp(
      VaultState.UNLOCKED,
      [{ expiresAt: now + 1000, status: "active" }],
      { ...MOCK_TOKEN, scope: ["use"] },
    );

    const res = await app.request("/api/v1/health/expiring", { headers: AUTH });
    expect(res.status).toBe(403);
  });

  it("GET /api/v1/health/expiring filters by token secret-name scope", async () => {
    const now = Date.now();
    const threeDays = now + 3 * 24 * 60 * 60 * 1000;

    const { app } = createTestApp(
      VaultState.UNLOCKED,
      [
        { expiresAt: threeDays, status: "active", name: "db-prod" },
        { expiresAt: threeDays, status: "active", name: "api-key" },
      ],
      { ...MOCK_TOKEN, scope: ["list"], secrets: ["db-*"] },
    );

    const res = await app.request("/api/v1/health/expiring", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toHaveLength(1);
    expect(body.data[0].name).toBe("db-prod");
  });

  it("GET /api/v1/health/expiring scopes the listing to the token's project", async () => {
    const { app, engine } = createTestApp(VaultState.UNLOCKED, [], {
      ...MOCK_TOKEN,
      scope: ["list"],
      project: "proj-a",
    });

    const res = await app.request("/api/v1/health/expiring", { headers: AUTH });
    expect(res.status).toBe(200);
    expect(engine.listSecrets).toHaveBeenCalledWith("proj-a");
  });

  it("GET /api/v1/health/expiring rejects out-of-range and malformed days", async () => {
    const { app } = createTestApp(VaultState.UNLOCKED, []);

    for (const days of ["99999999", "366", "0", "-1", "abc", "7.5"]) {
      const res = await app.request(`/api/v1/health/expiring?days=${days}`, { headers: AUTH });
      expect(res.status).toBe(400);
    }

    const ok = await app.request("/api/v1/health/expiring?days=365", { headers: AUTH });
    expect(ok.status).toBe(200);
  });
});
