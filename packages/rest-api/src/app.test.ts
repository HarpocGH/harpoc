import { describe, it, expect, vi } from "vitest";
import { VaultError, VaultState, VAULT_VERSION } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { createApp } from "./app.js";

const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
};

function createMockEngine() {
  return {
    getState: vi.fn().mockReturnValue(VaultState.UNLOCKED),
    verifyToken: vi.fn().mockReturnValue(MOCK_TOKEN),
    listSecrets: vi.fn().mockReturnValue([]),
    createSecret: vi.fn().mockResolvedValue({
      handle: "secret://k",
      status: "created",
      message: "Secret created",
    }),
    getSecretInfo: vi.fn().mockResolvedValue({
      handle: "secret://k",
      name: "k",
      type: "api_key",
      project: null,
      status: "active",
      version: 1,
      createdAt: 1000,
      updatedAt: 1000,
      expiresAt: null,
      rotatedAt: null,
    }),
    getSecretValue: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3])),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    useSecret: vi.fn().mockResolvedValue({ status: 200 }),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-1"),
    listPolicies: vi.fn().mockReturnValue([{
      id: "p1",
      secret_id: "uuid-1",
      principal_type: "agent",
      principal_id: "a1",
      permissions: ["read"],
      created_at: Date.now(),
      expires_at: null,
      created_by: "test-agent",
    }]),
    grantPolicy: vi.fn().mockReturnValue({
      id: "p1",
      secret_id: "uuid-1",
      principal_type: "agent",
      principal_id: "a1",
      permissions: ["read"],
      created_at: Date.now(),
      expires_at: null,
      created_by: "test-agent",
    }),
    revokePolicy: vi.fn(),
    queryAudit: vi.fn().mockReturnValue([]),
  };
}

describe("createApp integration", () => {
  it("health endpoint works without auth", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/health");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.state).toBe("unlocked");
    expect(body.data.version).toBe(VAULT_VERSION);
  });

  it("protected routes require auth", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/secrets");
    expect(res.status).toBe(401);
  });

  it("protected routes work with valid auth", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: "Bearer valid" },
    });
    expect(res.status).toBe(200);
  });

  it("secret CRUD flow works end-to-end", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);
    const headers = { authorization: "Bearer valid", "content-type": "application/json" };

    // Create
    const createRes = await app.request("/api/v1/secrets", {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "k", type: "api_key" }),
    });
    expect(createRes.status).toBe(201);

    // Read info
    const infoRes = await app.request("/api/v1/secrets/k", {
      headers: { authorization: "Bearer valid" },
    });
    expect(infoRes.status).toBe(200);

    // Read value
    const valueRes = await app.request("/api/v1/secrets/k/value", {
      headers: { authorization: "Bearer valid" },
    });
    expect(valueRes.status).toBe(200);

    // Rotate
    const rotateRes = await app.request("/api/v1/secrets/k/rotate", {
      method: "POST",
      headers,
      body: JSON.stringify({ value: Buffer.from("new").toString("base64") }),
    });
    expect(rotateRes.status).toBe(200);

    // Revoke
    const revokeRes = await app.request("/api/v1/secrets/k?confirm=true", {
      method: "DELETE",
      headers: { authorization: "Bearer valid" },
    });
    expect(revokeRes.status).toBe(200);
  });

  it("policy flow works through app", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);
    const headers = { authorization: "Bearer valid", "content-type": "application/json" };

    // Grant
    const grantRes = await app.request("/api/v1/secrets/k/policies", {
      method: "POST",
      headers,
      body: JSON.stringify({
        principal_type: "agent",
        principal_id: "a1",
        permissions: ["read"],
      }),
    });
    expect(grantRes.status).toBe(201);

    // List
    const listRes = await app.request("/api/v1/secrets/k/policies", {
      headers: { authorization: "Bearer valid" },
    });
    expect(listRes.status).toBe(200);

    // Revoke
    const revokeRes = await app.request("/api/v1/secrets/k/policies/p1", {
      method: "DELETE",
      headers: { authorization: "Bearer valid" },
    });
    expect(revokeRes.status).toBe(200);
  });

  it("audit query works through app", async () => {
    const engine = createMockEngine();
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/audit", {
      headers: { authorization: "Bearer valid" },
    });
    expect(res.status).toBe(200);
  });

  it("VAULT_LOCKED errors return 503", async () => {
    const engine = createMockEngine();
    engine.verifyToken.mockImplementation(() => {
      throw VaultError.vaultLocked();
    });
    const app = createApp(engine as never);

    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: "Bearer valid" },
    });
    expect(res.status).toBe(503);
  });
});
