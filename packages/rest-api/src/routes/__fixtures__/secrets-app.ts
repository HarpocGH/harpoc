import { vi } from "vitest";
import type { Mock } from "vitest";
import { Hono } from "hono";
import type { VaultApiToken } from "@harpoc/shared";
import { authMiddleware } from "../../middleware/auth.js";
import { errorHandler } from "../../middleware/error-handler.js";
import { RateLimiter } from "../../middleware/rate-limit.js";
import { createSecretRoutes } from "../secrets.js";
import type { HarpocEnv } from "../../types.js";

// The readJsonBody non-object clause: every JSON scalar and the array are
// refused before any route reads a field (D2, 2026-08-20).
export const NON_OBJECT_BODIES = [
  ["a string", '"hi"'],
  ["a number", "42"],
  ["a boolean", "true"],
  ["null", "null"],
  ["an array", "[1,2]"],
] as const;

// R3: the PUT body is the whole policy — every field, no defaults.
export const FULL_POLICY = {
  url_allowlist: ["https://api.github.com/*"],
  command_allowlist: ["gh"],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "status_only",
  response_header_allowlist: ["Content-Type"],
  network_isolation: false,
  fs_isolation: false,
  smtp_recipient_allowlist: [],
  imap_read_only: false,
  strict_tree_exit: false,
};

export const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["list", "read", "create", "rotate", "revoke", "use", "admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
};

/** The engine methods the secrets routes call, each a vitest mock. */
export interface MockEngine {
  verifyToken: Mock;
  auditScopeRefusal: Mock;
  listSecrets: Mock;
  createSecret: Mock;
  getSecretInfo: Mock;
  getSecretValue: Mock;
  revokeSecret: Mock;
  rotateSecret: Mock;
  useSecret: Mock;
  setInjectionPolicy: Mock;
  getInjectionPolicy: Mock;
  setMcpServerConfig: Mock;
  getMcpServerConfig: Mock;
  deleteMcpServerConfig: Mock;
  setConnectionConfig: Mock;
  getConnectionConfig: Mock;
  deleteConnectionConfig: Mock;
}

export function createMockEngine(): MockEngine {
  return {
    verifyToken: vi.fn().mockReturnValue(MOCK_TOKEN),
    auditScopeRefusal: vi.fn(),
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
      type: "http",
      status: 200,
      headers: { "content-type": "application/json" },
      body: '{"ok":true}',
    }),
    setInjectionPolicy: vi.fn().mockResolvedValue(undefined),
    getInjectionPolicy: vi.fn().mockResolvedValue({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
    }),
    setMcpServerConfig: vi.fn().mockResolvedValue(undefined),
    getMcpServerConfig: vi.fn().mockResolvedValue(undefined),
    deleteMcpServerConfig: vi.fn().mockResolvedValue(true),
    setConnectionConfig: vi.fn().mockResolvedValue(undefined),
    getConnectionConfig: vi.fn().mockResolvedValue(undefined),
    deleteConnectionConfig: vi.fn().mockResolvedValue(true),
  };
}

/**
 * The secrets route group as the suites drive it: one `authMiddleware` registration,
 * as `app.ts` mounts it (`/api/v1/secrets/*` also matches the bare collection path).
 */
export function buildSecretsApp(engine: MockEngine): Hono<HarpocEnv> {
  const app = new Hono<HarpocEnv>();
  app.onError(errorHandler);
  const limiter = new RateLimiter();
  app.use("*", async (c, next) => {
    c.set("engine", engine as never);
    c.set("limiter", limiter);
    await next();
  });
  app.use("/api/v1/secrets/*", authMiddleware);
  app.route("/api/v1/secrets", createSecretRoutes());
  return app;
}

export const AUTH = { authorization: "Bearer valid-jwt" };

export const EXPECTED_CALLER = {
  principal_type: "agent",
  principal_id: "test-agent",
  interface: "rest",
  admin_scope: true,
};
