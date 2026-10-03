import { describe, it, expect, vi } from "vitest";
import { McpServer } from "@modelcontextprotocol/server";
import { connectInMemoryClient } from "@harpoc/test-utils";
import type { CertManager } from "@harpoc/cert-manager";
import type { SecretInfo, VaultEngine } from "@harpoc/core";
import type { OAuthManager } from "@harpoc/oauth-proxy";
import type { Permission, ScopeRefusalReason, VaultApiToken } from "@harpoc/shared";
import { InjectionGuard } from "../guards/injection-guard.js";
import { RateLimiter } from "../guards/rate-limiter.js";
import { ScopeGuard } from "../guards/scope-guard.js";
import { registerListSecrets } from "./list-secrets.js";
import { registerGetSecretInfo } from "./get-secret-info.js";
import { registerUseSecret } from "./use-secret.js";
import { registerCreateSecret } from "./create-secret.js";
import { registerRenewCertificate } from "./renew-certificate.js";
import { registerRotateSecret } from "./rotate-secret.js";
import { registerRevokeSecret } from "./revoke-secret.js";
import { registerStartOauthFlow } from "./start-oauth-flow.js";
import { registerCheckHealth } from "./check-health.js";

const INFO: SecretInfo = {
  handle: "secret://default/prod-key",
  name: "prod-key",
  type: "api_key",
  project: "default",
  status: "active",
  version: 1,
  createdAt: 1000,
  updatedAt: 2000,
  expiresAt: null,
  rotatedAt: null,
};

const SCOPE: Permission[] = ["list", "read", "use", "create", "rotate", "revoke"];

const HTTP_ACTION = {
  type: "http",
  method: "GET",
  url: "https://api.example.com/v1/ping",
  injection: { type: "bearer" },
};

function mockEngine(): VaultEngine {
  return {
    listSecrets: vi.fn().mockReturnValue([INFO]),
    getSecretInfo: vi.fn().mockResolvedValue(INFO),
    useSecret: vi.fn().mockResolvedValue({ type: "http", status: 200, body: "{}" }),
    createSecret: vi.fn().mockResolvedValue({
      handle: INFO.handle,
      status: "pending",
      message: "Secret created without value",
    }),
    createOAuthSecret: vi.fn().mockResolvedValue({ handle: INFO.handle, secretId: "uuid-1" }),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-123"),
    getState: vi.fn().mockReturnValue("unlocked"),
    getExpiringOAuthTokenStatuses: vi.fn().mockReturnValue([]),
    getExpiringCertificateStatuses: vi.fn().mockReturnValue([]),
    secretNameTaken: vi.fn().mockResolvedValue(false),
    assertRotateAllowed: vi.fn().mockResolvedValue(undefined),
  } as unknown as VaultEngine;
}

function makeToken(overrides: Partial<VaultApiToken>): VaultApiToken {
  return {
    sub: "agent-1",
    vault_id: "vault-1",
    scope: SCOPE,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: "jti-scope-refusal",
    principal_type: "agent",
    ...overrides,
  };
}

const oauthManager = {
  startDeviceCode: vi.fn(),
  startClientCredentials: vi.fn(),
} as unknown as OAuthManager;

const certManager = {
  renewCertificate: vi.fn().mockResolvedValue({
    secret_id: "uuid-123",
    subject: "CN=example.com",
    issuer: "CN=fixture-ca",
    not_before: 1_000,
    not_after: 2_000,
    auto_renew: true,
    renewal_status: "ok",
  }),
} as unknown as CertManager;

type Register = (server: McpServer, engine: VaultEngine, guard: ScopeGuard) => void;

interface ToolCase {
  tool: string;
  args: Record<string, unknown>;
  permission: Permission;
  reaches: keyof VaultEngine;
  register: Register;
}

interface RefusalCase extends ToolCase {
  token: Partial<VaultApiToken>;
  reason: ScopeRefusalReason;
}

const CASES: ToolCase[] = [
  {
    tool: "list_secrets",
    args: { project: "default" },
    permission: "list",
    reaches: "listSecrets",
    register: (s, e, g) => registerListSecrets(s, e, g, new RateLimiter()),
  },
  {
    tool: "get_secret_info",
    args: { handle: INFO.handle },
    permission: "read",
    reaches: "getSecretInfo",
    register: (s, e, g) => registerGetSecretInfo(s, e, g, new RateLimiter()),
  },
  {
    tool: "use_secret",
    args: { handle: INFO.handle, action: HTTP_ACTION },
    permission: "use",
    reaches: "useSecret",
    register: (s, e, g) => registerUseSecret(s, e, g, new RateLimiter(), new InjectionGuard()),
  },
  {
    tool: "create_secret",
    args: { name: "prod-key", type: "api_key", project: "default" },
    permission: "create",
    reaches: "createSecret",
    register: (s, e, g) => registerCreateSecret(s, e, g, new RateLimiter()),
  },
  {
    tool: "rotate_secret",
    args: { handle: INFO.handle },
    permission: "rotate",
    reaches: "assertRotateAllowed",
    register: (s, e, g) => registerRotateSecret(s, e, g, new RateLimiter()),
  },
  {
    tool: "revoke_secret",
    args: { handle: INFO.handle },
    permission: "revoke",
    reaches: "revokeSecret",
    register: (s, e, g) => registerRevokeSecret(s, e, g, new RateLimiter()),
  },
  {
    tool: "check_secret_health",
    args: {},
    permission: "list",
    reaches: "listSecrets",
    register: (s, e, g) => registerCheckHealth(s, e, g, new RateLimiter()),
  },
  {
    tool: "start_oauth_flow",
    args: {
      name: "prod-key",
      provider: "github",
      grant_type: "authorization_code",
      client_id: "client-1",
      project: "default",
    },
    permission: "create",
    reaches: "createOAuthSecret",
    register: (s, e, g) => registerStartOauthFlow(s, e, g, new RateLimiter(), oauthManager),
  },
  {
    tool: "renew_certificate",
    args: { handle: INFO.handle },
    permission: "rotate",
    reaches: "resolveSecretId",
    register: (s, e, g) => registerRenewCertificate(s, e, g, new RateLimiter(), certManager),
  },
];

const DIMENSIONS: Record<string, ScopeRefusalReason[]> = {
  list_secrets: ["project"],
  get_secret_info: ["project", "secret"],
  use_secret: ["project", "secret"],
  create_secret: ["project", "secret"],
  rotate_secret: ["project", "secret"],
  revoke_secret: ["project", "secret"],
  start_oauth_flow: ["project", "secret"],
  renew_certificate: ["project", "secret"],
};

const REFUSALS: RefusalCase[] = [
  ...CASES.map((c) => ({
    ...c,
    token: { scope: SCOPE.filter((p) => p !== c.permission) },
    reason: "permission" as const,
  })),
  ...CASES.flatMap((c) =>
    (DIMENSIONS[c.tool] ?? []).map((reason) => ({
      ...c,
      token: reason === "project" ? { project: "other" } : { secrets: ["ci-*"] },
      reason,
    })),
  ),
];

describe("every MCP tool consults the scope guard (C3)", () => {
  it.each(REFUSALS)(
    "$tool refuses a token on $reason before the engine",
    async ({ tool, args, register, token, reason }) => {
      const engine = mockEngine();
      const seen = vi.fn();
      const guard = new ScopeGuard(makeToken(token), "mcp", undefined, undefined, seen);
      const server = new McpServer({ name: "t", version: "0.0.0" });
      register(server, engine, guard);

      const client = await connectInMemoryClient(server);
      try {
        const result = await client.callTool(tool, args);
        expect(result.isError).toBe(true);
        expect(result.content[0]?.text ?? "").toContain("Access denied");
        expect(seen).toHaveBeenCalledExactlyOnceWith(tool, reason);
        for (const [method, fn] of Object.entries(engine)) {
          expect(fn, method).not.toHaveBeenCalled();
        }
      } finally {
        await client.close();
      }
    },
  );

  it.each(CASES)(
    "control: $tool answers a token holding every dimension",
    async ({ tool, args, register, reaches }) => {
      const engine = mockEngine();
      const seen = vi.fn();
      const token = makeToken({ project: "default", secrets: ["prod-*"] });
      const guard = new ScopeGuard(token, "mcp", undefined, undefined, seen);
      const server = new McpServer({ name: "t", version: "0.0.0" });
      register(server, engine, guard);

      const client = await connectInMemoryClient(server);
      try {
        const result = await client.callTool(tool, args);
        expect(result.isError ?? false).toBe(false);
        expect(seen).not.toHaveBeenCalled();
        expect(engine[reaches]).toHaveBeenCalled();
      } finally {
        await client.close();
      }
    },
  );

  it("the dimension table names only inventoried tools and holds 24 refusal rows", () => {
    const tools = new Set(CASES.map((c) => c.tool));
    expect(Object.keys(DIMENSIONS).filter((tool) => !tools.has(tool))).toEqual([]);
    expect(REFUSALS).toHaveLength(24);
  });
});
