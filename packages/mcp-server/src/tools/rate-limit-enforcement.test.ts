import { describe, it, expect, vi, beforeEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CertManager } from "@harpoc/cert-manager";
import type { SecretInfo, VaultEngine } from "@harpoc/core";
import type { OAuthManager } from "@harpoc/oauth-proxy";
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

/**
 * T8 (MCP half): `RATE_LIMIT_EXCEEDED` was asserted only inside the rate
 * limiter's own unit test and, since M10b, for `create_secret`. Deleting the
 * `checkLimit` call from any other tool left the suite green — the guard that
 * bounds how fast an agent can drive the credential surface was effectively
 * untested at the tool boundary.
 */

const INFO: SecretInfo = {
  handle: "secret://my-key",
  name: "my-key",
  type: "api_key",
  project: null,
  status: "active",
  version: 1,
  createdAt: 1000,
  updatedAt: 2000,
  expiresAt: null,
  rotatedAt: null,
};

function mockEngine(): VaultEngine {
  return {
    listSecrets: vi.fn().mockReturnValue([INFO]),
    getSecretInfo: vi.fn().mockResolvedValue(INFO),
    useSecret: vi.fn().mockResolvedValue({ type: "http", status: 200, body: "{}" }),
    createSecret: vi.fn().mockResolvedValue({
      handle: "secret://new-key",
      status: "pending",
      message: "Secret created without value",
    }),
    createOAuthSecret: vi.fn().mockResolvedValue({ handle: "secret://gh-app", secretId: "uuid-1" }),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-123"),
    getState: vi.fn().mockReturnValue("unlocked"),
    getExpiringOAuthTokenStatuses: vi.fn().mockReturnValue([]),
    getExpiringCertificateStatuses: vi.fn().mockReturnValue([]),
  } as unknown as VaultEngine;
}

async function callTool(
  server: McpServer,
  name: string,
  args: Record<string, unknown>,
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
  const lowLevelServer = (
    server as unknown as { server: { _requestHandlers: Map<string, unknown> } }
  ).server;
  const handler = lowLevelServer._requestHandlers.get("tools/call") as (
    req: { method: string; params: { name: string; arguments?: Record<string, unknown> } },
    extra: unknown,
  ) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;
  return handler(
    { method: "tools/call", params: { name, arguments: args } },
    { signal: new AbortController().signal, sessionId: "test" },
  );
}

const HTTP_ACTION = {
  type: "http",
  method: "GET",
  url: "https://api.example.com/v1/ping",
  injection: { type: "bearer" },
};

type Register = (server: McpServer, engine: VaultEngine, limiter: RateLimiter) => void;

interface ToolCase {
  tool: string;
  args: Record<string, unknown>;
  register: Register;
}

let engine: VaultEngine;
let scopeGuard: ScopeGuard;
let injectionGuard: InjectionGuard;
let oauthManager: OAuthManager;
let certManager: CertManager;

beforeEach(() => {
  engine = mockEngine();
  scopeGuard = new ScopeGuard(null);
  injectionGuard = new InjectionGuard();
  oauthManager = {
    startDeviceCode: vi.fn(),
    startClientCredentials: vi.fn(),
  } as unknown as OAuthManager;
  certManager = {
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
});

const CASES: ToolCase[] = [
  {
    tool: "list_secrets",
    args: {},
    register: (s, e, l) => registerListSecrets(s, e, scopeGuard, l),
  },
  {
    tool: "get_secret_info",
    args: { handle: "secret://my-key" },
    register: (s, e, l) => registerGetSecretInfo(s, e, scopeGuard, l),
  },
  {
    tool: "use_secret",
    args: { handle: "secret://my-key", action: HTTP_ACTION },
    register: (s, e, l) => registerUseSecret(s, e, scopeGuard, l, injectionGuard),
  },
  {
    tool: "create_secret",
    args: { name: "new-key", type: "api_key" },
    register: (s, e, l) => registerCreateSecret(s, e, scopeGuard, l),
  },
  {
    tool: "rotate_secret",
    args: { handle: "secret://my-key" },
    register: (s, e, l) => registerRotateSecret(s, e, scopeGuard, l),
  },
  {
    tool: "revoke_secret",
    args: { handle: "secret://my-key" },
    register: (s, e, l) => registerRevokeSecret(s, e, scopeGuard, l),
  },
  {
    tool: "check_secret_health",
    args: {},
    register: (s, e, l) => registerCheckHealth(s, e, scopeGuard, l),
  },
  {
    tool: "start_oauth_flow",
    args: {
      name: "new-key",
      provider: "github",
      grant_type: "authorization_code",
      client_id: "client-1",
    },
    register: (s, e, l) => registerStartOauthFlow(s, e, scopeGuard, l, oauthManager),
  },
  {
    tool: "renew_certificate",
    args: { handle: "secret://my-key" },
    register: (s, e, l) => registerRenewCertificate(s, e, scopeGuard, l, certManager),
  },
];

describe("every MCP tool consults the rate limiter (T8)", () => {
  it.each(CASES)(
    "$tool refuses once the global tier is exhausted",
    async ({ tool, args, register }) => {
      const server = new McpServer({ name: "t", version: "0.0.0" });
      // Global tier of one: the first call spends it, the second must be refused
      // before the engine is reached.
      const limiter = new RateLimiter(1, 10_000, 10_000);
      register(server, engine, limiter);

      const first = await callTool(server, tool, args);
      expect(first.isError ?? false).toBe(false);

      const second = await callTool(server, tool, args);
      expect(second.isError).toBe(true);
      expect(second.content[0]?.text ?? "").toContain("rate limit");
    },
  );

  it.each(CASES)(
    "control: $tool answers twice under a default limiter",
    async ({ tool, args, register }) => {
      const server = new McpServer({ name: "t", version: "0.0.0" });
      register(server, engine, new RateLimiter());

      await callTool(server, tool, args);
      const second = await callTool(server, tool, args);
      expect(second.isError ?? false).toBe(false);
    },
  );

  /**
   * The per-secret tiers are separate buckets, and `use_secret` is the one
   * keyed by the requested handle under its own (higher) limit — a tier the
   * global-exhaustion case above cannot distinguish.
   */
  it("use_secret is bounded by the use tier, keyed by the requested handle", async () => {
    const server = new McpServer({ name: "t", version: "0.0.0" });
    const limiter = new RateLimiter(10_000, 10_000, 2);
    registerUseSecret(server, engine, scopeGuard, limiter, injectionGuard);

    const args = { handle: "secret://my-key", action: HTTP_ACTION };

    expect((await callTool(server, "use_secret", args)).isError ?? false).toBe(false);
    expect((await callTool(server, "use_secret", args)).isError ?? false).toBe(false);

    const exhausted = await callTool(server, "use_secret", args);
    expect(exhausted.isError).toBe(true);
    expect(exhausted.content[0]?.text ?? "").toContain("rate limit");
  });

  it("rotate_secret buckets per requested name, not vault-wide", async () => {
    const server = new McpServer({ name: "t", version: "0.0.0" });
    const limiter = new RateLimiter(10_000, 1);
    registerRotateSecret(server, engine, scopeGuard, limiter);

    await callTool(server, "rotate_secret", { handle: "secret://my-key" });
    const sameName = await callTool(server, "rotate_secret", { handle: "secret://my-key" });
    expect(sameName.isError).toBe(true);

    const otherName = await callTool(server, "rotate_secret", { handle: "secret://other-key" });
    expect(otherName.isError ?? false).toBe(false);
  });
});
