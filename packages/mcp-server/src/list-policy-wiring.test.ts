import { describe, it, expect, vi, beforeEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SecretInfo, VaultEngine } from "@harpoc/core";
import type { VaultApiToken } from "@harpoc/shared";
import { RateLimiter } from "./guards/rate-limiter.js";
import { ScopeGuard } from "./guards/scope-guard.js";
import { registerListSecrets } from "./tools/list-secrets.js";
import { registerCheckHealth } from "./tools/check-health.js";
import { registerSecretsResource } from "./resources/secrets.js";
import { registerHealthResource } from "./resources/health.js";
import { registerProjectsResource } from "./resources/projects.js";

/**
 * W2 — every MCP enumeration surface hands the token-derived caller to the
 * engine, so per-secret `list` policies apply; and the by-name resource reads
 * through the gated `getSecretInfo` instead of answering out of the listing.
 */

const TOKEN: VaultApiToken = {
  sub: "agent-1",
  vault_id: "vault-1",
  scope: ["list", "read"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
};

const EXPECTED_CALLER = {
  principal_type: "agent",
  principal_id: "agent-1",
  interface: "mcp",
};

const VISIBLE: SecretInfo = {
  handle: "secret://visible",
  name: "visible",
  type: "api_key",
  project: "api",
  status: "active",
  version: 1,
  createdAt: 1000,
  updatedAt: 2000,
  expiresAt: null,
  rotatedAt: null,
};

const GATED: SecretInfo = {
  handle: "secret://gated",
  name: "gated",
  type: "api_key",
  project: "db",
  status: "active",
  version: 1,
  createdAt: 1000,
  updatedAt: 2000,
  expiresAt: Date.now() + 60_000,
  rotatedAt: null,
};

/** Stands in for the engine's policy filter: a caller sees only VISIBLE. */
function mockEngine(): VaultEngine {
  return {
    listSecrets: vi.fn((_project?: string, caller?: unknown) =>
      caller ? [VISIBLE] : [VISIBLE, GATED],
    ),
    getSecretInfo: vi.fn().mockResolvedValue(VISIBLE),
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

async function readResource(
  server: McpServer,
  uri: string,
): Promise<{ contents: Array<{ text?: string }> }> {
  const lowLevelServer = (
    server as unknown as { server: { _requestHandlers: Map<string, unknown> } }
  ).server;
  const handler = lowLevelServer._requestHandlers.get("resources/read") as (
    req: { method: string; params: { uri: string } },
    extra: unknown,
  ) => Promise<{ contents: Array<{ text?: string }> }>;
  return handler(
    { method: "resources/read", params: { uri } },
    { signal: new AbortController().signal, sessionId: "test" },
  );
}

function firstText(result: { contents: Array<{ text?: string }> }): string {
  return result.contents[0]?.text ?? "";
}

let server: McpServer;
let engine: VaultEngine;
let scopeGuard: ScopeGuard;
let rateLimiter: RateLimiter;

beforeEach(() => {
  server = new McpServer({ name: "test", version: "0.0.0" });
  engine = mockEngine();
  scopeGuard = new ScopeGuard(TOKEN);
  rateLimiter = new RateLimiter();
});

describe("tools", () => {
  it("list_secrets passes the token-derived caller and returns only the permitted rows", async () => {
    registerListSecrets(server, engine, scopeGuard, rateLimiter);

    const result = await callTool(server, "list_secrets", {});
    expect(engine.listSecrets).toHaveBeenCalledWith(undefined, EXPECTED_CALLER);

    const data = JSON.parse(result.content[0]?.text ?? "[]") as Array<{ name: string }>;
    expect(data.map((s) => s.name)).toEqual(["visible"]);
  });

  it("check_secret_health aggregates over the engine-filtered set", async () => {
    registerCheckHealth(server, engine, scopeGuard, rateLimiter);

    const result = await callTool(server, "check_secret_health", {});
    expect(engine.listSecrets).toHaveBeenCalledWith(undefined, EXPECTED_CALLER);

    const data = JSON.parse(result.content[0]?.text ?? "{}") as {
      total_secrets: number;
      expiring_soon: Array<{ handle: string }>;
    };
    // GATED expires within the window — its absence proves the aggregate is
    // computed over the filtered listing, not a fresh unfiltered one.
    expect(data.total_secrets).toBe(1);
    expect(data.expiring_soon).toHaveLength(0);
  });
});

describe("resources", () => {
  it("secrets-list passes the caller", async () => {
    registerSecretsResource(server, engine, scopeGuard);

    const text = firstText(await readResource(server, "secret://vault/secrets"));
    expect(engine.listSecrets).toHaveBeenCalledWith(undefined, EXPECTED_CALLER);
    expect(text).toContain("visible");
    expect(text).not.toContain("gated");
  });

  it("vault-health passes the caller", async () => {
    registerHealthResource(server, engine, scopeGuard);

    const text = firstText(await readResource(server, "secret://vault/health"));
    expect(engine.listSecrets).toHaveBeenCalledWith(undefined, EXPECTED_CALLER);
    expect(JSON.parse(text).total_secrets).toBe(1);
  });

  it("projects census passes the caller", async () => {
    registerProjectsResource(server, engine, scopeGuard);

    const text = firstText(await readResource(server, "secret://vault/projects"));
    expect(engine.listSecrets).toHaveBeenCalledWith(undefined, EXPECTED_CALLER);
    const census = JSON.parse(text) as Array<{ project: string }>;
    expect(census.map((c) => c.project)).toEqual(["api"]);
  });

  it("secret-by-name reads through the gated getSecretInfo, not the listing", async () => {
    registerSecretsResource(server, engine, scopeGuard);

    const text = firstText(await readResource(server, "secret://vault/secrets/visible"));
    expect(engine.getSecretInfo).toHaveBeenCalledWith("secret://visible", EXPECTED_CALLER);
    expect(JSON.parse(text).name).toBe("visible");
  });

  it("secret-by-name propagates a policy denial instead of serving the row", async () => {
    (
      engine.getSecretInfo as unknown as { mockRejectedValue: (e: Error) => void }
    ).mockRejectedValue(new Error("ACCESS_DENIED"));
    registerSecretsResource(server, engine, scopeGuard);

    await expect(readResource(server, "secret://vault/secrets/visible")).rejects.toThrow();
  });
});

describe("trusted local path", () => {
  it("a tokenless guard forwards no caller — the full-access mode is unfiltered", async () => {
    const tokenless = new ScopeGuard(null);
    registerListSecrets(server, engine, tokenless, rateLimiter);

    const result = await callTool(server, "list_secrets", {});
    expect(engine.listSecrets).toHaveBeenCalledWith(undefined, undefined);

    const data = JSON.parse(result.content[0]?.text ?? "[]") as Array<{ name: string }>;
    expect(data.map((s) => s.name).sort()).toEqual(["gated", "visible"]);
  });
});
