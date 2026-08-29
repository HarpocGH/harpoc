import { describe, it, expect, vi } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CertManager } from "@harpoc/cert-manager";
import type { VaultEngine } from "@harpoc/core";
import type { OAuthManager } from "@harpoc/oauth-proxy";
import { createMcpServer } from "../server.js";
import { collectValueViaUrlElicitation } from "../elicitation/value-collector.js";

// Real by default (the no-channel test relies on the genuine capability probe);
// the collect-succeeds case overrides it per call.
vi.mock("../elicitation/value-collector.js", async () => {
  const actual = await vi.importActual<typeof import("../elicitation/value-collector.js")>(
    "../elicitation/value-collector.js",
  );
  return {
    ...actual,
    collectValueViaUrlElicitation: vi.fn(actual.collectValueViaUrlElicitation),
  };
});

/**
 * D1 (config-then-defer): the tool must expose exactly these inputs — the
 * absence of `client_secret` is the property under test, not an omission.
 */
const EXPECTED_INPUT_PROPERTIES = [
  "auth_endpoint",
  "client_id",
  "device_authorization_endpoint",
  "grant_type",
  "name",
  "project",
  "provider",
  "scopes",
  "token_endpoint",
  "token_endpoint_auth_method",
];

const EXPECTED_CALLER = {
  principal_type: "agent",
  principal_id: "agent",
  interface: "mcp",
};

function token(scope: string[]): Record<string, unknown> {
  return {
    sub: "agent",
    vault_id: "v",
    scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: "jti-1",
    principal_type: "agent",
  };
}

function mockEngine(overrides: Record<string, unknown> = {}): VaultEngine {
  return {
    listSecrets: vi.fn().mockReturnValue([]),
    getSecretInfo: vi.fn().mockResolvedValue({}),
    useSecret: vi.fn().mockResolvedValue({ status: 200, body: "" }),
    createSecret: vi
      .fn()
      .mockResolvedValue({ handle: "secret://x", status: "pending", message: "" }),
    createOAuthSecret: vi.fn().mockResolvedValue({ handle: "secret://gh-app", secretId: "uuid-1" }),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-123"),
    getState: vi.fn().mockReturnValue("unlocked"),
    queryAudit: vi.fn().mockReturnValue([]),
    auditServerStart: vi.fn(),
    isTokenRevoked: vi.fn().mockReturnValue(false),
    verifyToken: vi.fn().mockReturnValue(token(["create"])),
    ...overrides,
  } as unknown as VaultEngine;
}

interface Harness {
  server: McpServer;
  engine: VaultEngine;
  oauthManager: OAuthManager;
}

function harness(
  options: {
    scope?: string[];
    oauthOverrides?: Record<string, unknown>;
  } = {},
): Harness {
  const engine = mockEngine({
    verifyToken: vi.fn().mockReturnValue(token(options.scope ?? ["create"])),
  });
  const oauthManager = {
    startDeviceCode: vi.fn(),
    startClientCredentials: vi.fn(),
    ...options.oauthOverrides,
  } as unknown as OAuthManager;
  const server = createMcpServer({
    engine,
    launchToken: "jwt",
    oauthManager,
    certManager: {} as unknown as CertManager,
  });
  return { server, engine, oauthManager };
}

function requestHandler<T>(server: McpServer, method: string): (req: unknown, extra: unknown) => T {
  const lowLevel = (server as unknown as { server: { _requestHandlers: Map<string, unknown> } })
    .server;
  const handler = lowLevel._requestHandlers.get(method);
  if (!handler) throw new Error(`No ${method} handler found`);
  return handler as (req: unknown, extra: unknown) => T;
}

const EXTRA = { signal: new AbortController().signal, sessionId: "test" };

interface ToolDescriptor {
  name: string;
  inputSchema: { properties?: Record<string, unknown> };
}

async function listTools(server: McpServer): Promise<ToolDescriptor[]> {
  const handler = requestHandler<Promise<{ tools: ToolDescriptor[] }>>(server, "tools/list");
  const result = await handler({ method: "tools/list", params: {} }, EXTRA);
  return result.tools;
}

interface ToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

function callTool(
  server: McpServer,
  name: string,
  args: Record<string, unknown>,
): Promise<ToolResult> {
  const handler = requestHandler<Promise<ToolResult>>(server, "tools/call");
  return handler({ method: "tools/call", params: { name, arguments: args } }, EXTRA);
}

function toolData(result: ToolResult): Record<string, unknown> {
  return JSON.parse((result.content[0] as { text: string }).text) as Record<string, unknown>;
}

function oauthConfigOf(engine: VaultEngine): Record<string, unknown> {
  const calls = (engine.createOAuthSecret as ReturnType<typeof vi.fn>).mock.calls;
  return (calls[0] as [string, Record<string, unknown>])[1];
}

describe("start_oauth_flow", () => {
  it("accepts no client_secret input property (D1)", async () => {
    const { server } = harness();
    const tool = (await listTools(server)).find((t) => t.name === "start_oauth_flow");
    expect(tool).toBeDefined();
    const properties = Object.keys((tool as ToolDescriptor).inputSchema.properties ?? {}).sort();
    expect(properties).toEqual(EXPECTED_INPUT_PROPERTIES);
  });

  it("the advertised schema itself rejects a non-loopback plain-HTTP endpoint", async () => {
    // Contract must match enforcement: the shared oauthEndpointUrlSchema
    // (HTTPS-or-loopback) refuses at the tool schema, not later inside
    // providerConfigFromFlowInput with different error text than REST gives.
    const { server, engine } = harness();

    const result = await callTool(server, "start_oauth_flow", {
      name: "gh-app",
      provider: "custom",
      grant_type: "client_credentials",
      client_id: "cid",
      token_endpoint: "http://attacker.example/token",
    });

    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain("-32602");
    expect(result.content[0]?.text).toContain("HTTPS");
    expect(engine.createOAuthSecret).not.toHaveBeenCalled();
  });

  it("the advertised schema itself caps the secret name length", async () => {
    const { server, engine } = harness();

    const result = await callTool(server, "start_oauth_flow", {
      name: "a".repeat(256),
      provider: "github",
      grant_type: "authorization_code",
      client_id: "cid",
    });

    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain("-32602");
    expect(engine.createOAuthSecret).not.toHaveBeenCalled();
  });

  it("authorization_code creates the secret from the preset endpoints and defers the browser leg", async () => {
    const { server, engine } = harness();

    const result = await callTool(server, "start_oauth_flow", {
      name: "gh-app",
      provider: "github",
      grant_type: "authorization_code",
      client_id: "client-123",
    });

    expect(engine.createOAuthSecret).toHaveBeenCalledWith(
      "gh-app",
      expect.objectContaining({
        provider: "github",
        grant_type: "authorization_code",
        auth_endpoint: "https://github.com/login/oauth/authorize",
        client_id: "client-123",
      }),
      undefined,
      EXPECTED_CALLER,
    );
    expect(oauthConfigOf(engine).client_secret).toBeUndefined();

    const data = toolData(result);
    expect(data.handle).toBe("secret://gh-app");
    expect(data.status).toBe("pending_authorization");
    expect(data.message).toContain("harpoc oauth connect");
  });

  it("device_code returns the manager's auth_url and user_code without the completion promise", async () => {
    const startDeviceCode = vi.fn().mockResolvedValue({
      handle: "secret://gh-dev",
      status: "pending_authorization",
      auth_url: "https://github.com/login/device",
      user_code: "WDJB-MJHT",
      message: "Please visit https://github.com/login/device and enter code: WDJB-MJHT",
      completion: Promise.resolve(),
    });
    const { server, engine } = harness({ oauthOverrides: { startDeviceCode } });

    const result = await callTool(server, "start_oauth_flow", {
      name: "gh-dev",
      provider: "github",
      grant_type: "device_code",
      client_id: "client-123",
    });

    expect(startDeviceCode).toHaveBeenCalledWith(
      "gh-dev",
      expect.objectContaining({
        device_authorization_endpoint: "https://github.com/login/device/code",
      }),
      undefined,
      EXPECTED_CALLER,
    );
    // The manager creates the secret itself — the tool must not create a second one.
    expect(engine.createOAuthSecret).not.toHaveBeenCalled();

    const data = toolData(result);
    expect(data.handle).toBe("secret://gh-dev");
    expect(data.status).toBe("pending_authorization");
    expect(data.auth_url).toBe("https://github.com/login/device");
    expect(data.user_code).toBe("WDJB-MJHT");
    expect("completion" in data).toBe(false);
  });

  it("client_credentials without an out-of-band channel leaves a PENDING secret and skips the manager", async () => {
    const { server, engine, oauthManager } = harness();

    const result = await callTool(server, "start_oauth_flow", {
      name: "m2m",
      provider: "custom",
      grant_type: "client_credentials",
      client_id: "client-123",
      token_endpoint: "https://idp.example.com/oauth/token",
    });

    expect(engine.createOAuthSecret).toHaveBeenCalledTimes(1);
    expect(oauthManager.startClientCredentials).not.toHaveBeenCalled();

    const data = toolData(result);
    expect(data.status).toBe("pending");
    expect(data.message).toContain("harpoc oauth connect");
    expect(data.message).toContain("--client-credentials");
  });

  it("client_credentials completes with the collected secret, zeroes the bytes and returns metadata only", async () => {
    const secret = "cc-collected-secret";
    const bytes = new TextEncoder().encode(secret);
    vi.mocked(collectValueViaUrlElicitation).mockResolvedValueOnce(bytes);
    const startClientCredentials = vi
      .fn()
      .mockResolvedValue({ handle: "secret://gh", status: "authorized", message: "ok" });
    const { server, engine } = harness({ oauthOverrides: { startClientCredentials } });

    const result = await callTool(server, "start_oauth_flow", {
      name: "gh-m2m",
      provider: "github",
      grant_type: "client_credentials",
      client_id: "client-123",
    });

    // The PENDING config is written before the secret is collected.
    expect(engine.createOAuthSecret).toHaveBeenCalledTimes(1);
    expect(oauthConfigOf(engine).client_secret).toBeUndefined();

    expect(startClientCredentials).toHaveBeenCalledWith(
      "gh-m2m",
      expect.objectContaining({
        client_secret: secret,
        token_endpoint: "https://github.com/login/oauth/access_token",
      }),
      undefined,
      EXPECTED_CALLER,
    );
    expect(Array.from(bytes).every((b) => b === 0)).toBe(true);

    const data = toolData(result);
    expect(Object.keys(data).sort()).toEqual(["handle", "message", "status"]);
    expect((result.content[0] as { text: string }).text).not.toContain(secret);
  });

  it("denies a token without the create scope", async () => {
    const { server, engine, oauthManager } = harness({ scope: ["use", "read"] });

    const result = await callTool(server, "start_oauth_flow", {
      name: "gh-app",
      provider: "github",
      grant_type: "authorization_code",
      client_id: "client-123",
    });

    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain("Access denied");
    expect(engine.createOAuthSecret).not.toHaveBeenCalled();
    expect(oauthManager.startDeviceCode).not.toHaveBeenCalled();
  });
});
