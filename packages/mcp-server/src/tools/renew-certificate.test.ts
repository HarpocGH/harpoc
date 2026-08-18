import { describe, it, expect, vi } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CertManager } from "@harpoc/cert-manager";
import type { VaultEngine } from "@harpoc/core";
import type { CertificateStatus } from "@harpoc/shared";
import { RateLimiter } from "../guards/rate-limiter.js";
import { createMcpServer } from "../server.js";

function token(scope: string[]): Record<string, unknown> {
  return {
    sub: "agent",
    vault_id: "v",
    scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: "jti-1",
  };
}

const EXPECTED_CALLER = {
  principal_type: "agent",
  principal_id: "agent",
  interface: "mcp",
};

const STATUS: CertificateStatus = {
  secret_id: "uuid-123",
  subject: "CN=example.com",
  issuer: "CN=fixture-ca",
  not_before: 1_000,
  not_after: 2_000,
  auto_renew: true,
  renewal_status: "ok",
};

function mockEngine(overrides: Record<string, unknown> = {}): VaultEngine {
  return {
    listSecrets: vi.fn().mockReturnValue([]),
    getSecretInfo: vi.fn().mockResolvedValue({}),
    useSecret: vi.fn().mockResolvedValue({ status: 200, body: "" }),
    createSecret: vi
      .fn()
      .mockResolvedValue({ handle: "secret://x", status: "pending", message: "" }),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    resolveSecretId: vi
      .fn()
      .mockImplementation(async (handle: string) =>
        handle === "secret://other-cert" ? "uuid-456" : "uuid-123",
      ),
    getState: vi.fn().mockReturnValue("unlocked"),
    queryAudit: vi.fn().mockReturnValue([]),
    auditServerStart: vi.fn(),
    isTokenRevoked: vi.fn().mockReturnValue(false),
    verifyToken: vi.fn().mockReturnValue(token(["rotate"])),
    ...overrides,
  } as unknown as VaultEngine;
}

interface Harness {
  server: McpServer;
  engine: VaultEngine;
  certManager: CertManager;
}

function harness(
  options: {
    scope?: string[];
    certManagerOverrides?: Record<string, unknown>;
    rateLimiter?: RateLimiter;
  } = {},
): Harness {
  const engine = mockEngine({
    verifyToken: vi.fn().mockReturnValue(token(options.scope ?? ["rotate"])),
  });
  const certManager = {
    renewCertificate: vi.fn().mockResolvedValue(STATUS),
    ...options.certManagerOverrides,
  } as unknown as CertManager;
  const server = createMcpServer({
    engine,
    launchToken: "jwt",
    certManager,
    rateLimiter: options.rateLimiter,
  });
  return { server, engine, certManager };
}

function requestHandler<T>(server: McpServer, method: string): (req: unknown, extra: unknown) => T {
  const lowLevel = (server as unknown as { server: { _requestHandlers: Map<string, unknown> } })
    .server;
  const handler = lowLevel._requestHandlers.get(method);
  if (!handler) throw new Error(`No ${method} handler found`);
  return handler as (req: unknown, extra: unknown) => T;
}

const EXTRA = { signal: new AbortController().signal, sessionId: "test" };

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

describe("renew_certificate", () => {
  it("denies a token without the rotate scope", async () => {
    const { server, certManager } = harness({ scope: ["use", "read"] });

    const result = await callTool(server, "renew_certificate", {
      handle: "secret://my-cert",
    });

    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain("Access denied");
    expect(certManager.renewCertificate).not.toHaveBeenCalled();
  });

  it("resolves the handle and calls certManager.renewCertificate with the resolved secretId and the scope guard's caller", async () => {
    const { server, engine, certManager } = harness();

    await callTool(server, "renew_certificate", { handle: "secret://prod/my-cert" });

    expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://prod/my-cert");
    expect(certManager.renewCertificate).toHaveBeenCalledWith("uuid-123", {
      caller: EXPECTED_CALLER,
    });
  });

  // D1: the bind port is no longer an MCP-side choice, so a smuggled one is
  // dropped the way any undeclared argument is — the renewal still runs, on the
  // http-01 default port, and the manager is never told which port to try.
  it("drops a smuggled http_port rather than refusing it, and never forwards it to the manager", async () => {
    const { server, certManager } = harness();

    const result = await callTool(server, "renew_certificate", {
      handle: "secret://my-cert",
      http_port: 8080,
    });

    expect(result.isError ?? false).toBe(false);
    expect(certManager.renewCertificate).toHaveBeenCalledWith("uuid-123", {
      caller: EXPECTED_CALLER,
    });
  });

  it("result JSON keys are exactly the CertificateStatus fields — no PEM, no key", async () => {
    const { server } = harness();

    const result = await callTool(server, "renew_certificate", {
      handle: "secret://my-cert",
    });

    const data = toolData(result);
    expect(Object.keys(data).sort()).toEqual([
      "auto_renew",
      "issuer",
      "not_after",
      "not_before",
      "renewal_status",
      "secret_id",
      "subject",
    ]);
    expect(data).toEqual(STATUS);
  });

  it("charges the per-secret rate limit tier, keyed by the resolved secretId — a different secret still proceeds", async () => {
    const limiter = new RateLimiter(10_000, 1);
    const { server, certManager } = harness({ rateLimiter: limiter });

    const first = await callTool(server, "renew_certificate", { handle: "secret://my-cert" });
    expect(first.isError ?? false).toBe(false);

    const second = await callTool(server, "renew_certificate", { handle: "secret://my-cert" });
    expect(second.isError).toBe(true);
    expect((second.content[0] as { text: string }).text).toContain("rate limit");

    const otherSecret = await callTool(server, "renew_certificate", {
      handle: "secret://other-cert",
    });
    expect(otherSecret.isError ?? false).toBe(false);
    expect(certManager.renewCertificate).toHaveBeenLastCalledWith(
      "uuid-456",
      expect.objectContaining({}),
    );
  });

  it("a certManager throw surfaces as an error result, not a crash", async () => {
    const renewCertificate = vi
      .fn()
      .mockRejectedValue(new Error("no ACME account for this certificate"));
    const { server } = harness({ certManagerOverrides: { renewCertificate } });

    const result = await callTool(server, "renew_certificate", { handle: "secret://my-cert" });

    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain(
      "no ACME account for this certificate",
    );
  });
});
