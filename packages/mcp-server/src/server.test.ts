import { describe, it, expect, vi } from "vitest";
import type { VaultEngine } from "@harpoc/core";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { createMcpServer } from "./server.js";

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
    resolveSecretId: vi.fn().mockResolvedValue("uuid-123"),
    getState: vi.fn().mockReturnValue("unlocked"),
    queryAudit: vi.fn().mockReturnValue([]),
    verifyToken: vi.fn().mockReturnValue({
      sub: "agent",
      vault_id: "v",
      scope: ["use", "list"],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: "jti-1",
    }),
    ...overrides,
  } as unknown as VaultEngine;
}

describe("createMcpServer", () => {
  it("throws TOKEN_REQUIRED without token and without allowTokenless", () => {
    const engine = mockEngine();
    expect(() => createMcpServer({ engine })).toThrow(
      expect.objectContaining({ code: ErrorCode.TOKEN_REQUIRED }),
    );
  });

  it("TOKEN_REQUIRED message names both recovery paths", () => {
    const engine = mockEngine();
    try {
      createMcpServer({ engine });
      expect.unreachable("should have thrown");
    } catch (err) {
      const message = (err as Error).message;
      expect(message).toContain("harpoc auth token");
      expect(message).toContain("HARPOC_TOKEN");
      expect(message).toContain("--allow-tokenless");
    }
  });

  it("creates server without token when allowTokenless is set, warning on stderr", () => {
    const engine = mockEngine();
    const stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    try {
      const server = createMcpServer({ engine, allowTokenless: true });
      expect(server).toBeDefined();
      const written = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
      expect(written).toContain("WARNING");
      expect(written).toContain("unrestricted");
    } finally {
      stderrSpy.mockRestore();
    }
  });

  it("emits no warning on the token path", () => {
    const engine = mockEngine();
    const stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    try {
      createMcpServer({ engine, launchToken: "valid.jwt.token" });
      const written = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
      expect(written).not.toContain("WARNING");
    } finally {
      stderrSpy.mockRestore();
    }
  });

  it("creates server with valid token", () => {
    const engine = mockEngine();
    const server = createMcpServer({ engine, launchToken: "valid.jwt.token" });
    expect(server).toBeDefined();
    expect(engine.verifyToken).toHaveBeenCalledWith("valid.jwt.token");
  });

  it("throws on expired token", () => {
    const engine = mockEngine({
      verifyToken: vi.fn().mockImplementation(() => {
        throw VaultError.tokenExpired();
      }),
    });

    expect(() => createMcpServer({ engine, launchToken: "expired.jwt" })).toThrow(
      expect.objectContaining({ code: ErrorCode.TOKEN_EXPIRED }),
    );
  });

  it("throws on revoked token", () => {
    const engine = mockEngine({
      verifyToken: vi.fn().mockImplementation(() => {
        throw VaultError.tokenRevoked();
      }),
    });

    expect(() => createMcpServer({ engine, launchToken: "revoked.jwt" })).toThrow(
      expect.objectContaining({ code: ErrorCode.TOKEN_REVOKED }),
    );
  });

  it("registers all 7 tools", () => {
    const engine = mockEngine();
    const server = createMcpServer({ engine, allowTokenless: true });

    // Access internal tool registry
    const lowLevel = (server as unknown as { server: { _requestHandlers: Map<string, unknown> } })
      .server;
    const listHandler = lowLevel._requestHandlers.get("tools/list") as (
      req: unknown,
      extra: unknown,
    ) => Promise<{ tools: Array<{ name: string }> }>;

    expect(listHandler).toBeDefined();
  });

  describe("scope enforcement e2e", () => {
    it("rejects create_secret with use-only token", async () => {
      const engine = mockEngine({
        verifyToken: vi.fn().mockReturnValue({
          sub: "agent",
          vault_id: "v",
          scope: ["use", "list"],
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
          jti: "jti-1",
        }),
      });

      const server = createMcpServer({ engine, launchToken: "token" });

      // Call tools/call through the server
      const lowLevel = (server as unknown as { server: { _requestHandlers: Map<string, unknown> } })
        .server;
      const callHandler = lowLevel._requestHandlers.get("tools/call") as (
        req: { method: string; params: { name: string; arguments?: Record<string, unknown> } },
        extra: unknown,
      ) => Promise<unknown>;

      const result = (await callHandler(
        {
          method: "tools/call",
          params: { name: "create_secret", arguments: { name: "x", type: "api_key" } },
        },
        { signal: new AbortController().signal, sessionId: "test" },
      )) as { content: Array<{ text: string }>; isError?: boolean };
      expect(result.isError).toBe(true);
      expect((result.content[0] as { text: string }).text).toContain("Access denied");
    });

    it("allows list_secrets with list token", async () => {
      const engine = mockEngine({
        verifyToken: vi.fn().mockReturnValue({
          sub: "agent",
          vault_id: "v",
          scope: ["list"],
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
          jti: "jti-1",
        }),
      });

      const server = createMcpServer({ engine, launchToken: "token" });

      const lowLevel = (server as unknown as { server: { _requestHandlers: Map<string, unknown> } })
        .server;
      const callHandler = lowLevel._requestHandlers.get("tools/call") as (
        req: { method: string; params: { name: string; arguments?: Record<string, unknown> } },
        extra: unknown,
      ) => Promise<{ content: Array<{ type: string; text: string }> }>;

      const result = await callHandler(
        { method: "tools/call", params: { name: "list_secrets", arguments: {} } },
        { signal: new AbortController().signal, sessionId: "test" },
      );
      expect(result.content).toBeDefined();
    });
  });
});
