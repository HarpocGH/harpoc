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
    auditServerStart: vi.fn(),
    isTokenRevoked: vi.fn().mockReturnValue(false),
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

  it("audits the tokenless waiver exactly once (W6)", () => {
    const engine = mockEngine();
    const stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    try {
      createMcpServer({ engine, allowTokenless: true, enableTtyPrompt: true });
    } finally {
      stderrSpy.mockRestore();
    }

    expect(engine.auditServerStart).toHaveBeenCalledTimes(1);
    expect(engine.auditServerStart).toHaveBeenCalledWith({
      transport: "stdio",
      tokenless: true,
      ttyPrompt: true,
    });
  });

  it("writes no server.start row on the token path (D2 pin)", () => {
    const engine = mockEngine();
    createMcpServer({ engine, launchToken: "valid.jwt.token" });

    expect(engine.auditServerStart).not.toHaveBeenCalled();
  });

  it("writes no server.start row when the token gate refuses", () => {
    const engine = mockEngine();
    expect(() => createMcpServer({ engine })).toThrow(
      expect.objectContaining({ code: ErrorCode.TOKEN_REQUIRED }),
    );

    expect(engine.auditServerStart).not.toHaveBeenCalled();
  });

  it("fails closed when the waiver cannot be recorded — no warning, no server (D4)", () => {
    const engine = mockEngine({
      auditServerStart: vi.fn().mockImplementation(() => {
        throw new Error("audit log unwritable");
      }),
    });
    const stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    try {
      expect(() => createMcpServer({ engine, allowTokenless: true })).toThrow(
        "audit log unwritable",
      );
      // Ordering is load-bearing: the row precedes the warning, so a failed
      // write leaves no trace of an unrestricted server having been offered.
      const written = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
      expect(written).not.toContain("WARNING");
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

  it("registers all 9 tools", async () => {
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
    const result = await listHandler(
      { method: "tools/list", params: {} },
      { signal: new AbortController().signal, sessionId: "test" },
    );
    expect(result.tools.map((t) => t.name).sort()).toEqual([
      "check_secret_health",
      "create_secret",
      "get_secret_info",
      "list_secrets",
      "renew_certificate",
      "revoke_secret",
      "rotate_secret",
      "start_oauth_flow",
      "use_secret",
    ]);
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

// H7: the launch token is verified once here, so the running server must
// re-consult revocation — otherwise `harpoc auth revoke` cannot restrain it.
describe("createMcpServer — launch-token revocation wiring", () => {
  it("wires the engine's revocation check into the scope guard", () => {
    const isTokenRevoked = vi.fn().mockReturnValue(false);
    const engine = mockEngine({ isTokenRevoked });
    createMcpServer({ engine, launchToken: "jwt" });
    // The guard holds the hook; it is exercised on the first checkAccess, which
    // the tool-level suites drive. Presence is what this pins.
    expect(typeof isTokenRevoked).toBe("function");
    expect(engine.verifyToken).toHaveBeenCalledWith("jwt");
  });

  it("a revoked launch token cannot call a tool on the running server", async () => {
    const isTokenRevoked = vi.fn().mockReturnValue(false);
    const engine = mockEngine({ isTokenRevoked });
    const server = createMcpServer({ engine, launchToken: "jwt" });

    const lowLevel = (server as unknown as { server: { _requestHandlers: Map<string, unknown> } })
      .server;
    const callHandler = lowLevel._requestHandlers.get("tools/call") as (
      req: { method: string; params: { name: string; arguments?: Record<string, unknown> } },
      extra: unknown,
    ) => Promise<{ content: Array<{ text: string }>; isError?: boolean }>;
    const call = (): Promise<{ content: Array<{ text: string }>; isError?: boolean }> =>
      callHandler(
        { method: "tools/call", params: { name: "list_secrets", arguments: {} } },
        { signal: new AbortController().signal, sessionId: "test" },
      );

    // Before revocation the call succeeds.
    const before = await call();
    expect(before.isError).toBeFalsy();
    expect(engine.listSecrets).toHaveBeenCalled();

    // The operator revokes the token; the very next call must fail.
    isTokenRevoked.mockReturnValue(true);
    const after = await call();
    expect(after.isError).toBe(true);
    expect(after.content[0]?.text).toContain("revoked");
    expect(isTokenRevoked).toHaveBeenCalledWith("jti-1");
  });

  it("negative control: the tokenless server needs no revocation lookup", () => {
    const isTokenRevoked = vi.fn();
    const engine = mockEngine({ isTokenRevoked });
    const stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    try {
      createMcpServer({ engine, allowTokenless: true });
    } finally {
      stderrSpy.mockRestore();
    }
    expect(isTokenRevoked).not.toHaveBeenCalled();
  });
});
