import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from "vitest";

// ── Hoisted mocks (available inside vi.mock factories) ─────────────

const {
  mockEngine,
  mockMcpServer,
  mockMcpHttpServer,
  mockTransport,
  mockRestServer,
  mockRestOAuthManager,
  mockScheduler,
  schedulerCtorCalls,
  mockCertManager,
  certManagerCtorCalls,
  mockRenewalScheduler,
  renewalSchedulerCtorCalls,
} = vi.hoisted(() => ({
  mockEngine: {
    destroy: vi.fn().mockResolvedValue(undefined),
    createToken: vi.fn().mockReturnValue("mock-launch-jwt"),
  },
  mockMcpServer: {
    connect: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
  },
  mockMcpHttpServer: {
    port: 3001,
    endpoint: "/mcp",
    close: vi.fn().mockResolvedValue(undefined),
  },
  mockTransport: {},
  mockRestServer: {
    close: vi.fn(),
  },
  mockRestOAuthManager: {
    cancelPendingFlows: vi.fn(),
  },
  mockScheduler: {
    start: vi.fn(),
    stop: vi.fn(),
  },
  schedulerCtorCalls: [] as { engine: unknown; options: Record<string, unknown> }[],
  mockCertManager: {
    renewCertificate: vi.fn().mockResolvedValue(undefined),
  },
  certManagerCtorCalls: [] as { engine: unknown }[],
  mockRenewalScheduler: {
    start: vi.fn(),
    stop: vi.fn(),
  },
  renewalSchedulerCtorCalls: [] as {
    engine: unknown;
    renewer: unknown;
    options: Record<string, unknown>;
  }[],
}));

// ── Module mocks ───────────────────────────────────────────────────

vi.mock("../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

vi.mock("@harpoc/mcp-server", () => ({
  createMcpServer: vi.fn().mockReturnValue(mockMcpServer),
  startMcpHttpServer: vi.fn().mockResolvedValue(mockMcpHttpServer),
}));

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn().mockReturnValue(mockTransport),
}));

vi.mock("@harpoc/rest-api", () => ({
  startServer: vi.fn().mockReturnValue(mockRestServer),
  createDefaultOAuthManager: vi.fn().mockReturnValue(mockRestOAuthManager),
}));

vi.mock("@harpoc/oauth-proxy", () => ({
  TokenRefreshScheduler: vi.fn().mockImplementation((engine: unknown, options: unknown) => {
    schedulerCtorCalls.push({ engine, options: options as Record<string, unknown> });
    return mockScheduler;
  }),
}));

vi.mock("@harpoc/cert-manager", () => ({
  CertManager: vi.fn().mockImplementation((engine: unknown) => {
    certManagerCtorCalls.push({ engine });
    return mockCertManager;
  }),
  RenewalScheduler: vi
    .fn()
    .mockImplementation((engine: unknown, renewer: unknown, options: unknown) => {
      renewalSchedulerCtorCalls.push({
        engine,
        renewer,
        options: options as Record<string, unknown>,
      });
      return mockRenewalScheduler;
    }),
}));

// ── Helpers ────────────────────────────────────────────────────────

import { Command } from "commander";
import { registerServerCommand } from "./server.js";

function buildProgram(): Command {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  registerServerCommand(program);
  return program;
}

async function run(args: string[]): Promise<void> {
  const program = buildProgram();
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "server", "start", ...args]);
}

// ── Tests ──────────────────────────────────────────────────────────

describe("server start", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let priorSigintListeners: NodeJS.SignalsListener[];
  let priorSigtermListeners: NodeJS.SignalsListener[];

  beforeEach(() => {
    vi.clearAllMocks();
    schedulerCtorCalls.length = 0;
    certManagerCtorCalls.length = 0;
    renewalSchedulerCtorCalls.length = 0;
    priorSigintListeners = process.listeners("SIGINT");
    priorSigtermListeners = process.listeners("SIGTERM");
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    // Each run() registers shutdown handlers on the real process; drop only
    // the ones this test added so they don't accumulate across the suite.
    for (const listener of process.listeners("SIGINT")) {
      if (!priorSigintListeners.includes(listener)) process.removeListener("SIGINT", listener);
    }
    for (const listener of process.listeners("SIGTERM")) {
      if (!priorSigtermListeners.includes(listener)) process.removeListener("SIGTERM", listener);
    }
    exitSpy.mockRestore();
    errorSpy.mockRestore();
  });

  // ── Validation errors ───────────────────────────────────────────

  it("exits with error when no server flag is provided", async () => {
    await expect(run([])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(
      "Error: At least one of --mcp, --mcp-http, --rest, --oauth-refresh or --cert-renew is required.",
    );
  });

  it("exits with error for non-numeric port", async () => {
    await expect(run(["--rest", "--port", "abc"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid port"));
  });

  it("exits with error for port out of range", async () => {
    await expect(run(["--rest", "--port", "99999"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid port"));
  });

  it("exits with error for port 0", async () => {
    await expect(run(["--rest", "--port", "0"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid port"));
  });

  it("exits with error when --token is used without --mcp", async () => {
    await expect(run(["--rest", "--token", "jwt"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--token requires --mcp"));
  });

  it("exits with error when --token is used with --mcp-http only", async () => {
    await expect(run(["--mcp-http", "--token", "jwt"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--token requires --mcp"));
  });

  it("exits with error when --allow-tokenless is used without --mcp", async () => {
    await expect(run(["--rest", "--allow-tokenless"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--allow-tokenless requires --mcp"),
    );
  });

  it("exits with error when --allow-tokenless is combined with --token", async () => {
    const { createMcpServer } = await import("@harpoc/mcp-server");

    await expect(run(["--mcp", "--allow-tokenless", "--token", "jwt"])).rejects.toThrow(
      "process.exit",
    );
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--allow-tokenless conflicts with a launch token"),
    );
    expect(createMcpServer).not.toHaveBeenCalled();
  });

  it("exits with error for an invalid --mcp-http-port", async () => {
    await expect(run(["--mcp-http", "--mcp-http-port", "abc"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid MCP HTTP port"));
  });

  it("exits with error when REST and MCP HTTP ports collide", async () => {
    await expect(
      run(["--rest", "--mcp-http", "--port", "4000", "--mcp-http-port", "4000"]),
    ).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("must differ"));
  });

  // ── MCP mode ────────────────────────────────────────────────────

  it("starts MCP server with --mcp", async () => {
    const { createMcpServer } = await import("@harpoc/mcp-server");
    const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");

    await run(["--mcp"]);

    expect(createMcpServer).toHaveBeenCalledWith({
      engine: mockEngine,
      launchToken: undefined,
      allowTokenless: undefined,
      enableTtyPrompt: true,
    });
    expect(StdioServerTransport).toHaveBeenCalled();
    expect(mockMcpServer.connect).toHaveBeenCalledWith(mockTransport);
  });

  it("passes allowTokenless with --mcp --allow-tokenless", async () => {
    const { createMcpServer } = await import("@harpoc/mcp-server");

    await run(["--mcp", "--allow-tokenless"]);

    expect(createMcpServer).toHaveBeenCalledWith({
      engine: mockEngine,
      launchToken: undefined,
      allowTokenless: true,
      enableTtyPrompt: true,
    });
  });

  it("a TOKEN_REQUIRED throw from createMcpServer exits 1 with the guidance", async () => {
    const { createMcpServer } = await import("@harpoc/mcp-server");
    const { VaultError } = await import("@harpoc/shared");
    (createMcpServer as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
      throw VaultError.tokenRequired();
    });

    await expect(run(["--mcp"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--allow-tokenless"));
    expect(mockEngine.destroy).toHaveBeenCalled();
  });

  it("passes launch token to MCP server with --mcp --token", async () => {
    const { createMcpServer } = await import("@harpoc/mcp-server");

    await run(["--mcp", "--token", "my.jwt.token"]);

    expect(createMcpServer).toHaveBeenCalledWith({
      engine: mockEngine,
      launchToken: "my.jwt.token",
      enableTtyPrompt: true,
    });
  });

  // ── HARPOC_TOKEN environment variable ───────────────────────────

  describe("HARPOC_TOKEN environment variable", () => {
    const savedEnv = process.env.HARPOC_TOKEN;

    beforeEach(() => {
      delete process.env.HARPOC_TOKEN;
    });

    afterEach(() => {
      if (savedEnv === undefined) {
        delete process.env.HARPOC_TOKEN;
      } else {
        process.env.HARPOC_TOKEN = savedEnv;
      }
    });

    it("resolves the launch token from HARPOC_TOKEN with --mcp", async () => {
      const { createMcpServer } = await import("@harpoc/mcp-server");
      process.env.HARPOC_TOKEN = "env.jwt.token";

      await run(["--mcp"]);

      expect(createMcpServer).toHaveBeenCalledWith({
        engine: mockEngine,
        launchToken: "env.jwt.token",
        enableTtyPrompt: true,
      });
    });

    it("an explicit --token wins over HARPOC_TOKEN", async () => {
      const { createMcpServer } = await import("@harpoc/mcp-server");
      process.env.HARPOC_TOKEN = "env.jwt.token";

      await run(["--mcp", "--token", "flag.jwt.token"]);

      expect(createMcpServer).toHaveBeenCalledWith({
        engine: mockEngine,
        launchToken: "flag.jwt.token",
        enableTtyPrompt: true,
      });
    });

    it("exits with error when --allow-tokenless meets an ambient HARPOC_TOKEN", async () => {
      const { createMcpServer } = await import("@harpoc/mcp-server");
      process.env.HARPOC_TOKEN = "env.jwt.token";

      await expect(run(["--mcp", "--allow-tokenless"])).rejects.toThrow("process.exit");
      expect(exitSpy).toHaveBeenCalledWith(1);
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--allow-tokenless conflicts with a launch token"),
      );
      expect(createMcpServer).not.toHaveBeenCalled();
    });

    it("an ambient HARPOC_TOKEN without --mcp is ignored, not an error", async () => {
      const { createMcpServer } = await import("@harpoc/mcp-server");
      const { startServer } = await import("@harpoc/rest-api");
      process.env.HARPOC_TOKEN = "env.jwt.token";

      await run(["--rest"]);

      expect(startServer).toHaveBeenCalled();
      expect(createMcpServer).not.toHaveBeenCalled();
      expect(exitSpy).not.toHaveBeenCalled();
    });
  });

  // ── MCP Streamable HTTP mode ────────────────────────────────────

  it("starts MCP Streamable HTTP server with --mcp-http", async () => {
    const { startMcpHttpServer } = await import("@harpoc/mcp-server");

    await run(["--mcp-http"]);

    expect(startMcpHttpServer).toHaveBeenCalledWith({ engine: mockEngine, port: 3001 });
  });

  it("starts MCP Streamable HTTP server with custom port", async () => {
    const { startMcpHttpServer } = await import("@harpoc/mcp-server");

    await run(["--mcp-http", "--mcp-http-port", "8090"]);

    expect(startMcpHttpServer).toHaveBeenCalledWith({ engine: mockEngine, port: 8090 });
  });

  it("starts stdio and Streamable HTTP MCP servers together", async () => {
    const { createMcpServer, startMcpHttpServer } = await import("@harpoc/mcp-server");
    const originalLog = console.log;

    await run(["--mcp", "--mcp-http"]);

    expect(createMcpServer).toHaveBeenCalled();
    expect(startMcpHttpServer).toHaveBeenCalled();

    console.log = originalLog;
  });

  // ── REST mode ───────────────────────────────────────────────────

  it("starts REST server with --rest", async () => {
    const { startServer } = await import("@harpoc/rest-api");

    await run(["--rest"]);

    expect(startServer).toHaveBeenCalledWith({
      engine: mockEngine,
      port: 3000,
      hostname: "127.0.0.1",
      oauthManager: mockRestOAuthManager,
    });
  });

  it("starts REST server with custom port", async () => {
    const { startServer } = await import("@harpoc/rest-api");

    await run(["--rest", "--port", "8080"]);

    expect(startServer).toHaveBeenCalledWith({
      engine: mockEngine,
      port: 8080,
      hostname: "127.0.0.1",
      oauthManager: mockRestOAuthManager,
    });
  });

  it("starts REST server with custom bind address", async () => {
    const { startServer } = await import("@harpoc/rest-api");

    await run(["--rest", "--host", "0.0.0.0"]);

    expect(startServer).toHaveBeenCalledWith({
      engine: mockEngine,
      port: 3000,
      hostname: "0.0.0.0",
      oauthManager: mockRestOAuthManager,
    });
  });

  it("constructs the REST OAuth manager through the rest-api factory", async () => {
    const { createDefaultOAuthManager } = await import("@harpoc/rest-api");

    await run(["--rest"]);

    // The owner of the app's background flows must be the CLI, not createApp:
    // an internally-constructed manager has no dispose path on shutdown (D4).
    expect(createDefaultOAuthManager).toHaveBeenCalledTimes(1);
    expect(createDefaultOAuthManager).toHaveBeenCalledWith(mockEngine);
  });

  it("does not construct a REST OAuth manager without --rest (negative control)", async () => {
    const { createDefaultOAuthManager } = await import("@harpoc/rest-api");

    await run(["--mcp-http"]);

    expect(createDefaultOAuthManager).not.toHaveBeenCalled();
  });

  it("SIGINT shutdown cancels pending OAuth flows before destroying the engine", async () => {
    const onSpy = vi.spyOn(process, "on");
    exitSpy.mockImplementation(() => undefined as never);

    await run(["--rest"]);

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    expect(sigintCall).toBeDefined();
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => {
      expect(exitSpy).toHaveBeenCalledWith(0);
    });
    // A pending authorization-code flow pins a loopback listener and a 5-minute
    // timer, and completes against the store — abort it before the store closes.
    expect(mockRestOAuthManager.cancelPendingFlows).toHaveBeenCalledTimes(1);
    const cancelOrder = mockRestOAuthManager.cancelPendingFlows.mock
      .invocationCallOrder[0] as number;
    const destroyOrder = mockEngine.destroy.mock.invocationCallOrder[0] as number;
    expect(cancelOrder).toBeLessThan(destroyOrder);

    onSpy.mockRestore();
  });

  it("shutdown without --rest cancels nothing (negative control)", async () => {
    const onSpy = vi.spyOn(process, "on");
    exitSpy.mockImplementation(() => undefined as never);

    await run(["--mcp"]);
    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(0));
    expect(mockRestOAuthManager.cancelPendingFlows).not.toHaveBeenCalled();

    onSpy.mockRestore();
  });

  // ── Web UI ──────────────────────────────────────────────────────

  it("--ui requires --rest", async () => {
    await expect(run(["--ui"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith("Error: --ui requires --rest.");
  });

  it("--rest --ui passes uiDir to startServer, mints the launch token, prints the URL", async () => {
    await run(["--rest", "--ui"]);
    const { startServer } = await import("@harpoc/rest-api");
    const call = (startServer as unknown as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as {
      uiDir?: string;
    };
    expect(call.uiDir).toMatch(/web-ui[\\/]dist$/);
    expect(mockEngine.createToken).toHaveBeenCalledWith("web-ui", ["admin"], 24 * 60 * 60 * 1000, {
      principalType: "user",
      label: "web-ui launch",
    });
    expect(errorSpy).toHaveBeenCalledWith(
      "[harpoc] Web UI: http://127.0.0.1:3000/ui#token=mock-launch-jwt",
    );
  });

  it("--rest without --ui passes no uiDir and mints no token", async () => {
    await run(["--rest"]);
    const { startServer } = await import("@harpoc/rest-api");
    const call = (startServer as unknown as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as {
      uiDir?: string;
    };
    expect(call.uiDir).toBeUndefined();
    expect(mockEngine.createToken).not.toHaveBeenCalled();
  });

  it("--ui-token-ttl requires --ui", async () => {
    await expect(run(["--rest", "--ui-token-ttl", "10"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith("Error: --ui-token-ttl requires --ui.");
  });

  it("--ui-token-ttl refuses a non-integer value", async () => {
    await expect(run(["--rest", "--ui", "--ui-token-ttl", "ten"])).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(
      "Error: --ui-token-ttl must be a whole number of minutes (>= 1).",
    );
  });

  it("--ui-token-ttl refuses a value over the 24 h cap — never clamps", async () => {
    await expect(run(["--rest", "--ui", "--ui-token-ttl", "1441"])).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(
      "Error: --ui-token-ttl exceeds the 24 h token cap (1440).",
    );
    expect(mockEngine.createToken).not.toHaveBeenCalled();
  });

  it("--ui-token-ttl mints the launch token with the shortened TTL", async () => {
    await run(["--rest", "--ui", "--ui-token-ttl", "30"]);
    expect(mockEngine.createToken).toHaveBeenCalledWith("web-ui", ["admin"], 30 * 60 * 1000, {
      principalType: "user",
      label: "web-ui launch",
    });
  });

  it.each(["0x10", "1e2", " 5 ", "5.0"])(
    "--ui-token-ttl refuses the non-decimal form %j",
    async (value: string) => {
      await expect(run(["--rest", "--ui", "--ui-token-ttl", value])).rejects.toThrow(
        "process.exit",
      );
      expect(errorSpy).toHaveBeenCalledWith(
        "Error: --ui-token-ttl must be a whole number of minutes (>= 1).",
      );
      expect(mockEngine.createToken).not.toHaveBeenCalled();
    },
  );

  it("--port refuses a hex form", async () => {
    await expect(run(["--rest", "--port", "0x1f90"])).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith('Error: Invalid port "0x1f90". Must be 1-65535.');
  });

  it("--ui-token-ttl 1440 is accepted — the boundary equals the 24 h cap", async () => {
    await run(["--rest", "--ui", "--ui-token-ttl", "1440"]);
    expect(mockEngine.createToken).toHaveBeenCalledWith("web-ui", ["admin"], 1440 * 60_000, {
      principalType: "user",
      label: "web-ui launch",
    });
  });

  it("--ui-token-ttl 1 is accepted at the low boundary", async () => {
    await run(["--rest", "--ui", "--ui-token-ttl", "1"]);
    expect(mockEngine.createToken).toHaveBeenCalledWith("web-ui", ["admin"], 60_000, {
      principalType: "user",
      label: "web-ui launch",
    });
  });

  it("--ui-token-ttl 0 is refused", async () => {
    await expect(run(["--rest", "--ui", "--ui-token-ttl", "0"])).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(
      "Error: --ui-token-ttl must be a whole number of minutes (>= 1).",
    );
    expect(mockEngine.createToken).not.toHaveBeenCalled();
  });

  it("the launch warning names the 24 h cap when the flag is absent", async () => {
    await run(["--rest", "--ui"]);
    expect(errorSpy).toHaveBeenCalledWith(
      "[harpoc] The link grants admin access until the token expires (24 h cap). Do not share it.",
    );
  });

  it("the launch warning names the actual validity under --ui-token-ttl", async () => {
    await run(["--rest", "--ui", "--ui-token-ttl", "30"]);
    expect(errorSpy).toHaveBeenCalledWith(
      "[harpoc] The link grants admin access until the token expires (30 min). Do not share it.",
    );
  });

  // ── Dual mode ───────────────────────────────────────────────────

  it("starts both MCP and REST with --mcp --rest", async () => {
    const { createMcpServer } = await import("@harpoc/mcp-server");
    const { startServer } = await import("@harpoc/rest-api");

    await run(["--mcp", "--rest"]);

    expect(createMcpServer).toHaveBeenCalled();
    expect(startServer).toHaveBeenCalled();
  });

  it("redirects console.log to stderr in dual mode", async () => {
    const originalLog = console.log;
    await run(["--mcp", "--rest"]);

    // After dual-mode init, console.log should be console.error
    expect(console.log).toBe(console.error);

    // Restore for other tests
    console.log = originalLog;
  });

  // ── OAuth refresh scheduler ─────────────────────────────────────

  it("--oauth-refresh alone is a valid start mode and starts the scheduler", async () => {
    const { TokenRefreshScheduler } = await import("@harpoc/oauth-proxy");

    await run(["--oauth-refresh"]);

    expect(TokenRefreshScheduler).toHaveBeenCalledTimes(1);
    expect(schedulerCtorCalls[0]?.engine).toBe(mockEngine);
    expect(mockScheduler.start).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("OAuth token refresh scheduler running"),
    );
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("--rest --oauth-refresh starts both", async () => {
    const { startServer } = await import("@harpoc/rest-api");

    await run(["--rest", "--oauth-refresh"]);

    expect(startServer).toHaveBeenCalled();
    expect(mockScheduler.start).toHaveBeenCalledTimes(1);
  });

  it("--rest alone does not construct a scheduler (negative control)", async () => {
    const { TokenRefreshScheduler } = await import("@harpoc/oauth-proxy");

    await run(["--rest"]);

    expect(TokenRefreshScheduler).not.toHaveBeenCalled();
    expect(mockScheduler.start).not.toHaveBeenCalled();
  });

  it("onRefreshError prints a Warning: line to stderr", async () => {
    await run(["--oauth-refresh"]);

    const options = schedulerCtorCalls[0]?.options as {
      onRefreshError: (secretId: string, err: unknown) => void;
    };
    options.onRefreshError("secret-1", new Error("provider offline"));

    expect(errorSpy).toHaveBeenCalledWith(
      "Warning: OAuth token refresh failed (secret-1): provider offline",
    );
  });

  it("onRefreshError is suppressed once shutdown began (review T6)", async () => {
    const onSpy = vi.spyOn(process, "on");
    exitSpy.mockImplementation(() => undefined as never);

    await run(["--oauth-refresh"]);
    const options = schedulerCtorCalls[0]?.options as {
      onRefreshError: (secretId: string, err: unknown) => void;
    };

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    (sigintCall?.[1] as () => void)();
    await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(0));

    errorSpy.mockClear();
    // A drain-window failure (e.g. vaultLocked racing the teardown) must not
    // print a spurious warning while the process is already exiting.
    options.onRefreshError("secret-1", new Error("vault locked"));
    expect(errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("Warning:"));

    onSpy.mockRestore();
  });

  it("SIGINT shutdown stops the scheduler before destroying the engine", async () => {
    const onSpy = vi.spyOn(process, "on");
    exitSpy.mockImplementation(() => undefined as never);

    await run(["--oauth-refresh"]);

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    expect(sigintCall).toBeDefined();
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => {
      expect(exitSpy).toHaveBeenCalledWith(0);
    });
    expect(mockScheduler.stop).toHaveBeenCalledTimes(1);
    const stopOrder = mockScheduler.stop.mock.invocationCallOrder[0] as number;
    const destroyOrder = mockEngine.destroy.mock.invocationCallOrder[0] as number;
    expect(stopOrder).toBeLessThan(destroyOrder);

    onSpy.mockRestore();
  });

  it("shutdown awaits the scheduler drain before destroying the engine (review fix F2)", async () => {
    const onSpy = vi.spyOn(process, "on");
    exitSpy.mockImplementation(() => undefined as never);
    let releaseDrain: () => void = () => {};
    mockScheduler.stop.mockReturnValueOnce(
      new Promise<void>((resolve) => {
        releaseDrain = resolve;
      }),
    );

    await run(["--oauth-refresh"]);
    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => expect(mockScheduler.stop).toHaveBeenCalled());
    await new Promise((resolve) => setTimeout(resolve, 20));
    // The store must stay open while a rotated token may still arrive —
    // pre-fix, shutdown fired stop() without awaiting the drain.
    expect(mockEngine.destroy).not.toHaveBeenCalled();

    releaseDrain();
    await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(0));
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);

    onSpy.mockRestore();
  });

  it("combined --oauth-refresh --rest: refresh drain precedes restServer.close", async () => {
    const onSpy = vi.spyOn(process, "on");
    exitSpy.mockImplementation(() => undefined as never);

    await run(["--oauth-refresh", "--rest"]);

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    expect(sigintCall).toBeDefined();
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => {
      expect(exitSpy).toHaveBeenCalledWith(0);
    });
    expect(mockScheduler.stop).toHaveBeenCalledTimes(1);
    expect(mockRestServer.close).toHaveBeenCalledTimes(1);
    // Tripwire on the drain's direction of travel: the stop < destroy pins
    // above stay green while the drain slides down the teardown sequence.
    const stopOrder = mockScheduler.stop.mock.invocationCallOrder[0] as number;
    const closeOrder = mockRestServer.close.mock.invocationCallOrder[0] as number;
    expect(stopOrder).toBeLessThan(closeOrder);

    onSpy.mockRestore();
  });

  // ── Certificate renewal scheduler ───────────────────────────────

  it("--cert-renew alone is a valid start mode and starts the scheduler", async () => {
    const { CertManager, RenewalScheduler } = await import("@harpoc/cert-manager");

    await run(["--cert-renew"]);

    expect(exitSpy).not.toHaveBeenCalled();
    expect(CertManager).toHaveBeenCalledTimes(1);
    expect(certManagerCtorCalls[0]?.engine).toBe(mockEngine);
    expect(RenewalScheduler).toHaveBeenCalledTimes(1);
    expect(renewalSchedulerCtorCalls[0]?.engine).toBe(mockEngine);
    expect(mockRenewalScheduler.start).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("certificate renewal scheduler running"),
    );
    // The first check fires one interval after start, not at start — the
    // startup line has to say so, or an operator reads silence as failure.
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("first check in ~1 h"));
  });

  it("threads the default httpPort 80 into renewCertificate", async () => {
    await run(["--cert-renew"]);

    const renewer = renewalSchedulerCtorCalls[0]?.renewer as {
      renewCertificate: (secretId: string) => Promise<unknown>;
    };
    await renewer.renewCertificate("sid-1");

    expect(mockCertManager.renewCertificate).toHaveBeenCalledWith("sid-1", { httpPort: 80 });
  });

  it("--cert-renew-port 8080 threads httpPort 8080 into renewCertificate", async () => {
    await run(["--cert-renew", "--cert-renew-port", "8080"]);

    const renewer = renewalSchedulerCtorCalls[0]?.renewer as {
      renewCertificate: (secretId: string) => Promise<unknown>;
    };
    await renewer.renewCertificate("sid-1");

    expect(mockCertManager.renewCertificate).toHaveBeenCalledWith("sid-1", { httpPort: 8080 });
  });

  it("exits with error when --cert-renew-port is given without --cert-renew", async () => {
    await expect(run(["--rest", "--cert-renew-port", "8080"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--cert-renew-port requires --cert-renew"),
    );
  });

  it("exits with error for an invalid --cert-renew-port before loading the vault", async () => {
    const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

    await expect(run(["--cert-renew", "--cert-renew-port", "abc"])).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(
      'Error: Invalid cert renewal port "abc". Must be 1-65535.',
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("--rest alone does not construct a renewal scheduler (negative control)", async () => {
    const { RenewalScheduler } = await import("@harpoc/cert-manager");

    await run(["--rest"]);

    expect(RenewalScheduler).not.toHaveBeenCalled();
    expect(mockRenewalScheduler.start).not.toHaveBeenCalled();
  });

  it("onRenewError prints a Warning: line to stderr", async () => {
    await run(["--cert-renew"]);

    const options = renewalSchedulerCtorCalls[0]?.options as {
      onRenewError: (secretId: string, err: unknown) => void;
    };
    options.onRenewError("secret-1", new Error("CA unreachable"));

    expect(errorSpy).toHaveBeenCalledWith(
      "Warning: certificate renewal failed (secret-1): CA unreachable",
    );
  });

  it("onRenewError is suppressed once shutdown began", async () => {
    const onSpy = vi.spyOn(process, "on");
    exitSpy.mockImplementation(() => undefined as never);

    await run(["--cert-renew"]);
    const options = renewalSchedulerCtorCalls[0]?.options as {
      onRenewError: (secretId: string, err: unknown) => void;
    };

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    (sigintCall?.[1] as () => void)();
    await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(0));

    errorSpy.mockClear();
    options.onRenewError("secret-1", new Error("vault locked"));
    expect(errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("Warning:"));

    onSpy.mockRestore();
  });

  it("SIGINT shutdown stops the renewal scheduler before destroying the engine", async () => {
    const onSpy = vi.spyOn(process, "on");
    exitSpy.mockImplementation(() => undefined as never);

    await run(["--cert-renew"]);

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    expect(sigintCall).toBeDefined();
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => {
      expect(exitSpy).toHaveBeenCalledWith(0);
    });
    expect(mockRenewalScheduler.stop).toHaveBeenCalledTimes(1);
    const stopOrder = mockRenewalScheduler.stop.mock.invocationCallOrder[0] as number;
    const destroyOrder = mockEngine.destroy.mock.invocationCallOrder[0] as number;
    expect(stopOrder).toBeLessThan(destroyOrder);

    onSpy.mockRestore();
  });

  it("shutdown awaits the renewal scheduler drain before destroying the engine", async () => {
    const onSpy = vi.spyOn(process, "on");
    exitSpy.mockImplementation(() => undefined as never);
    let releaseDrain: () => void = () => {};
    mockRenewalScheduler.stop.mockReturnValueOnce(
      new Promise<void>((resolve) => {
        releaseDrain = resolve;
      }),
    );

    await run(["--cert-renew"]);
    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => expect(mockRenewalScheduler.stop).toHaveBeenCalled());
    await new Promise((resolve) => setTimeout(resolve, 20));
    // An order abandoned between issuance and storage is lost for good —
    // the store must stay open while a renewal may still be settling.
    expect(mockEngine.destroy).not.toHaveBeenCalled();

    releaseDrain();
    await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(0));
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);

    onSpy.mockRestore();
  });

  it("combined --cert-renew --rest: renewal drain precedes restServer.close", async () => {
    const onSpy = vi.spyOn(process, "on");
    exitSpy.mockImplementation(() => undefined as never);

    await run(["--cert-renew", "--rest"]);

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    expect(sigintCall).toBeDefined();
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => {
      expect(exitSpy).toHaveBeenCalledWith(0);
    });
    expect(mockRenewalScheduler.stop).toHaveBeenCalledTimes(1);
    expect(mockRestServer.close).toHaveBeenCalledTimes(1);
    // Same tripwire as the refresh twin: pins the direction the drain may
    // move in the shutdown sequence, which stop < destroy alone cannot see.
    const stopOrder = mockRenewalScheduler.stop.mock.invocationCallOrder[0] as number;
    const closeOrder = mockRestServer.close.mock.invocationCallOrder[0] as number;
    expect(stopOrder).toBeLessThan(closeOrder);

    onSpy.mockRestore();
  });

  // ── Shutdown ────────────────────────────────────────────────────

  it("registers SIGINT and SIGTERM handlers", async () => {
    const onSpy = vi.spyOn(process, "on");

    await run(["--mcp"]);

    const events = onSpy.mock.calls.map((c) => c[0]);
    expect(events).toContain("SIGINT");
    expect(events).toContain("SIGTERM");

    onSpy.mockRestore();
  });
});
