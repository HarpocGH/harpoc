import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Hoisted mocks (available inside vi.mock factories) ─────────────

const {
  mockEngine,
  mockMcpServer,
  mockMcpHttpServer,
  mockTransport,
  mockRestServer,
  mockScheduler,
  schedulerCtorCalls,
} = vi.hoisted(() => ({
  mockEngine: {
    destroy: vi.fn().mockResolvedValue(undefined),
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
  mockScheduler: {
    start: vi.fn(),
    stop: vi.fn(),
  },
  schedulerCtorCalls: [] as { engine: unknown; options: Record<string, unknown> }[],
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
}));

vi.mock("@harpoc/oauth-proxy", () => ({
  TokenRefreshScheduler: vi.fn().mockImplementation((engine: unknown, options: unknown) => {
    schedulerCtorCalls.push({ engine, options: options as Record<string, unknown> });
    return mockScheduler;
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
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let priorSigintListeners: NodeJS.SignalsListener[];
  let priorSigtermListeners: NodeJS.SignalsListener[];

  beforeEach(() => {
    vi.clearAllMocks();
    schedulerCtorCalls.length = 0;
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
      "Error: At least one of --mcp, --mcp-http, --rest or --oauth-refresh is required.",
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
      enableTtyPrompt: true,
    });
    expect(StdioServerTransport).toHaveBeenCalled();
    expect(mockMcpServer.connect).toHaveBeenCalledWith(mockTransport);
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
    });
  });

  it("starts REST server with custom port", async () => {
    const { startServer } = await import("@harpoc/rest-api");

    await run(["--rest", "--port", "8080"]);

    expect(startServer).toHaveBeenCalledWith({
      engine: mockEngine,
      port: 8080,
      hostname: "127.0.0.1",
    });
  });

  it("starts REST server with custom bind address", async () => {
    const { startServer } = await import("@harpoc/rest-api");

    await run(["--rest", "--host", "0.0.0.0"]);

    expect(startServer).toHaveBeenCalledWith({
      engine: mockEngine,
      port: 3000,
      hostname: "0.0.0.0",
    });
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
