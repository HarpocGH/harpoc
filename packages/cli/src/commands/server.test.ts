import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Hoisted mocks (available inside vi.mock factories) ─────────────

const { mockEngine, mockMcpServer, mockTransport, mockRestServer } = vi.hoisted(() => ({
  mockEngine: {
    destroy: vi.fn().mockResolvedValue(undefined),
  },
  mockMcpServer: {
    connect: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
  },
  mockTransport: {},
  mockRestServer: {
    close: vi.fn(),
  },
}));

// ── Module mocks ───────────────────────────────────────────────────

vi.mock("../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

vi.mock("@harpoc/mcp-server", () => ({
  createMcpServer: vi.fn().mockReturnValue(mockMcpServer),
}));

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn().mockReturnValue(mockTransport),
}));

vi.mock("@harpoc/rest-api", () => ({
  startServer: vi.fn().mockReturnValue(mockRestServer),
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

  beforeEach(() => {
    vi.clearAllMocks();
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
  });

  // ── Validation errors ───────────────────────────────────────────

  it("exits with error when neither --mcp nor --rest is provided", async () => {
    await expect(run([])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith("Error: At least one of --mcp or --rest is required.");
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
    expect(errorSpy).toHaveBeenCalledWith("Error: --token requires --mcp.");
  });

  // ── MCP mode ────────────────────────────────────────────────────

  it("starts MCP server with --mcp", async () => {
    const { createMcpServer } = await import("@harpoc/mcp-server");
    const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");

    await run(["--mcp"]);

    expect(createMcpServer).toHaveBeenCalledWith({
      engine: mockEngine,
      launchToken: undefined,
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
    });
  });

  // ── REST mode ───────────────────────────────────────────────────

  it("starts REST server with --rest", async () => {
    const { startServer } = await import("@harpoc/rest-api");

    await run(["--rest"]);

    expect(startServer).toHaveBeenCalledWith({ engine: mockEngine, port: 3000 });
  });

  it("starts REST server with custom port", async () => {
    const { startServer } = await import("@harpoc/rest-api");

    await run(["--rest", "--port", "8080"]);

    expect(startServer).toHaveBeenCalledWith({ engine: mockEngine, port: 8080 });
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
