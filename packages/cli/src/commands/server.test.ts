import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { Mock } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";

// ── Hoisted mocks (available inside vi.mock factories) ─────────────

const {
  mockEngine,
  mockMcpServer,
  mockMcpHttpServer,
  mockHandle,
  mockRestServer,
  mockRestOAuthManager,
  mockScheduler,
  schedulerCtorCalls,
  mockCertManager,
  certManagerCtorCalls,
  mockRenewalScheduler,
  renewalSchedulerCtorCalls,
  mockEgressProxy,
  mockAgentSocketServer,
  mockUnlockKeySource,
  mockRotationScheduler,
  rotationSchedulerCtorCalls,
} = vi.hoisted(() => ({
  mockEngine: {
    destroy: vi.fn().mockResolvedValue(undefined),
    createToken: vi.fn().mockReturnValue("mock-launch-jwt"),
    auditServerStop: vi.fn(),
    loadProxyCa: vi.fn().mockResolvedValue(null),
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
  mockHandle: {
    close: vi.fn().mockResolvedValue(undefined),
  },
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
  mockEgressProxy: {
    listenTcp: vi.fn(async (port: number) => ({ port })),
    listenSocket: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
  },
  mockAgentSocketServer: {
    start: vi.fn(),
    /** Every server start() resolved, in order. */
    started: [] as { socketPath: string; consumer: string; stop: Mock<() => Promise<void>> }[],
  },
  mockUnlockKeySource: {
    readUnlockKeyFile: vi.fn(),
    readUnlockCredential: vi.fn(),
    readUnlockKeyDpapi: vi.fn(),
  },
  mockRotationScheduler: {
    start: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn().mockResolvedValue(undefined),
  },
  rotationSchedulerCtorCalls: [] as {
    engine: unknown;
    specs: unknown;
    options: Record<string, unknown>;
  }[],
}));

// ── Module mocks ───────────────────────────────────────────────────

vi.mock("../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  unlockEngineWithKey: vi.fn().mockResolvedValue(mockEngine),
}));

vi.mock("@harpoc/mcp-server", () => ({
  createStdioServerFactory: vi.fn().mockReturnValue(() => mockMcpServer),
  startMcpHttpServer: vi.fn().mockResolvedValue(mockMcpHttpServer),
  readLaunchTokenFile: vi.fn().mockReturnValue({ ok: true, token: "file.jwt.token" }),
}));

vi.mock("@modelcontextprotocol/server/stdio", () => ({
  serveStdio: vi.fn().mockReturnValue(mockHandle),
}));

vi.mock("@harpoc/rest-api", () => ({
  startServer: vi.fn().mockResolvedValue(mockRestServer),
  createDefaultOAuthManager: vi.fn().mockReturnValue(mockRestOAuthManager),
}));

vi.mock("@harpoc/oauth-proxy", () => ({
  TokenRefreshScheduler: vi.fn().mockImplementation(function (engine: unknown, options: unknown) {
    schedulerCtorCalls.push({ engine, options: options as Record<string, unknown> });
    return mockScheduler;
  }),
}));

vi.mock("@harpoc/cert-manager", () => ({
  CertManager: vi.fn().mockImplementation(function (engine: unknown) {
    certManagerCtorCalls.push({ engine });
    return mockCertManager;
  }),
  RenewalScheduler: vi.fn().mockImplementation(function (
    engine: unknown,
    renewer: unknown,
    options: unknown,
  ) {
    renewalSchedulerCtorCalls.push({
      engine,
      renewer,
      options: options as Record<string, unknown>,
    });
    return mockRenewalScheduler;
  }),
}));

vi.mock("@harpoc/egress-proxy", () => ({
  createEgressProxy: vi.fn().mockReturnValue(mockEgressProxy),
}));

// server.ts reaches core only for AgentSocketServer, the unlock key's three readers and the token
// rotation's scheduler (vault-loader.js, the engine's one other path, is mocked above).
vi.mock("@harpoc/core", () => ({
  AgentSocketServer: mockAgentSocketServer,
  readUnlockKeyFile: mockUnlockKeySource.readUnlockKeyFile,
  readUnlockCredential: mockUnlockKeySource.readUnlockCredential,
  readUnlockKeyDpapi: mockUnlockKeySource.readUnlockKeyDpapi,
  // runtime-dir.ts's win32 access-list read (B7): a listing that fails, so the real ladder on
  // win32 refuses fail-closed unless a row stubs the ladder.
  listWindowsAclSync: vi.fn(() => {
    throw new Error("ACL listing failed (exit 1)");
  }),
  TokenRotationScheduler: vi.fn().mockImplementation(function (
    engine: unknown,
    specs: unknown,
    options: unknown,
  ) {
    rotationSchedulerCtorCalls.push({ engine, specs, options: options as Record<string, unknown> });
    return mockRotationScheduler;
  }),
}));

// Spy wrapper around the real implementation: the assertion's argument and its
// order against loadUnlockedEngine are observable.
vi.mock("../utils/runtime-dir.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../utils/runtime-dir.js")>();
  return {
    ...actual,
    assertRuntimeDir: vi.fn(actual.assertRuntimeDir),
    consumerSocketPaths: vi.fn(actual.consumerSocketPaths),
    consumerDirs: vi.fn(actual.consumerDirs),
  };
});

// ── Helpers ────────────────────────────────────────────────────────

import { listWindowsAclSync } from "@harpoc/core";
import { registerServerCommand } from "./server.js";
import { buildCli, spyCli, type CliSpies } from "../__fixtures__/cli-harness.js";
import { assertRuntimeDir, consumerDirs, consumerSocketPaths } from "../utils/runtime-dir.js";

const run = buildCli(registerServerCommand, ["server", "start"]);

const REAL_PLATFORM = process.platform;

/**
 * The platform server.ts and runtime-dir.ts read, stubbed so that every row runs on every leg
 * (RA-B5-6): Linux by default, win32 in the Windows rows (B7's branches).
 */
function stubPlatform(value: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value, configurable: true });
}

/** The memory session's line, printed once the engine opens (B5). */
const MEMORY_SESSION =
  "[harpoc] memory session: the vault stays unlocked in this process alone (no session file, no idle seal) until POST /api/v1/vault/lock or SIGTERM";

// ── Tests ──────────────────────────────────────────────────────────

describe("server start", () => {
  let spies: CliSpies;
  let originalLog: typeof console.log;
  let priorSigintListeners: ((signal: "SIGINT") => void)[];
  let priorSigtermListeners: ((signal: "SIGTERM") => void)[];
  let priorStdinEndListeners: ((...args: unknown[]) => void)[];

  beforeEach(() => {
    originalLog = console.log;
    vi.clearAllMocks();
    schedulerCtorCalls.length = 0;
    certManagerCtorCalls.length = 0;
    renewalSchedulerCtorCalls.length = 0;
    rotationSchedulerCtorCalls.length = 0;
    priorSigintListeners = process.listeners("SIGINT");
    priorSigtermListeners = process.listeners("SIGTERM");
    priorStdinEndListeners = process.stdin.listeners("end") as ((...args: unknown[]) => void)[];
    spies = spyCli();
    stubPlatform("linux");
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
    for (const listener of process.stdin.listeners("end") as ((...args: unknown[]) => void)[]) {
      if (!priorStdinEndListeners.includes(listener)) process.stdin.removeListener("end", listener);
    }
    spies.restore();
    stubPlatform(REAL_PLATFORM);
    console.log = originalLog;
  });

  // ── Validation errors ───────────────────────────────────────────

  it("exits with error when no server flag is provided", async () => {
    await expect(run([])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      "Error: At least one of --mcp, --mcp-http, --rest, --oauth-refresh or --cert-renew is required.",
    );
  });

  it("exits with error for non-numeric port", async () => {
    await expect(run(["--rest", "--port", "abc"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid port"));
  });

  it("exits with error for port out of range", async () => {
    await expect(run(["--rest", "--port", "99999"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid port"));
  });

  it("exits with error for port 0", async () => {
    await expect(run(["--rest", "--port", "0"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid port"));
  });

  it("exits with error when --token-file is used without --mcp", async () => {
    await expect(run(["--rest", "--token-file", "/tmp/launch-token"])).rejects.toThrow(
      "process.exit",
    );
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--token-file requires --mcp"),
    );
  });

  it("exits with error when --token-file is used with --mcp-http only", async () => {
    await expect(run(["--mcp-http", "--token-file", "/tmp/launch-token"])).rejects.toThrow(
      "process.exit",
    );
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--token-file requires --mcp"),
    );
  });

  it("D61: refuses a non-loopback --host without --allowed-host before the vault opens", async () => {
    const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
    await expect(run(["--rest", "--host", "0.0.0.0"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("requires --allowed-host"));
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("D61: hands every --allowed-host to startServer with the bind address", async () => {
    const { startServer } = await import("@harpoc/rest-api");
    await run([
      "--rest",
      "--host",
      "0.0.0.0",
      "--allowed-host",
      "vault.example",
      "--allowed-host",
      "api.example",
    ]);
    expect(startServer).toHaveBeenCalledWith(
      expect.objectContaining({
        hostname: "0.0.0.0",
        allowedHosts: ["vault.example", "api.example"],
      }),
    );
  });

  it("D61: --allowed-host on a loopback bind is accepted and additive", async () => {
    const { startServer } = await import("@harpoc/rest-api");
    await run(["--rest", "--allowed-host", "vault.example"]);
    expect(startServer).toHaveBeenCalledWith(
      expect.objectContaining({
        hostname: "127.0.0.1",
        allowedHosts: ["vault.example"],
      }),
    );
  });

  it("D61: --allowed-host requires --rest, and an entry with a port is refused", async () => {
    await expect(run(["--mcp", "--allowed-host", "vault.example"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--allowed-host requires --rest"),
    );
    spies.errorSpy.mockClear();
    await expect(run(["--rest", "--allowed-host", "vault.example:3000"])).rejects.toThrow(
      "process.exit",
    );
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Invalid allowed host "vault.example:3000"'),
    );
  });

  it("refuses the removed --token flag with the pointer to the two channels", async () => {
    const { createStdioServerFactory } = await import("@harpoc/mcp-server");

    await expect(run(["--mcp", "--token", "jwt"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("--token was removed"));
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("--token-file <path>"));
    expect(createStdioServerFactory).not.toHaveBeenCalled();
  });

  it("exits with error when --allow-tokenless is used without --mcp", async () => {
    await expect(run(["--rest", "--allow-tokenless"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--allow-tokenless requires --mcp"),
    );
  });

  it("exits with error when --allow-tokenless is combined with --token-file", async () => {
    const { createStdioServerFactory, readLaunchTokenFile } = await import("@harpoc/mcp-server");

    await expect(
      run(["--mcp", "--allow-tokenless", "--token-file", "/tmp/launch-token"]),
    ).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--allow-tokenless conflicts with a launch token"),
    );
    expect(readLaunchTokenFile).not.toHaveBeenCalled();
    expect(createStdioServerFactory).not.toHaveBeenCalled();
  });

  it("exits with error for an invalid --mcp-http-port", async () => {
    await expect(run(["--mcp-http", "--mcp-http-port", "abc"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid MCP HTTP port"));
  });

  it("exits with error when REST and MCP HTTP ports collide", async () => {
    await expect(
      run(["--rest", "--mcp-http", "--port", "4000", "--mcp-http-port", "4000"]),
    ).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("must differ"));
  });

  it("exits with error when the REST port and the cert-renewal port collide", async () => {
    await expect(
      run(["--rest", "--port", "3000", "--cert-renew", "--cert-renew-port", "3000"]),
    ).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--cert-renew-port must differ"),
    );
  });

  it("exits with error when the MCP HTTP port and the cert-renewal port collide", async () => {
    await expect(
      run(["--mcp-http", "--mcp-http-port", "3001", "--cert-renew", "--cert-renew-port", "3001"]),
    ).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--cert-renew-port must differ"),
    );
  });

  // ── MCP mode ────────────────────────────────────────────────────

  it("starts MCP server with --mcp", async () => {
    const { createStdioServerFactory } = await import("@harpoc/mcp-server");
    const { serveStdio } = await import("@modelcontextprotocol/server/stdio");

    await run(["--mcp"]);

    expect(createStdioServerFactory).toHaveBeenCalledWith({
      engine: mockEngine,
      launchToken: undefined,
      allowTokenless: undefined,
      enableTtyPrompt: true,
    });
    expect(serveStdio).toHaveBeenCalledTimes(1);
    const factory = vi.mocked(serveStdio).mock.calls[0]?.[0];
    expect(factory?.({} as never)).toBe(mockMcpServer);
    expect(typeof vi.mocked(serveStdio).mock.calls[0]?.[1]?.onerror).toBe("function");
  });

  it("passes allowTokenless with --mcp --allow-tokenless", async () => {
    const { createStdioServerFactory } = await import("@harpoc/mcp-server");

    await run(["--mcp", "--allow-tokenless"]);

    expect(createStdioServerFactory).toHaveBeenCalledWith({
      engine: mockEngine,
      launchToken: undefined,
      allowTokenless: true,
      enableTtyPrompt: true,
    });
  });

  it("a TOKEN_REQUIRED throw from createStdioServerFactory exits 1 with the guidance", async () => {
    const { createStdioServerFactory } = await import("@harpoc/mcp-server");
    const { VaultError } = await import("@harpoc/shared");
    (createStdioServerFactory as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
      throw VaultError.tokenRequired();
    });

    await expect(run(["--mcp"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("--allow-tokenless"));
    expect(mockEngine.destroy).toHaveBeenCalled();
  });

  it("passes the file's token to the MCP server with --mcp --token-file", async () => {
    const { createStdioServerFactory, readLaunchTokenFile } = await import("@harpoc/mcp-server");

    await run(["--mcp", "--token-file", "/tmp/launch-token"]);

    expect(readLaunchTokenFile).toHaveBeenCalledWith("/tmp/launch-token");
    expect(createStdioServerFactory).toHaveBeenCalledWith({
      engine: mockEngine,
      launchToken: "file.jwt.token",
      enableTtyPrompt: true,
    });
  });

  it("a --token-file refusal exits 1 before the vault is loaded", async () => {
    const { createStdioServerFactory, readLaunchTokenFile } = await import("@harpoc/mcp-server");
    const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
    (readLaunchTokenFile as ReturnType<typeof vi.fn>).mockReturnValueOnce({
      ok: false,
      message: "Error: Cannot read --token-file /tmp/launch-token: ENOENT\n",
    });

    await expect(run(["--mcp", "--token-file", "/tmp/launch-token"])).rejects.toThrow(
      "process.exit",
    );
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      "Error: Cannot read --token-file /tmp/launch-token: ENOENT",
    );
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(createStdioServerFactory).not.toHaveBeenCalled();
  });

  it.each(["--allow-tokenless", "-"])(
    "refuses a flag Commander took as the --token-file path (%j) before the file is read",
    async (value) => {
      const { createStdioServerFactory, readLaunchTokenFile } = await import("@harpoc/mcp-server");
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

      await expect(run(["--mcp", "--token-file", value])).rejects.toThrow("process.exit");
      expect(spies.exitSpy).toHaveBeenCalledWith(1);
      expect(spies.errorSpy).toHaveBeenCalledWith(
        "Error: --token-file requires a path (give a path that starts with a dash as ./-name).",
      );
      expect(readLaunchTokenFile).not.toHaveBeenCalled();
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(createStdioServerFactory).not.toHaveBeenCalled();
    },
  );

  it("refuses `--token-file --mcp` with the dash-led message, not the transport refusal", async () => {
    const { createStdioServerFactory, readLaunchTokenFile } = await import("@harpoc/mcp-server");
    const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

    await expect(run(["--token-file", "--mcp"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy.mock.calls[0]).toEqual([
      "Error: --token-file requires a path (give a path that starts with a dash as ./-name).",
    ]);
    expect(spies.errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("At least one of"));
    expect(readLaunchTokenFile).not.toHaveBeenCalled();
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(createStdioServerFactory).not.toHaveBeenCalled();
  });

  it("reads a dash-led --token-file written as ./-name", async () => {
    const { readLaunchTokenFile } = await import("@harpoc/mcp-server");

    await run(["--mcp", "--token-file", "./-launch-token"]);

    expect(readLaunchTokenFile).toHaveBeenCalledWith("./-launch-token");
  });

  // ── HARPOC_TOKEN environment variable ───────────────────────────

  describe("HARPOC_TOKEN environment variable", () => {
    it("resolves the launch token from HARPOC_TOKEN with --mcp", async () => {
      const { createStdioServerFactory } = await import("@harpoc/mcp-server");
      process.env.HARPOC_TOKEN = "env.jwt.token";

      await run(["--mcp"]);

      expect(createStdioServerFactory).toHaveBeenCalledWith({
        engine: mockEngine,
        launchToken: "env.jwt.token",
        enableTtyPrompt: true,
      });
    });

    it("an explicit --token-file wins over HARPOC_TOKEN", async () => {
      const { createStdioServerFactory } = await import("@harpoc/mcp-server");
      process.env.HARPOC_TOKEN = "env.jwt.token";

      await run(["--mcp", "--token-file", "/tmp/launch-token"]);

      expect(createStdioServerFactory).toHaveBeenCalledWith({
        engine: mockEngine,
        launchToken: "file.jwt.token",
        enableTtyPrompt: true,
      });
    });

    it("exits with error when --allow-tokenless meets an ambient HARPOC_TOKEN", async () => {
      const { createStdioServerFactory } = await import("@harpoc/mcp-server");
      process.env.HARPOC_TOKEN = "env.jwt.token";

      await expect(run(["--mcp", "--allow-tokenless"])).rejects.toThrow("process.exit");
      expect(spies.exitSpy).toHaveBeenCalledWith(1);
      expect(spies.errorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--allow-tokenless conflicts with a launch token"),
      );
      expect(createStdioServerFactory).not.toHaveBeenCalled();
    });

    it("an ambient HARPOC_TOKEN without --mcp is ignored, not an error", async () => {
      const { createStdioServerFactory } = await import("@harpoc/mcp-server");
      const { startServer } = await import("@harpoc/rest-api");
      process.env.HARPOC_TOKEN = "env.jwt.token";

      await run(["--rest"]);

      expect(startServer).toHaveBeenCalled();
      expect(createStdioServerFactory).not.toHaveBeenCalled();
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });
  });

  // ── --runtime-dir ───────────────────────────────────────────────

  describe("--runtime-dir", () => {
    const FLAG_AS_PATH =
      "Error: [INVALID_INPUT] --runtime-dir: a flag, not a path (give a path that starts with a dash as ./-name)";
    let dir: string;

    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "harpoc-server-runtime-dir-"));
    });

    afterEach(() => {
      vi.unstubAllEnvs();
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    it.each([[["--runtime-dir", "--rest"]], [["--rest", "--runtime-dir=-x"]]])(
      "refuses a flag taken as the --runtime-dir path first (%j), before the vault opens",
      async (argv) => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

        await expect(run(argv)).rejects.toThrow("process.exit");
        expect(spies.exitSpy).toHaveBeenCalledWith(1);
        expect(spies.errorSpy.mock.calls[0]).toEqual([FLAG_AS_PATH]);
        expect(spies.errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("At least one of"));
        expect(assertRuntimeDir).not.toHaveBeenCalled();
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      },
    );

    it.each(["", "  "])(
      "refuses an empty --runtime-dir (%j) before the vault opens",
      async (value) => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

        await expect(run(["--rest", "--runtime-dir", value])).rejects.toThrow("process.exit");
        expect(spies.exitSpy).toHaveBeenCalledWith(1);
        expect(spies.errorSpy.mock.calls[0]).toEqual([
          "Error: [INVALID_INPUT] --runtime-dir: empty path",
        ]);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      },
    );

    it("refuses a missing --runtime-dir before the vault opens", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
      const { startServer } = await import("@harpoc/rest-api");
      const missing = join(dir, "missing");

      await expect(run(["--rest", "--runtime-dir", missing])).rejects.toThrow("process.exit");
      expect(spies.exitSpy).toHaveBeenCalledWith(1);
      expect(spies.errorSpy.mock.calls[0]).toEqual([
        `Error: [INVALID_INPUT] --runtime-dir: no such directory: ${missing}`,
      ]);
      expect(assertRuntimeDir).toHaveBeenCalledWith({ path: missing, source: "--runtime-dir" });
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(startServer).not.toHaveBeenCalled();
    });

    it("checks the directory after the option parses: a port typo reports the port", async () => {
      await expect(
        run(["--rest", "--port", "abc", "--runtime-dir", join(dir, "missing")]),
      ).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls[0]).toEqual([
        'Error: [INVALID_INPUT] Invalid port "abc". Must be 1-65535.',
      ]);
      expect(assertRuntimeDir).not.toHaveBeenCalled();
    });

    // mkdtemp creates the directory 0700, owned by this user (mkdtemp(3));
    // win32 refuses the option (the runIf row below).
    it.skipIf(process.platform === "win32")(
      "asserts --runtime-dir before the vault opens, then starts the daemon (POSIX)",
      async () => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
        const { startServer } = await import("@harpoc/rest-api");

        await run(["--rest", "--runtime-dir", dir]);

        expect(assertRuntimeDir).toHaveBeenCalledWith({ path: dir, source: "--runtime-dir" });
        const [asserted] = vi.mocked(assertRuntimeDir).mock.invocationCallOrder;
        const [loaded] = vi.mocked(loadUnlockedEngine).mock.invocationCallOrder;
        expect(asserted).toBeDefined();
        expect(asserted as number).toBeLessThan(loaded as number);
        expect(startServer).toHaveBeenCalledWith({
          engine: mockEngine,
          port: 3000,
          hostname: "127.0.0.1",
          allowedHosts: [],
          oauthManager: mockRestOAuthManager,
        });
        expect(spies.exitSpy).not.toHaveBeenCalled();
      },
    );

    it.skipIf(process.platform === "win32")(
      "refuses a 0755 --runtime-dir before the vault opens (chmod; POSIX)",
      async () => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
        chmodSync(dir, 0o755);

        await expect(run(["--rest", "--runtime-dir", dir])).rejects.toThrow("process.exit");
        expect(spies.exitSpy).toHaveBeenCalledWith(1);
        expect(spies.errorSpy.mock.calls[0]).toEqual([
          `Error: [INVALID_INPUT] --runtime-dir: mode 0755 is not 0750 or stricter (group-writable or world-accessible): ${dir}`,
        ]);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      },
    );

    // B7 flips B1's RD-3 refusal: the directory is judged by its access list; a listing that
    // cannot be read refuses fail-closed (core's listing is mocked to fail in this suite).
    it("on Windows --runtime-dir is judged by its access list before the vault opens; an unreadable list refuses", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
      stubPlatform("win32");

      await expect(run(["--rest", "--runtime-dir", dir])).rejects.toThrow("process.exit");
      expect(spies.exitSpy).toHaveBeenCalledWith(1);
      expect(spies.errorSpy.mock.calls[0]).toEqual([
        `Error: [INVALID_INPUT] --runtime-dir: the access list cannot be read: ${dir}`,
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    });

    // Model A untouched: a unit's RuntimeDirectory= (0755 by default) sets the
    // variable for a daemon that asked for no runtime directory.
    it("an ambient RUNTIME_DIRECTORY without --runtime-dir is not read: --rest starts", async () => {
      const { startServer } = await import("@harpoc/rest-api");
      vi.stubEnv("RUNTIME_DIRECTORY", join(dir, "missing"));

      await run(["--rest"]);

      expect(startServer).toHaveBeenCalled();
      expect(assertRuntimeDir).not.toHaveBeenCalled();
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });
  });

  // ── --proxy (the egress credential proxy, B2) ──────────────────

  describe("--proxy", () => {
    let dir: string;

    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "harpoc-server-proxy-"));
    });

    afterEach(() => {
      vi.unstubAllEnvs();
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    /** A consumer directory as the recipe leaves it: this user's own, 0750 whatever the umask. */
    function consumer(name: string): string {
      const path = join(dir, name);
      mkdirSync(path);
      chmodSync(path, 0o750);
      return path;
    }

    it("--proxy alone is a valid start: the proxy on the engine, TCP on 127.0.0.1:3128, no socket", async () => {
      const { createEgressProxy } = await import("@harpoc/egress-proxy");

      await run(["--session", "memory", "--proxy"]);

      expect(createEgressProxy).toHaveBeenCalledWith({ engine: mockEngine });
      expect(mockEgressProxy.listenTcp.mock.calls).toEqual([[3128, "127.0.0.1"]]);
      expect(mockEgressProxy.listenSocket).not.toHaveBeenCalled();
      expect(spies.errorSpy).toHaveBeenCalledWith(
        "[harpoc] egress proxy listening on http://127.0.0.1:3128 (TCP only: no --runtime-dir)",
      );
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });

    it("--proxy-port moves the TCP listener", async () => {
      await run(["--session", "memory", "--proxy", "--proxy-port", "4000"]);

      expect(mockEgressProxy.listenTcp.mock.calls).toEqual([[4000, "127.0.0.1"]]);
    });

    it("--proxy-port refuses a hex form INVALID_INPUT before the vault opens", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

      await expect(run(["--session", "memory", "--proxy", "--proxy-port", "0x10"])).rejects.toThrow(
        "process.exit",
      );
      expect(spies.errorSpy.mock.calls[0]).toEqual([
        'Error: [INVALID_INPUT] Invalid proxy port "0x10". Must be 1-65535.',
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    });

    it("--proxy-port requires --proxy", async () => {
      await expect(run(["--rest", "--proxy-port", "4000"])).rejects.toThrow("process.exit");
      expect(spies.exitSpy).toHaveBeenCalledWith(1);
      expect(spies.errorSpy).toHaveBeenCalledWith("Error: --proxy-port requires --proxy.");
    });

    it.each([
      {
        argv: ["--rest", "--port", "4000", "--proxy-port", "4000"],
        line: "Error: --port and --proxy-port must differ (both are 4000).",
      },
      {
        argv: ["--mcp-http", "--mcp-http-port", "3128"],
        line: "Error: --mcp-http-port and --proxy-port must differ (both are 3128).",
      },
      {
        argv: ["--cert-renew", "--cert-renew-port", "3128"],
        line: "Error: --cert-renew-port and --proxy-port must differ (both are 3128).",
      },
    ])("refuses a port the proxy shares before the vault opens: $line", async ({ argv, line }) => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

      await expect(run(["--session", "memory", "--proxy", ...argv])).rejects.toThrow(
        "process.exit",
      );
      expect(spies.errorSpy.mock.calls[0]).toEqual([line]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    });

    // Model A untouched: without --proxy nothing creates the proxy.
    it("--rest alone creates no proxy (negative control)", async () => {
      const { createEgressProxy } = await import("@harpoc/egress-proxy");

      await run(["--rest"]);

      expect(createEgressProxy).not.toHaveBeenCalled();
    });

    // RD-1: --proxy is the first per-consumer feature, so systemd's variable is its default.
    // A drive-less absolute path: on win32 a drive letter's colon would read as RD-2's list.
    it("under --proxy the ambient RUNTIME_DIRECTORY is read and asserted before the vault opens", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
      const missing = "/harpoc-b2-no-such-runtime-dir";
      vi.stubEnv("RUNTIME_DIRECTORY", missing);

      await expect(run(["--session", "memory", "--proxy"])).rejects.toThrow("process.exit");
      expect(assertRuntimeDir).toHaveBeenCalledWith({
        path: missing,
        source: "$RUNTIME_DIRECTORY",
      });
      expect(spies.errorSpy.mock.calls[0]).toEqual([
        `Error: [INVALID_INPUT] $RUNTIME_DIRECTORY: no such directory: ${missing}`,
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    });

    // --runtime-dir is refused on win32 (RD-3): the socket half is POSIX-only.
    it.skipIf(process.platform === "win32")(
      "opens one proxy.sock per consumer directory, by name, after the TCP listener (POSIX)",
      async () => {
        consumer("bob");
        consumer("alice");
        writeFileSync(join(dir, "not-a-consumer"), "");

        await run(["--session", "memory", "--proxy", "--runtime-dir", dir]);

        expect(mockEgressProxy.listenSocket.mock.calls).toEqual([
          [join(dir, "alice", "proxy.sock")],
          [join(dir, "bob", "proxy.sock")],
        ]);
        const [tcp] = mockEgressProxy.listenTcp.mock.invocationCallOrder;
        const [firstSocket] = mockEgressProxy.listenSocket.mock.invocationCallOrder;
        expect(tcp as number).toBeLessThan(firstSocket as number);
        expect(spies.errorSpy).toHaveBeenCalledWith(
          "[harpoc] egress proxy listening on http://127.0.0.1:3128 and 2 consumer sockets (<consumer>/proxy.sock)",
        );
      },
    );

    it.skipIf(process.platform === "win32")(
      "a runtime directory without consumer directories starts the TCP listener alone (POSIX)",
      async () => {
        await run(["--session", "memory", "--proxy", "--runtime-dir", dir]);

        expect(mockEgressProxy.listenTcp).toHaveBeenCalledTimes(1);
        expect(mockEgressProxy.listenSocket).not.toHaveBeenCalled();
        expect(spies.errorSpy).toHaveBeenCalledWith(
          `[harpoc] egress proxy listening on http://127.0.0.1:3128 (TCP only: no consumer directory under ${dir})`,
        );
      },
    );

    it.skipIf(process.platform === "win32")(
      "a misconfigured consumer directory refuses the start before the vault opens (POSIX)",
      async () => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
        chmodSync(consumer("alice"), 0o770);

        await expect(run(["--session", "memory", "--proxy", "--runtime-dir", dir])).rejects.toThrow(
          "process.exit",
        );
        expect(spies.errorSpy.mock.calls[0]).toEqual([
          `Error: [INVALID_INPUT] consumer directory: mode 0770 is not 0750 or stricter (group-writable or world-accessible): ${join(dir, "alice")}`,
        ]);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      },
    );

    // B1's --rest --runtime-dir start reads no consumer directory.
    it.skipIf(process.platform === "win32")(
      "without --proxy no consumer directory is read: --rest --runtime-dir starts (POSIX)",
      async () => {
        const { startServer } = await import("@harpoc/rest-api");
        chmodSync(consumer("alice"), 0o770);

        await run(["--rest", "--runtime-dir", dir]);

        expect(startServer).toHaveBeenCalled();
        expect(spies.exitSpy).not.toHaveBeenCalled();
      },
    );

    it("a rejected proxy bind reaches the fatal path: the error on stderr, exit 1, engine destroyed", async () => {
      mockEgressProxy.listenTcp.mockRejectedValueOnce(
        new Error("listen EADDRINUSE: address already in use 127.0.0.1:3128"),
      );

      await expect(run(["--session", "memory", "--proxy"])).rejects.toThrow("process.exit");
      expect(spies.exitSpy).toHaveBeenCalledWith(1);
      expect(spies.errorSpy).toHaveBeenCalledWith(
        "Error: listen EADDRINUSE: address already in use 127.0.0.1:3128",
      );
      expect(mockEngine.destroy).toHaveBeenCalled();
    });

    it("redirects console.log to stderr beside the stdio server (--mcp --proxy)", async () => {
      await run(["--session", "memory", "--mcp", "--proxy"]);

      expect(console.log).toBe(console.error);
    });

    it("SIGTERM: one server.stop per listener in start order, each before its close, all before destroy", async () => {
      const onSpy = vi.spyOn(process, "on");
      spies.exitSpy.mockImplementation(() => undefined as never);

      await run(["--session", "memory", "--rest", "--proxy", "--proxy-port", "4000"]);
      const sigtermCall = onSpy.mock.calls.find((call) => call[0] === "SIGTERM");
      (sigtermCall?.[1] as () => void)();
      await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));

      expect(mockEngine.auditServerStop.mock.calls).toEqual([
        [
          expect.objectContaining({
            transport: "rest",
            tokenless: false,
            port: 3000,
            trigger: "SIGTERM",
          }),
        ],
        [
          {
            transport: "proxy",
            tokenless: false,
            port: 4000,
            uptimeMs: expect.any(Number),
            trigger: "SIGTERM",
          },
        ],
      ]);
      const [, proxyRow] = mockEngine.auditServerStop.mock.invocationCallOrder as number[];
      const restClose = mockRestServer.close.mock.invocationCallOrder[0] as number;
      const proxyClose = mockEgressProxy.close.mock.invocationCallOrder[0] as number;
      const destroy = mockEngine.destroy.mock.invocationCallOrder[0] as number;
      expect(restClose).toBeLessThan(proxyRow as number);
      expect(proxyRow as number).toBeLessThan(proxyClose);
      expect(proxyClose).toBeLessThan(destroy);

      onSpy.mockRestore();
    });

    it("SIGTERM while the proxy's bind is pending writes no proxy stop row and closes nothing (RA-4)", async () => {
      const onSpy = vi.spyOn(process, "on");
      spies.exitSpy.mockImplementation(() => undefined as never);
      let releaseBind: (bound: { port: number }) => void = () => undefined;
      const bind = new Promise<{ port: number }>((resolve) => {
        releaseBind = resolve;
      });
      mockEgressProxy.listenTcp.mockReturnValueOnce(bind);

      const started = run(["--session", "memory", "--proxy"]);
      await vi.waitFor(() => expect(mockEgressProxy.listenTcp).toHaveBeenCalledTimes(1));
      const sigtermCall = onSpy.mock.calls.find((call) => call[0] === "SIGTERM");
      (sigtermCall?.[1] as () => void)();
      await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
      releaseBind({ port: 3128 });
      await started;

      expect(mockEngine.auditServerStop).not.toHaveBeenCalled();
      expect(mockEgressProxy.close).not.toHaveBeenCalled();

      onSpy.mockRestore();
    });

    it("stdin EOF beside --proxy: only the stdio server stops, the proxy keeps serving", async () => {
      const onceSpy = vi.spyOn(process.stdin, "once");
      spies.exitSpy.mockImplementation(() => undefined as never);

      await run(["--session", "memory", "--mcp", "--allow-tokenless", "--proxy"]);
      const endCall = onceSpy.mock.calls.find((call) => (call[0] as string) === "end");
      (endCall?.[1] as () => void)();
      await vi.waitFor(() => expect(mockHandle.close).toHaveBeenCalledTimes(1));
      // A shutdown would be chained on the close's settlement: let it run before the negative.
      await new Promise<void>((resolve) => setImmediate(resolve));

      expect(mockEngine.auditServerStop.mock.calls).toEqual([
        [expect.objectContaining({ transport: "stdio", trigger: "transport_closed" })],
      ]);
      expect(mockEgressProxy.close).not.toHaveBeenCalled();
      expect(spies.exitSpy).not.toHaveBeenCalled();

      onceSpy.mockRestore();
    });
  });

  // ── --proxy with the Harpoc CA (B8) ─────────────────────────────

  describe("--proxy with the Harpoc CA (B8)", () => {
    const CERT_PEM =
      "-----BEGIN CERTIFICATE-----\nMIIBfixtureINTERMEDIATE\n-----END CERTIFICATE-----\n";
    const ROOT_PEM = "-----BEGIN CERTIFICATE-----\nMIIBfixtureROOT\n-----END CERTIFICATE-----\n";
    const KEY_PEM =
      "-----BEGIN PRIVATE KEY-----\nMIGHfixturecaKEYbody\n-----END PRIVATE KEY-----\n";
    /** What `loadProxyCa` resolves: a fresh key buffer per start, so the wipe of one is observable. */
    const loaded = (unconstrained = false) => ({
      certPem: CERT_PEM,
      keyPem: Buffer.from(KEY_PEM, "utf8"),
      rootPem: ROOT_PEM,
      hosts: ["api.github.com", "127.0.0.1"],
      unconstrained,
      notAfter: Date.UTC(2036, 10, 6, 10, 33, 14),
      fingerprint256:
        "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89",
    });
    let dir: string;

    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "harpoc-server-proxy-ca-"));
      mockEngine.loadProxyCa.mockImplementation(async () => loaded());
    });

    afterEach(() => {
      mockEngine.loadProxyCa.mockReset();
      mockEngine.loadProxyCa.mockResolvedValue(null);
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    function consumer(name: string): string {
      const path = join(dir, name);
      mkdirSync(path);
      chmodSync(path, 0o750);
      return path;
    }

    it("hands the proxy the intermediate, its key bytes and the stored hosts (lane P's ca option); names CONNECT in the line", async () => {
      const { createEgressProxy } = await import("@harpoc/egress-proxy");

      await run(["--session", "memory", "--proxy"]);

      expect(mockEngine.loadProxyCa).toHaveBeenCalledTimes(1);
      expect(createEgressProxy).toHaveBeenCalledWith({
        engine: mockEngine,
        ca: {
          certPem: CERT_PEM,
          keyPem: expect.any(Buffer),
          hosts: ["api.github.com", "127.0.0.1"],
        },
      });
      expect(spies.errorSpy.mock.calls).toContainEqual([
        "[harpoc] Harpoc CA: no consumer directory, no ca.pem written (harpoc proxy ca export prints the certificate)",
      ]);
      expect(spies.errorSpy.mock.calls).toContainEqual([
        "[harpoc] egress proxy listening on http://127.0.0.1:3128 (TCP only: no --runtime-dir) — CONNECT for 2 host(s) (Harpoc CA SHA-256 AB:CD:EF:01:23:45:67:89…)",
      ]);
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });

    it("loads the CA after the vault opens and before the first listener (--rest beside it)", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
      const { startServer } = await import("@harpoc/rest-api");

      await run(["--session", "memory", "--rest", "--proxy", "--proxy-port", "4000"]);

      const opened = vi.mocked(loadUnlockedEngine).mock.invocationCallOrder[0] as number;
      const caLoaded = mockEngine.loadProxyCa.mock.invocationCallOrder[0] as number;
      const rest = vi.mocked(startServer).mock.invocationCallOrder[0] as number;
      expect(opened).toBeLessThan(caLoaded);
      expect(caLoaded).toBeLessThan(rest);
    });

    // RD-B8-13: the fallback's certificates are unconstrained; the proxy's set is the host list.
    it("an unconstrained CA still bounds CONNECT by its host list; the line names the certificates and their expiry", async () => {
      const { createEgressProxy } = await import("@harpoc/egress-proxy");
      mockEngine.loadProxyCa.mockImplementation(async () => loaded(true));

      await run(["--session", "memory", "--proxy"]);

      expect(vi.mocked(createEgressProxy).mock.calls[0]?.[0]).toMatchObject({
        ca: { hosts: ["api.github.com", "127.0.0.1"] },
      });
      expect(spies.errorSpy.mock.calls).toContainEqual([
        "[harpoc] egress proxy listening on http://127.0.0.1:3128 (TCP only: no --runtime-dir) — CONNECT for 2 host(s), certificates unconstrained (Harpoc CA SHA-256 AB:CD:EF:01:23:45:67:89…, until 2036-11-06T10:33:14.000Z)",
      ]);
    });

    it.skipIf(process.platform === "win32")(
      "writes the root as <consumer>/ca.pem, 0640, into every consumer directory before the proxy listens (POSIX)",
      async () => {
        consumer("alice");
        consumer("bob");
        const umask = process.umask(0o077);
        try {
          await run(["--session", "memory", "--proxy", "--runtime-dir", dir]);
        } finally {
          process.umask(umask);
        }

        for (const name of ["alice", "bob"]) {
          const path = join(dir, name, "ca.pem");
          expect(readFileSync(path, "utf8")).toBe(ROOT_PEM);
          expect(statSync(path).mode & 0o777).toBe(0o640);
        }
        expect(spies.errorSpy.mock.calls).toContainEqual([
          "[harpoc] Harpoc CA: the certificate written to 2 consumer directories (<consumer>/ca.pem)",
        ]);
      },
    );

    it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
      "a consumer directory the daemon cannot write refuses the start FILE_IO_ERROR naming the file, before the proxy listens (POSIX)",
      async () => {
        const alice = consumer("alice");
        chmodSync(alice, 0o550);
        try {
          await expect(
            run(["--session", "memory", "--proxy", "--runtime-dir", dir]),
          ).rejects.toThrow("process.exit");
        } finally {
          chmodSync(alice, 0o750);
        }

        expect(spies.errorSpy.mock.calls.at(-1)?.[0]).toMatch(
          /^Error: \[FILE_IO_ERROR\] could not write the CA certificate .*ca\.pem \(EACCES\)$/,
        );
        expect(mockEgressProxy.listenTcp).not.toHaveBeenCalled();
        expect(mockEngine.destroy).toHaveBeenCalled();
      },
    );

    it("an expired CA prints the line and starts without CONNECT (createEgressProxy called with { engine }; no ca.pem written)", async () => {
      const { createEgressProxy } = await import("@harpoc/egress-proxy");
      const { startServer } = await import("@harpoc/rest-api");
      mockEngine.loadProxyCa.mockRejectedValueOnce(
        VaultError.proxyCaExpired("2026-11-01T00:00:00.000Z"),
      );
      stubPlatform("win32");
      vi.mocked(assertRuntimeDir).mockImplementation(() => undefined);
      mkdirSync(join(dir, "alice"));
      vi.mocked(consumerDirs).mockImplementation(() => [
        { consumer: "alice", dir: join(dir, "alice"), sid: "S-1-5-21-1-2-3-1002" },
      ]);
      try {
        await run([
          "--session",
          "memory",
          "--rest",
          "--proxy",
          "--proxy-port",
          "4000",
          "--runtime-dir",
          dir,
        ]);
      } finally {
        vi.mocked(consumerDirs).mockReset();
        vi.mocked(assertRuntimeDir).mockReset();
      }

      expect(spies.errorSpy.mock.calls).toContainEqual([
        "[harpoc] Harpoc CA expired at 2026-11-01T00:00:00.000Z — CONNECT disabled until harpoc proxy ca init --force",
      ]);
      expect(createEgressProxy).toHaveBeenCalledWith({ engine: mockEngine });
      expect(existsSync(join(dir, "alice", "ca.pem"))).toBe(false);
      expect(spies.errorSpy.mock.calls).toContainEqual([
        "[harpoc] egress proxy listening on http://127.0.0.1:4000 (TCP only: Windows serves no proxy.sock)",
      ]);
      expect(startServer).toHaveBeenCalled();
      expect(mockEgressProxy.listenTcp).toHaveBeenCalledTimes(1);
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });

    it("an expired CA whose refusal names no instant takes the same path: the line with <unknown>, the daemon started without CONNECT", async () => {
      const { createEgressProxy } = await import("@harpoc/egress-proxy");
      mockEngine.loadProxyCa.mockRejectedValueOnce(
        new VaultError(ErrorCode.CERT_EXPIRED, "Certificate expired"),
      );

      await run(["--session", "memory", "--proxy"]);

      expect(spies.errorSpy.mock.calls).toContainEqual([
        "[harpoc] Harpoc CA expired at <unknown> — CONNECT disabled until harpoc proxy ca init --force",
      ]);
      expect(createEgressProxy).toHaveBeenCalledWith({ engine: mockEngine });
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });

    it("zero-fills the key bytes when a listener fails between the CA's load and the proxy's creation", async () => {
      const { startServer } = await import("@harpoc/rest-api");
      const material = loaded();
      mockEngine.loadProxyCa.mockImplementation(async () => material);
      vi.mocked(startServer).mockRejectedValueOnce(
        new Error("listen EADDRINUSE: address already in use 127.0.0.1:3000"),
      );

      await expect(
        run(["--session", "memory", "--rest", "--proxy", "--proxy-port", "4000"]),
      ).rejects.toThrow("process.exit");

      expect(material.keyPem.every((byte) => byte === 0)).toBe(true);
      expect(mockEgressProxy.listenTcp).not.toHaveBeenCalled();
      expect(mockEngine.destroy).toHaveBeenCalled();
    });

    it("zero-fills the key bytes once the proxy is created, and never prints the key", async () => {
      const { createEgressProxy } = await import("@harpoc/egress-proxy");

      await run(["--session", "memory", "--proxy"]);

      const handed = vi.mocked(createEgressProxy).mock.calls[0]?.[0] as unknown as {
        ca: { keyPem: Buffer };
      };
      expect(handed.ca.keyPem.length).toBe(Buffer.byteLength(KEY_PEM));
      expect(handed.ca.keyPem.every((byte) => byte === 0)).toBe(true);
      expect(`${spies.stdout()}\n${spies.stderr()}`).not.toContain("fixturecaKEYbody");
    });

    it("zero-fills the key bytes when the proxy's creation throws", async () => {
      const { createEgressProxy } = await import("@harpoc/egress-proxy");
      let handedKey: Buffer | undefined;
      vi.mocked(createEgressProxy).mockImplementationOnce((options) => {
        handedKey = (options as unknown as { ca: { keyPem: Buffer } }).ca.keyPem;
        throw new VaultError(
          ErrorCode.CERT_INVALID,
          "Certificate invalid: CA private key PEM is not parseable",
        );
      });

      await expect(run(["--session", "memory", "--proxy"])).rejects.toThrow("process.exit");

      expect(handedKey?.every((byte) => byte === 0)).toBe(true);
      expect(mockEngine.destroy).toHaveBeenCalled();
    });

    // Model A untouched: without --proxy the CA is never read.
    it("--rest alone never loads the CA (negative control)", async () => {
      await run(["--rest"]);

      expect(mockEngine.loadProxyCa).not.toHaveBeenCalled();
    });

    describe("on Windows (the platform stubbed)", () => {
      beforeEach(() => stubPlatform("win32"));

      afterEach(() => {
        vi.mocked(consumerDirs).mockReset();
        vi.mocked(assertRuntimeDir).mockReset();
      });

      it("writes ca.pem into each consumer directory the access-list check passed (inherited list, no icacls)", async () => {
        vi.mocked(assertRuntimeDir).mockImplementation(() => undefined);
        mkdirSync(join(dir, "alice"));
        vi.mocked(consumerDirs).mockImplementation(() => [
          { consumer: "alice", dir: join(dir, "alice"), sid: "S-1-5-21-1-2-3-1002" },
        ]);

        await run(["--session", "memory", "--proxy", "--runtime-dir", dir]);

        expect(readFileSync(join(dir, "alice", "ca.pem"), "utf8")).toBe(ROOT_PEM);
        expect(spies.errorSpy.mock.calls).toContainEqual([
          "[harpoc] Harpoc CA: the certificate written to 1 consumer directory (<consumer>/ca.pem)",
        ]);
        expect(spies.errorSpy.mock.calls).toContainEqual([
          "[harpoc] egress proxy listening on http://127.0.0.1:3128 (TCP only: Windows serves no proxy.sock) — CONNECT for 2 host(s) (Harpoc CA SHA-256 AB:CD:EF:01:23:45:67:89…)",
        ]);
      });
    });
  });

  // ── --ssh-agent (the persistent agent socket, B3) ──────────────

  describe("--ssh-agent", () => {
    const REQUIRES =
      "Error: --ssh-agent requires --runtime-dir (or systemd's $RUNTIME_DIRECTORY): one ssh-agent.sock per consumer directory.";
    let dir: string;

    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "harpoc-server-ssh-agent-"));
      mockAgentSocketServer.started.length = 0;
      mockAgentSocketServer.start.mockImplementation(
        async (options: { socketPath: string; consumer: string }) => {
          const server = {
            socketPath: options.socketPath,
            consumer: options.consumer,
            stop: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
          };
          mockAgentSocketServer.started.push(server);
          return server;
        },
      );
    });

    afterEach(() => {
      vi.unstubAllEnvs();
      // Back to the real implementations the spy wrapper was built on.
      vi.mocked(assertRuntimeDir).mockReset();
      vi.mocked(consumerSocketPaths).mockReset();
      mockAgentSocketServer.start.mockReset();
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    /**
     * The runtime-directory ladder stubbed for one start, so a start row runs on every platform
     * (--runtime-dir is refused on win32 — RD-3; the real ladder's rows are runtime-dir.test.ts's,
     * the --proxy describe's and the POSIX rows below): the directory passes, and the listing
     * names `<dir>/<consumer>/<socket>` for each consumer, by name.
     */
    function stubConsumers(...names: string[]): void {
      vi.mocked(assertRuntimeDir).mockImplementation(() => undefined);
      vi.mocked(consumerSocketPaths).mockImplementation((_runtimeDir, socketName) =>
        names.map((name) => join(dir, name, socketName)),
      );
    }

    /** A consumer directory as the recipe leaves it: this user's own, 0750 whatever the umask. */
    function consumer(name: string): string {
      const path = join(dir, name);
      mkdirSync(path);
      chmodSync(path, 0o750);
      return path;
    }

    it("--ssh-agent without a runtime directory is refused before the vault opens", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

      await expect(run(["--session", "memory", "--ssh-agent"])).rejects.toThrow("process.exit");
      expect(spies.exitSpy).toHaveBeenCalledWith(1);
      // The combination-check form: the line, then exit 1 (the stub's throw is handleError's).
      expect(spies.errorSpy.mock.calls[0]).toEqual([REQUIRES]);
      expect(spies.errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("At least one of"));
      expect(assertRuntimeDir).not.toHaveBeenCalled();
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(mockAgentSocketServer.start).not.toHaveBeenCalled();
    });

    // RD-1: the socket is a per-consumer feature, so systemd's variable is its default.
    // A drive-less absolute path: on win32 a drive letter's colon would read as RD-2's list.
    it("under --ssh-agent the ambient RUNTIME_DIRECTORY is read and asserted before the vault opens", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
      const missing = "/harpoc-b3-no-such-runtime-dir";
      vi.stubEnv("RUNTIME_DIRECTORY", missing);

      await expect(run(["--session", "memory", "--ssh-agent"])).rejects.toThrow("process.exit");
      expect(assertRuntimeDir).toHaveBeenCalledWith({
        path: missing,
        source: "$RUNTIME_DIRECTORY",
      });
      expect(spies.errorSpy.mock.calls[0]).toEqual([
        `Error: [INVALID_INPUT] $RUNTIME_DIRECTORY: no such directory: ${missing}`,
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    });

    it("--ssh-agent --runtime-dir on Windows meets the access-list check before the vault opens", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
      stubPlatform("win32");

      await expect(
        run(["--session", "memory", "--ssh-agent", "--runtime-dir", dir]),
      ).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([
        [`Error: [INVALID_INPUT] --runtime-dir: the access list cannot be read: ${dir}`],
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(mockAgentSocketServer.start).not.toHaveBeenCalled();
    });

    describe("on Windows (the platform stubbed)", () => {
      beforeEach(() => stubPlatform("win32"));

      afterEach(() => {
        vi.mocked(consumerDirs).mockReset();
      });

      it("serves one pipe per consumer directory, the consumer's name in it, each granting its consumer's SID", async () => {
        vi.mocked(assertRuntimeDir).mockImplementation(() => undefined);
        vi.mocked(consumerDirs).mockImplementation(() => [
          { consumer: "alice", dir: join(dir, "alice"), sid: "S-1-5-21-1-2-3-1002" },
          { consumer: "bob", dir: join(dir, "bob"), sid: "S-1-5-21-1-2-3-1003" },
        ]);

        await run(["--session", "memory", "--ssh-agent", "--runtime-dir", dir]);

        expect(consumerSocketPaths).not.toHaveBeenCalled();
        expect(mockAgentSocketServer.start.mock.calls).toEqual([
          [
            {
              socketPath: "\\\\.\\pipe\\harpoc-alice-ssh-agent",
              consumer: "alice",
              engine: mockEngine,
              win32ConsumerSid: "S-1-5-21-1-2-3-1002",
              onError: expect.any(Function),
            },
          ],
          [
            {
              socketPath: "\\\\.\\pipe\\harpoc-bob-ssh-agent",
              consumer: "bob",
              engine: mockEngine,
              win32ConsumerSid: "S-1-5-21-1-2-3-1003",
              onError: expect.any(Function),
            },
          ],
        ]);
        expect(spies.errorSpy).toHaveBeenCalledWith(
          `[harpoc] ssh-agent listening on 2 consumer pipes (\\\\.\\pipe\\harpoc-<consumer>-ssh-agent) for the consumer directories under ${dir}`,
        );
        expect(spies.exitSpy).not.toHaveBeenCalled();
      });

      it("without --runtime-dir --ssh-agent defaults to %ProgramData%'s harpoc\\run, asserted before the vault opens", async () => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
        vi.stubEnv("ProgramData", "C:\\ProgramData");

        await expect(run(["--session", "memory", "--ssh-agent"])).rejects.toThrow("process.exit");
        expect(assertRuntimeDir).toHaveBeenCalledWith({
          path: "C:\\ProgramData\\harpoc\\run",
          source: "%ProgramData%",
        });
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      });

      it("without --runtime-dir --ssh-agent refuses an unset %ProgramData% with RP-B7-3's message, before the vault opens", async () => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
        vi.stubEnv("ProgramData", undefined);

        await expect(run(["--session", "memory", "--ssh-agent"])).rejects.toThrow("process.exit");
        expect(spies.errorSpy.mock.calls).toEqual([
          [
            "Error: [INVALID_INPUT] %ProgramData% is not set to an absolute path; name the runtime directory with --runtime-dir",
          ],
        ]);
        expect(assertRuntimeDir).not.toHaveBeenCalled();
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      });

      it("refuses a consumer directory entry without an account SID before the vault opens: no pipe without its access list", async () => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
        vi.mocked(assertRuntimeDir).mockImplementation(() => undefined);
        vi.mocked(consumerDirs).mockImplementation(() => [
          { consumer: "alice", dir: join(dir, "alice") },
        ]);

        await expect(
          run(["--session", "memory", "--ssh-agent", "--runtime-dir", dir]),
        ).rejects.toThrow("process.exit");
        expect(spies.errorSpy.mock.calls).toEqual([
          [
            'Error: [INVALID_INPUT] consumer "alice": no account SID resolved for the pipe\'s access list',
          ],
        ]);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
        expect(mockAgentSocketServer.start).not.toHaveBeenCalled();
      });

      it("a runtime directory listing no consumer names the Windows recipe", async () => {
        vi.mocked(assertRuntimeDir).mockImplementation(() => undefined);
        vi.mocked(consumerDirs).mockImplementation(() => []);

        await expect(
          run(["--session", "memory", "--ssh-agent", "--runtime-dir", dir]),
        ).rejects.toThrow("process.exit");
        expect(spies.errorSpy.mock.calls).toEqual([
          [
            `Error: [INVALID_INPUT] --runtime-dir: --ssh-agent found no consumer directory under ${dir} (one per agent user: deploy/windows/install-two-identity.ps1)`,
          ],
        ]);
      });

      it("--proxy alone reads no %ProgramData% default: TCP only, no --runtime-dir", async () => {
        vi.stubEnv("ProgramData", "C:\\ProgramData");

        await run(["--session", "memory", "--proxy"]);

        expect(assertRuntimeDir).not.toHaveBeenCalled();
        expect(spies.errorSpy).toHaveBeenCalledWith(
          "[harpoc] egress proxy listening on http://127.0.0.1:3128 (TCP only: no --runtime-dir)",
        );
      });

      it("--proxy --runtime-dir checks each consumer directory and starts no proxy.sock", async () => {
        vi.mocked(assertRuntimeDir).mockImplementation(() => undefined);
        vi.mocked(consumerDirs).mockImplementation(() => [
          { consumer: "alice", dir: join(dir, "alice"), sid: "S-1-5-21-1-2-3-1002" },
        ]);

        await run(["--session", "memory", "--proxy", "--runtime-dir", dir]);

        expect(vi.mocked(consumerDirs).mock.calls).toEqual([
          [{ path: dir, source: "--runtime-dir" }],
        ]);
        expect(consumerSocketPaths).not.toHaveBeenCalled();
        expect(mockEgressProxy.listenSocket).not.toHaveBeenCalled();
        expect(spies.errorSpy).toHaveBeenCalledWith(
          "[harpoc] egress proxy listening on http://127.0.0.1:3128 (TCP only: Windows serves no proxy.sock)",
        );
      });
    });

    it("starts one AgentSocketServer per consumer directory on the engine, by name, after the REST listener", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
      const { startServer } = await import("@harpoc/rest-api");
      stubConsumers("alice", "bob");

      await run(["--session", "memory", "--rest", "--ssh-agent", "--runtime-dir", dir]);

      expect(vi.mocked(consumerSocketPaths).mock.calls).toEqual([
        [{ path: dir, source: "--runtime-dir" }, "ssh-agent.sock"],
      ]);
      const [listed] = vi.mocked(consumerSocketPaths).mock.invocationCallOrder;
      const [loaded] = vi.mocked(loadUnlockedEngine).mock.invocationCallOrder;
      expect(listed as number).toBeLessThan(loaded as number);
      expect(mockAgentSocketServer.start.mock.calls).toEqual([
        [
          {
            socketPath: join(dir, "alice", "ssh-agent.sock"),
            consumer: "alice",
            engine: mockEngine,
            onError: expect.any(Function),
          },
        ],
        [
          {
            socketPath: join(dir, "bob", "ssh-agent.sock"),
            consumer: "bob",
            engine: mockEngine,
            onError: expect.any(Function),
          },
        ],
      ]);
      const [rest] = vi.mocked(startServer).mock.invocationCallOrder;
      const [firstSocket] = mockAgentSocketServer.start.mock.invocationCallOrder;
      expect(rest as number).toBeLessThan(firstSocket as number);
      expect(spies.errorSpy).toHaveBeenCalledWith(
        `[harpoc] ssh-agent listening on 2 consumer sockets (<consumer>/ssh-agent.sock) under ${dir}`,
      );
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });

    it("--ssh-agent alone is a start mode: one consumer, the singular line", async () => {
      stubConsumers("alice");

      await run(["--session", "memory", "--ssh-agent", "--runtime-dir", dir]);

      expect(mockAgentSocketServer.start).toHaveBeenCalledTimes(1);
      expect(spies.errorSpy.mock.calls).toEqual([
        [MEMORY_SESSION],
        [
          `[harpoc] ssh-agent listening on 1 consumer socket (<consumer>/ssh-agent.sock) under ${dir}`,
        ],
      ]);
    });

    it("a runtime directory listing no consumer refuses the start before the vault opens", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
      stubConsumers();

      await expect(
        run(["--session", "memory", "--rest", "--ssh-agent", "--runtime-dir", dir]),
      ).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([
        [
          `Error: [INVALID_INPUT] --runtime-dir: --ssh-agent found no consumer directory under ${dir} (one per agent user: deploy/linux/install-two-identity.sh)`,
        ],
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    });

    // Model A untouched: without --ssh-agent nothing lists a consumer directory for a socket.
    it("--rest --runtime-dir starts no agent socket and lists no consumer directory (negative control)", async () => {
      stubConsumers("alice");

      await run(["--rest", "--runtime-dir", dir]);

      expect(consumerSocketPaths).not.toHaveBeenCalled();
      expect(mockAgentSocketServer.start).not.toHaveBeenCalled();
      expect(spies.errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("ssh-agent"));
    });

    it("onError names the consumer and the code, never the message; silent once shutdown began", async () => {
      const onSpy = vi.spyOn(process, "on");
      spies.exitSpy.mockImplementation(() => undefined as never);
      stubConsumers("alice");

      await run(["--session", "memory", "--ssh-agent", "--runtime-dir", dir]);
      const [[options]] = mockAgentSocketServer.start.mock.calls as [
        [{ onError: (err: VaultError) => void }],
      ];
      spies.errorSpy.mockClear();
      options.onError(new VaultError(ErrorCode.INTERNAL_ERROR, "a message that names a value"));
      expect(spies.errorSpy.mock.calls).toEqual([["[harpoc] ssh-agent alice: INTERNAL_ERROR"]]);

      const sigtermCall = onSpy.mock.calls.find((call) => call[0] === "SIGTERM");
      (sigtermCall?.[1] as () => void)();
      await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
      spies.errorSpy.mockClear();
      options.onError(new VaultError(ErrorCode.VAULT_LOCKED, "Vault is locked"));
      expect(spies.errorSpy).not.toHaveBeenCalled();

      onSpy.mockRestore();
    });

    it("a rejected start reaches the fatal path: the error on stderr, exit 1, engine destroyed", async () => {
      stubConsumers("alice");
      mockAgentSocketServer.start.mockRejectedValueOnce(
        VaultError.invalidInput("ssh-agent socket: a live socket answers at the path"),
      );

      await expect(
        run(["--session", "memory", "--ssh-agent", "--runtime-dir", dir]),
      ).rejects.toThrow("process.exit");
      expect(spies.exitSpy).toHaveBeenCalledWith(1);
      expect(spies.errorSpy).toHaveBeenCalledWith(
        "Error: [INVALID_INPUT] ssh-agent socket: a live socket answers at the path",
      );
      expect(mockEngine.destroy).toHaveBeenCalled();
    });

    it("SIGTERM: the proxy's pair, then one server.stop per consumer socket, each before its stop(), all before destroy", async () => {
      const onSpy = vi.spyOn(process, "on");
      spies.exitSpy.mockImplementation(() => undefined as never);
      stubConsumers("alice", "bob");

      await run(["--session", "memory", "--proxy", "--ssh-agent", "--runtime-dir", dir]);
      // Beside --proxy both sockets live in each consumer directory.
      expect(vi.mocked(consumerSocketPaths).mock.calls.map((call) => call[1])).toEqual([
        "proxy.sock",
        "ssh-agent.sock",
      ]);
      expect(mockEgressProxy.listenSocket.mock.calls).toEqual([
        [join(dir, "alice", "proxy.sock")],
        [join(dir, "bob", "proxy.sock")],
      ]);
      const sigtermCall = onSpy.mock.calls.find((call) => call[0] === "SIGTERM");
      (sigtermCall?.[1] as () => void)();
      await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));

      expect(mockEngine.auditServerStop.mock.calls).toEqual([
        [expect.objectContaining({ transport: "proxy", port: 3128, trigger: "SIGTERM" })],
        [
          {
            transport: "ssh-agent",
            tokenless: true,
            consumer: "alice",
            uptimeMs: expect.any(Number),
            trigger: "SIGTERM",
          },
        ],
        [
          {
            transport: "ssh-agent",
            tokenless: true,
            consumer: "bob",
            uptimeMs: expect.any(Number),
            trigger: "SIGTERM",
          },
        ],
      ]);
      const [alice, bob] = mockAgentSocketServer.started;
      const [, aliceRow, bobRow] = mockEngine.auditServerStop.mock.invocationCallOrder as number[];
      const proxyClose = mockEgressProxy.close.mock.invocationCallOrder[0] as number;
      const aliceStop = alice?.stop.mock.invocationCallOrder[0] as number;
      const bobStop = bob?.stop.mock.invocationCallOrder[0] as number;
      const destroy = mockEngine.destroy.mock.invocationCallOrder[0] as number;
      expect(proxyClose).toBeLessThan(aliceRow as number);
      expect(aliceRow as number).toBeLessThan(aliceStop);
      expect(aliceStop).toBeLessThan(bobRow as number);
      expect(bobRow as number).toBeLessThan(bobStop);
      expect(bobStop).toBeLessThan(destroy);

      onSpy.mockRestore();
    });

    it("SIGTERM while a socket's start is pending stops only the sockets already serving (E-11)", async () => {
      const onSpy = vi.spyOn(process, "on");
      spies.exitSpy.mockImplementation(() => undefined as never);
      stubConsumers("alice", "bob");
      let releaseBob: () => void = () => undefined;
      const bobStop = vi.fn<() => Promise<void>>().mockResolvedValue(undefined);
      mockAgentSocketServer.start.mockImplementationOnce(
        async (options: { socketPath: string; consumer: string }) => {
          const server = {
            ...options,
            stop: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
          };
          mockAgentSocketServer.started.push(server);
          return server;
        },
      );
      mockAgentSocketServer.start.mockImplementationOnce(
        (options: { socketPath: string; consumer: string }) =>
          new Promise((resolve) => {
            releaseBob = () => resolve({ ...options, stop: bobStop });
          }),
      );

      const started = run(["--session", "memory", "--ssh-agent", "--runtime-dir", dir]);
      await vi.waitFor(() => expect(mockAgentSocketServer.start).toHaveBeenCalledTimes(2));
      const sigtermCall = onSpy.mock.calls.find((call) => call[0] === "SIGTERM");
      (sigtermCall?.[1] as () => void)();
      await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
      releaseBob();
      await started;

      expect(mockEngine.auditServerStop.mock.calls).toEqual([
        [expect.objectContaining({ transport: "ssh-agent", consumer: "alice" })],
      ]);
      expect(mockAgentSocketServer.started[0]?.stop).toHaveBeenCalledTimes(1);
      expect(bobStop).not.toHaveBeenCalled();

      onSpy.mockRestore();
    });

    it("redirects console.log to stderr beside the stdio server (--mcp --ssh-agent)", async () => {
      stubConsumers("alice");

      await run(["--session", "memory", "--mcp", "--ssh-agent", "--runtime-dir", dir]);

      expect(console.log).toBe(console.error);
    });

    it("stdin EOF beside --ssh-agent: only the stdio server stops, the sockets keep serving", async () => {
      const onceSpy = vi.spyOn(process.stdin, "once");
      spies.exitSpy.mockImplementation(() => undefined as never);
      stubConsumers("alice");

      await run([
        "--session",
        "memory",
        "--mcp",
        "--allow-tokenless",
        "--ssh-agent",
        "--runtime-dir",
        dir,
      ]);
      const endCall = onceSpy.mock.calls.find((call) => (call[0] as string) === "end");
      (endCall?.[1] as () => void)();
      await vi.waitFor(() => expect(mockHandle.close).toHaveBeenCalledTimes(1));
      // A shutdown would be chained on the close's settlement: let it run before the negative.
      await new Promise<void>((resolve) => setImmediate(resolve));

      expect(mockEngine.auditServerStop.mock.calls).toEqual([
        [expect.objectContaining({ transport: "stdio", trigger: "transport_closed" })],
      ]);
      expect(mockAgentSocketServer.started[0]?.stop).not.toHaveBeenCalled();
      expect(spies.exitSpy).not.toHaveBeenCalled();

      onceSpy.mockRestore();
    });

    // The real ladder: mkdtemp creates the directory 0700, owned by this user (mkdtemp(3)), and
    // --runtime-dir is refused on win32 (RD-3).
    it.skipIf(process.platform === "win32")(
      "opens one ssh-agent.sock per real consumer directory, by name; a plain file is no consumer (POSIX)",
      async () => {
        consumer("bob");
        consumer("alice");
        writeFileSync(join(dir, "not-a-consumer"), "");

        await run(["--session", "memory", "--ssh-agent", "--runtime-dir", dir]);

        expect(mockAgentSocketServer.start.mock.calls.map((call) => call[0])).toEqual([
          expect.objectContaining({
            socketPath: join(dir, "alice", "ssh-agent.sock"),
            consumer: "alice",
          }),
          expect.objectContaining({
            socketPath: join(dir, "bob", "ssh-agent.sock"),
            consumer: "bob",
          }),
        ]);
      },
    );

    it.skipIf(process.platform === "win32")(
      "a real runtime directory without consumer directories refuses --ssh-agent (POSIX)",
      async () => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

        await expect(
          run(["--session", "memory", "--ssh-agent", "--runtime-dir", dir]),
        ).rejects.toThrow("process.exit");
        expect(spies.errorSpy.mock.calls[0]).toEqual([
          `Error: [INVALID_INPUT] --runtime-dir: --ssh-agent found no consumer directory under ${dir} (one per agent user: deploy/linux/install-two-identity.sh)`,
        ]);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      },
    );

    describe("a link entry under the runtime directory (E-95)", () => {
      const links: string[] = [];

      afterEach(() => {
        vi.mocked(listWindowsAclSync).mockReset();
        for (const path of links.splice(0)) unlinkSync(path);
      });

      /** `<dir>/run` holding the real consumer directory `bob` (`0750`) and `alice`, a link to a directory beside it — a junction on win32, a symbolic link elsewhere — unlinked after the row; returns the runtime directory. */
      function runtimeWithLink(): string {
        const runtime = join(dir, "run");
        mkdirSync(runtime);
        mkdirSync(join(runtime, "bob"));
        chmodSync(join(runtime, "bob"), 0o750);
        mkdirSync(join(dir, "target"));
        symlinkSync(join(dir, "target"), join(runtime, "alice"), "junction");
        links.push(join(runtime, "alice"));
        return runtime;
      }

      it("on Windows (the platform stubbed) refuses the start before the vault opens, the link named", async () => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
        stubPlatform("win32");
        vi.mocked(assertRuntimeDir).mockImplementation(() => undefined);
        const daemon = "S-1-5-21-1-2-3-1001";
        vi.mocked(listWindowsAclSync).mockImplementation(() => ({
          user: daemon,
          owner: daemon,
          account: "S-1-5-21-1-2-3-1002",
          rules: [
            {
              allow: true,
              sid: daemon,
              rights: 0x1f01ff,
              inherited: false,
              inheritance: 3,
              propagation: 0,
            },
          ],
        }));
        const runtime = runtimeWithLink();

        await expect(
          run(["--session", "memory", "--ssh-agent", "--runtime-dir", runtime]),
        ).rejects.toThrow("process.exit");
        expect(spies.exitSpy).toHaveBeenCalledWith(1);
        expect(vi.mocked(consumerDirs).mock.calls).toEqual([
          [{ path: runtime, source: "--runtime-dir" }],
        ]);
        expect(listWindowsAclSync).not.toHaveBeenCalled();
        expect(consumerSocketPaths).not.toHaveBeenCalled();
        const line = String(spies.errorSpy.mock.calls[0]?.[0]);
        expect(line.includes("is a symbolic link or junction")).toBe(true);
        expect(spies.errorSpy.mock.calls).toEqual([
          [
            `Error: [INVALID_INPUT] --runtime-dir: the entry is a symbolic link or junction, not a consumer directory: ${join(runtime, "alice")}`,
          ],
        ]);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
        expect(mockAgentSocketServer.start).not.toHaveBeenCalled();
      });

      it("off Windows (the platform stubbed) refuses the start before the vault opens, the link named", async () => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
        vi.mocked(assertRuntimeDir).mockImplementation(() => undefined);
        const runtime = runtimeWithLink();

        await expect(
          run(["--session", "memory", "--ssh-agent", "--runtime-dir", runtime]),
        ).rejects.toThrow("process.exit");
        expect(spies.exitSpy).toHaveBeenCalledWith(1);
        expect(vi.mocked(consumerSocketPaths).mock.calls).toEqual([
          [{ path: runtime, source: "--runtime-dir" }, "ssh-agent.sock"],
        ]);
        expect(consumerDirs).not.toHaveBeenCalled();
        const line = String(spies.errorSpy.mock.calls[0]?.[0]);
        expect(line.includes("is a symbolic link or junction")).toBe(true);
        expect(spies.errorSpy.mock.calls).toEqual([
          [
            `Error: [INVALID_INPUT] --runtime-dir: the entry is a symbolic link or junction, not a consumer directory: ${join(runtime, "alice")}`,
          ],
        ]);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
        expect(mockAgentSocketServer.start).not.toHaveBeenCalled();
      });
    });
  });

  // ── --unlock-key-file / --unlock-credential (the unlock key, B4) ──

  describe("--unlock-key-file / --unlock-credential", () => {
    const KEY_FILE = "/etc/harpoc/unlock.key";
    const standing = (path: string): string =>
      `Warning: --unlock-key-file is a password file by another name: without a sealer, whoever can read ${path} unlocks the vault.`;
    const KEY_BYTES = Array.from({ length: 32 }, (_, i) => 0xa0 + i);
    let key: Uint8Array;

    beforeEach(() => {
      key = Uint8Array.from(KEY_BYTES);
      mockUnlockKeySource.readUnlockKeyFile.mockResolvedValue(key);
      mockUnlockKeySource.readUnlockCredential.mockResolvedValue(key);
    });

    afterEach(() => {
      vi.unstubAllEnvs();
      mockUnlockKeySource.readUnlockKeyFile.mockReset();
      mockUnlockKeySource.readUnlockCredential.mockReset();
    });

    /**
     * No form of the fixture key reached stdout or stderr, `JSON.stringify`'s object included —
     * every assertion a boolean naming the form, so a red never echoes the output it searched
     * (two-identity.test.ts's form); a row sweeps before it asserts on the captured output.
     */
    function expectNoKeyBytes(): void {
      const bytes = Buffer.from(KEY_BYTES);
      const forms: [form: string, needle: string][] = [
        ["hex", bytes.toString("hex")],
        ["base64", bytes.toString("base64")],
        ["a decimal list", KEY_BYTES.join(",")],
        ["util.inspect's list", KEY_BYTES.join(", ")],
        ["a JSON object", JSON.stringify(new Uint8Array(KEY_BYTES))],
        ["raw bytes", bytes.toString("latin1")],
      ];
      for (const [form, needle] of forms) {
        expect(spies.stdout().includes(needle), `stdout carries the key as ${form}`).toBe(false);
        expect(spies.stderr().includes(needle), `stderr carries the key as ${form}`).toBe(false);
      }
      const decimal = KEY_BYTES.join(",");
      const stripped = (text: string): string => text.replace(/\s+/g, "");
      expect(
        stripped(spies.stdout()).includes(decimal),
        "stdout carries the key as an inspected array",
      ).toBe(false);
      expect(
        stripped(spies.stderr()).includes(decimal),
        "stderr carries the key as an inspected array",
      ).toBe(false);
    }

    /** The engine was unlocked once, from the vault directory, with the reader's buffer itself. */
    async function expectUnlockedWithKey(): Promise<void> {
      const { unlockEngineWithKey } = await import("../utils/vault-loader.js");
      const calls = vi.mocked(unlockEngineWithKey).mock.calls;
      expect(calls.length).toBe(1);
      expect(calls[0]?.[0]).toBe("/mock/.harpoc");
      // Handed over, not copied, so the engine's wipe reaches it; compared by identity so a red
      // prints no byte of the key.
      expect(calls[0]?.[1] === key).toBe(true);
    }

    it("--unlock-key-file reads the key before the vault opens and unlocks the daemon's own engine with it", async () => {
      const { loadUnlockedEngine, unlockEngineWithKey } = await import("../utils/vault-loader.js");
      const { startServer } = await import("@harpoc/rest-api");

      await run(["--session", "memory", "--rest", "--unlock-key-file", KEY_FILE]);

      expectNoKeyBytes();
      expect(mockUnlockKeySource.readUnlockKeyFile.mock.calls).toEqual([
        [KEY_FILE, { onWarning: expect.any(Function) }],
      ]);
      expect(mockUnlockKeySource.readUnlockCredential.mock.calls.length).toBe(0);
      await expectUnlockedWithKey();
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      const [read] = mockUnlockKeySource.readUnlockKeyFile.mock.invocationCallOrder;
      const [unlocked] = vi.mocked(unlockEngineWithKey).mock.invocationCallOrder;
      const [served] = vi.mocked(startServer).mock.invocationCallOrder;
      expect(read as number).toBeLessThan(unlocked as number);
      expect(unlocked as number).toBeLessThan(served as number);
      expect(startServer).toHaveBeenCalledWith(expect.objectContaining({ engine: mockEngine }));
      // The standing warning, exactly once, then the memory session's line.
      expect(spies.errorSpy.mock.calls).toEqual([[standing(KEY_FILE)], [MEMORY_SESSION]]);
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });

    it("--unlock-credential reads systemd's credential through the process environment, with no standing warning", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

      await run(["--session", "memory", "--rest", "--unlock-credential", "harpoc-unlock"]);

      expectNoKeyBytes();
      const reads = mockUnlockKeySource.readUnlockCredential.mock.calls;
      expect(reads.length).toBe(1);
      expect(reads[0]?.[0]).toBe("harpoc-unlock");
      // The process environment itself, by identity: a red prints no variable of the runner's.
      expect(reads[0]?.[1] === process.env).toBe(true);
      expect(mockUnlockKeySource.readUnlockKeyFile).not.toHaveBeenCalled();
      await expectUnlockedWithKey();
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(spies.errorSpy.mock.calls).toEqual([[MEMORY_SESSION]]);
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });

    it("prints each warning the reader reports as a Warning: line after the standing one", async () => {
      mockUnlockKeySource.readUnlockKeyFile.mockImplementationOnce(
        async (path: string, options?: { onWarning?: (warning: string) => void }) => {
          options?.onWarning?.(
            `${path} is on a vfat filesystem — its modes are the mount's options, not the file's`,
          );
          return key;
        },
      );

      await run(["--session", "memory", "--rest", "--unlock-key-file", "/mnt/usb/unlock.key"]);

      expectNoKeyBytes();
      expect(spies.errorSpy.mock.calls).toEqual([
        [standing("/mnt/usb/unlock.key")],
        [
          "Warning: --unlock-key-file: /mnt/usb/unlock.key is on a vfat filesystem — its modes are the mount's options, not the file's",
        ],
        [MEMORY_SESSION],
      ]);
    });

    it("the key-unlocked engine serves the stdio server under its own launch token and mints the UI token after the unlock", async () => {
      const { createStdioServerFactory } = await import("@harpoc/mcp-server");
      const { unlockEngineWithKey } = await import("../utils/vault-loader.js");

      await run([
        "--session",
        "memory",
        "--mcp",
        "--token-file",
        "/tmp/launch-token",
        "--rest",
        "--ui",
        "--unlock-credential",
        "harpoc-unlock",
      ]);

      expectNoKeyBytes();
      expect(createStdioServerFactory).toHaveBeenCalledWith({
        engine: mockEngine,
        launchToken: "file.jwt.token",
        enableTtyPrompt: true,
      });
      const [unlocked] = vi.mocked(unlockEngineWithKey).mock.invocationCallOrder;
      const [minted] = mockEngine.createToken.mock.invocationCallOrder;
      expect(unlocked as number).toBeLessThan(minted as number);
    });

    it("refuses both sources at once before anything is read or the vault opens", async () => {
      const { loadUnlockedEngine, unlockEngineWithKey } = await import("../utils/vault-loader.js");

      await expect(
        run(["--rest", "--unlock-key-file", KEY_FILE, "--unlock-credential", "harpoc-unlock"]),
      ).rejects.toThrow("process.exit");
      expect(spies.exitSpy).toHaveBeenCalledWith(1);
      // The combination-check form: the line, then exit 1 (the stub's throw is handleError's).
      expect(spies.errorSpy.mock.calls[0]).toEqual([
        "Error: --unlock-key-file and --unlock-credential exclude each other: one unlock key source per start.",
      ]);
      expect(mockUnlockKeySource.readUnlockKeyFile).not.toHaveBeenCalled();
      expect(mockUnlockKeySource.readUnlockCredential.mock.calls.length).toBe(0);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(vi.mocked(unlockEngineWithKey).mock.calls.length).toBe(0);
    });

    it.each([
      {
        argv: ["--unlock-key-file", "--rest"],
        line: "Error: [INVALID_INPUT] --unlock-key-file: a flag, not a path (give a path that starts with a dash as ./-name)",
      },
      {
        argv: ["--rest", "--unlock-key-file=-k"],
        line: "Error: [INVALID_INPUT] --unlock-key-file: a flag, not a path (give a path that starts with a dash as ./-name)",
      },
      {
        argv: ["--rest", "--unlock-key-file", ""],
        line: "Error: [INVALID_INPUT] --unlock-key-file: empty path",
      },
      {
        argv: ["--unlock-credential", "--rest"],
        line: "Error: [INVALID_INPUT] --unlock-credential: a flag, not a credential name",
      },
      {
        argv: ["--rest", "--unlock-credential", " "],
        line: "Error: [INVALID_INPUT] --unlock-credential: empty name",
      },
    ])(
      "refuses $argv first, before the transport check, any read or the vault",
      async ({ argv, line }) => {
        const { loadUnlockedEngine, unlockEngineWithKey } =
          await import("../utils/vault-loader.js");

        await expect(run(argv)).rejects.toThrow("process.exit");
        expect(spies.exitSpy.mock.calls).toEqual([[1]]);
        expect(spies.errorSpy.mock.calls).toEqual([[line]]);
        expect(mockUnlockKeySource.readUnlockKeyFile).not.toHaveBeenCalled();
        expect(mockUnlockKeySource.readUnlockCredential.mock.calls.length).toBe(0);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
        expect(vi.mocked(unlockEngineWithKey).mock.calls.length).toBe(0);
      },
    );

    // Model A's line is byte-identical: an unlock key source is not a start mode.
    it.each([
      ["--unlock-key-file", KEY_FILE],
      ["--unlock-credential", "harpoc-unlock"],
    ])(
      "%s alone meets the at-least-one-mode refusal, its line unchanged, nothing read",
      async (flag, value) => {
        await expect(run(["--session", "memory", flag, value])).rejects.toThrow("process.exit");
        expect(spies.errorSpy.mock.calls[0]).toEqual([
          "Error: At least one of --mcp, --mcp-http, --rest, --oauth-refresh or --cert-renew is required.",
        ]);
        expect(mockUnlockKeySource.readUnlockKeyFile).not.toHaveBeenCalled();
        expect(mockUnlockKeySource.readUnlockCredential.mock.calls.length).toBe(0);
      },
    );

    it.each([
      {
        label: "a --port typo",
        argv: ["--rest", "--port", "abc", "--unlock-key-file", KEY_FILE],
        line: 'Error: [INVALID_INPUT] Invalid port "abc". Must be 1-65535.',
      },
      {
        // The ladder's first rung, on every platform (exists → directory → platform → owner → mode).
        label: "a --runtime-dir refusal",
        argv: [
          "--rest",
          "--runtime-dir",
          "/harpoc-b4-no-such-runtime-dir",
          "--unlock-key-file",
          KEY_FILE,
        ],
        line: "Error: [INVALID_INPUT] --runtime-dir: no such directory: /harpoc-b4-no-such-runtime-dir",
      },
    ])(
      "the key is read after every other refusal: $label is reported first",
      async ({ argv, line }) => {
        await expect(run(["--session", "memory", ...argv])).rejects.toThrow("process.exit");
        expect(spies.errorSpy.mock.calls).toEqual([[line]]);
        expect(mockUnlockKeySource.readUnlockKeyFile).not.toHaveBeenCalled();
      },
    );

    it.each([
      {
        label: "a refused key file (UNLOCK_KEY_SOURCE_UNSAFE)",
        argv: ["--rest", "--unlock-key-file", KEY_FILE],
        reader: mockUnlockKeySource.readUnlockKeyFile,
        refusal: VaultError.unlockKeySourceUnsafe(KEY_FILE, "mode", "mode 0640"),
      },
      {
        label: "an unset CREDENTIALS_DIRECTORY (INVALID_INPUT)",
        argv: ["--rest", "--unlock-credential", "harpoc-unlock"],
        reader: mockUnlockKeySource.readUnlockCredential,
        refusal: VaultError.invalidInput(
          "--unlock-credential: $CREDENTIALS_DIRECTORY is not set (systemd sets it for a unit with LoadCredential= or LoadCredentialEncrypted=)",
        ),
      },
    ])(
      "$label: the reader's refusal exits 1 with its line, no warning, before any engine is built",
      async ({ argv, reader, refusal }) => {
        const { loadUnlockedEngine, unlockEngineWithKey } =
          await import("../utils/vault-loader.js");
        reader.mockRejectedValueOnce(refusal);

        await expect(run(["--session", "memory", ...argv])).rejects.toThrow("process.exit");
        expect(spies.exitSpy.mock.calls).toEqual([[1]]);
        expect(spies.errorSpy.mock.calls).toEqual([
          [`Error: [${refusal.code}] ${refusal.message}`],
        ]);
        expect(vi.mocked(unlockEngineWithKey).mock.calls.length).toBe(0);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      },
    );

    it("a reader warning before the reader's refusal is not printed: the refusal's line alone, no standing warning", async () => {
      const { loadUnlockedEngine, unlockEngineWithKey } = await import("../utils/vault-loader.js");
      const err = VaultError.invalidUnlockKey(
        `${KEY_FILE} holds 31 bytes; an unlock key file holds exactly 32 raw bytes`,
      );
      mockUnlockKeySource.readUnlockKeyFile.mockImplementationOnce(
        async (_path: string, options?: { onWarning?: (warning: string) => void }) => {
          options?.onWarning?.(
            "/mnt/usb/unlock.key is on a vfat filesystem — its modes are the mount's options, not the file's",
          );
          throw err;
        },
      );

      await expect(
        run(["--session", "memory", "--rest", "--unlock-key-file", KEY_FILE]),
      ).rejects.toThrow("process.exit");
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([[`Error: [INVALID_UNLOCK_KEY] ${err.message}`]]);
      expect(vi.mocked(unlockEngineWithKey).mock.calls.length).toBe(0);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    });

    it.each([
      {
        label: "a wrong key",
        refusal: () => VaultError.invalidUnlockKey(),
        line: (err: VaultError) => `Error: [INVALID_UNLOCK_KEY] ${err.message}`,
      },
      {
        label: "no enrolled key",
        refusal: () => VaultError.unlockKeyNotEnrolled(),
        line: (err: VaultError) => `Error: [UNLOCK_KEY_NOT_ENROLLED] ${err.message}`,
      },
      {
        label: "the lockout the password path shares",
        refusal: () => VaultError.lockoutActive(30_000),
        line: () => "Error: Account locked. Try again in 30s.",
      },
    ])(
      "$label: the refused unlock exits 1 with the code's line, nothing served, no key byte",
      async ({ refusal, line }) => {
        const { unlockEngineWithKey } = await import("../utils/vault-loader.js");
        const { startServer } = await import("@harpoc/rest-api");
        const err = refusal();
        vi.mocked(unlockEngineWithKey).mockRejectedValueOnce(err);

        await expect(
          run(["--session", "memory", "--rest", "--unlock-credential", "harpoc-unlock"]),
        ).rejects.toThrow("process.exit");
        expectNoKeyBytes();
        expect(spies.exitSpy.mock.calls).toEqual([[1]]);
        expect(spies.errorSpy.mock.calls).toEqual([[line(err)]]);
        expect(startServer).not.toHaveBeenCalled();
        expect(mockEngine.destroy).not.toHaveBeenCalled();
      },
    );

    // Model A untouched: a unit's LoadCredentialEncrypted= sets the variable for a daemon that
    // asked for no unlock key.
    it("without either option an ambient CREDENTIALS_DIRECTORY is not read and the session loads as before", async () => {
      const { loadUnlockedEngine, unlockEngineWithKey } = await import("../utils/vault-loader.js");
      vi.stubEnv("CREDENTIALS_DIRECTORY", "/run/credentials/harpoc.service");

      await run(["--rest"]);

      expect(vi.mocked(loadUnlockedEngine).mock.calls).toEqual([["/mock/.harpoc"]]);
      expect(vi.mocked(unlockEngineWithKey).mock.calls.length).toBe(0);
      expect(mockUnlockKeySource.readUnlockKeyFile).not.toHaveBeenCalled();
      expect(mockUnlockKeySource.readUnlockCredential.mock.calls.length).toBe(0);
      expect(spies.errorSpy).not.toHaveBeenCalled();
    });

    describe("--unlock-key-dpapi (the DPAPI-sealed key, B7-U3)", () => {
      const DPAPI_FILE = "C:\\ProgramData\\harpoc\\vault\\unlock-key.dpapi";

      beforeEach(() => {
        mockUnlockKeySource.readUnlockKeyDpapi.mockResolvedValue(key);
      });

      afterEach(() => {
        mockUnlockKeySource.readUnlockKeyDpapi.mockReset();
      });

      it.each([
        {
          argv: ["--rest", "--unlock-key-dpapi", ""],
          line: "Error: [INVALID_INPUT] --unlock-key-dpapi: empty path",
        },
        {
          argv: ["--unlock-key-dpapi", "--rest"],
          line: "Error: [INVALID_INPUT] --unlock-key-dpapi: a flag, not a path (give a path that starts with a dash as ./-name)",
        },
      ])(
        "refuses --unlock-key-dpapi's value in $argv first, before the transport check, any read or the vault",
        async ({ argv, line }) => {
          const { loadUnlockedEngine, unlockEngineWithKey } =
            await import("../utils/vault-loader.js");

          await expect(run(argv)).rejects.toThrow("process.exit");
          expect(spies.exitSpy.mock.calls).toEqual([[1]]);
          expect(spies.errorSpy.mock.calls).toEqual([[line]]);
          expect(mockUnlockKeySource.readUnlockKeyDpapi).not.toHaveBeenCalled();
          expect(loadUnlockedEngine).not.toHaveBeenCalled();
          expect(vi.mocked(unlockEngineWithKey).mock.calls.length).toBe(0);
        },
      );

      it.each([
        { other: "--unlock-key-file", argv: ["--unlock-key-file", KEY_FILE] },
        { other: "--unlock-credential", argv: ["--unlock-credential", "harpoc-unlock"] },
      ])(
        "refuses --unlock-key-dpapi beside $other before anything is read or the vault opens",
        async ({ other, argv }) => {
          const { loadUnlockedEngine, unlockEngineWithKey } =
            await import("../utils/vault-loader.js");

          await expect(run(["--rest", "--unlock-key-dpapi", DPAPI_FILE, ...argv])).rejects.toThrow(
            "process.exit",
          );
          expect(spies.exitSpy).toHaveBeenCalledWith(1);
          // The combination-check form: the line, then exit 1 (the stub's throw is handleError's).
          expect(spies.errorSpy.mock.calls[0]).toEqual([
            `Error: --unlock-key-dpapi and ${other} exclude each other: one unlock key source per start.`,
          ]);
          expect(mockUnlockKeySource.readUnlockKeyDpapi).not.toHaveBeenCalled();
          expect(mockUnlockKeySource.readUnlockKeyFile).not.toHaveBeenCalled();
          expect(mockUnlockKeySource.readUnlockCredential.mock.calls.length).toBe(0);
          expect(loadUnlockedEngine).not.toHaveBeenCalled();
          expect(vi.mocked(unlockEngineWithKey).mock.calls.length).toBe(0);
        },
      );

      it("in file session mode (the default) it is refused SESSION_MODE_CONFLICT naming it, ahead of the platform refusal, nothing read", async () => {
        const { loadUnlockedEngine, unlockEngineWithKey } =
          await import("../utils/vault-loader.js");

        await expect(run(["--rest", "--unlock-key-dpapi", DPAPI_FILE])).rejects.toThrow(
          "process.exit",
        );
        expect(spies.exitSpy.mock.calls).toEqual([[1]]);
        expect(spies.errorSpy.mock.calls).toEqual([
          [
            `Error: [SESSION_MODE_CONFLICT] ${VaultError.sessionModeConflict("--unlock-key-dpapi").message}`,
          ],
        ]);
        expect(
          VaultError.sessionModeConflict("--unlock-key-dpapi").message.startsWith(
            "--unlock-key-dpapi requires --session memory",
          ),
        ).toBe(true);
        expect(mockUnlockKeySource.readUnlockKeyDpapi).not.toHaveBeenCalled();
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
        expect(vi.mocked(unlockEngineWithKey).mock.calls.length).toBe(0);
      });

      it("off Windows it is refused INVALID_INPUT naming the platform, before anything is read or any vault opens", async () => {
        const { loadUnlockedEngine, unlockEngineWithKey } =
          await import("../utils/vault-loader.js");
        stubPlatform("linux");

        await expect(
          run(["--session", "memory", "--rest", "--unlock-key-dpapi", DPAPI_FILE]),
        ).rejects.toThrow("process.exit");
        expect(spies.exitSpy.mock.calls).toEqual([[1]]);
        expect(spies.errorSpy.mock.calls).toEqual([
          [
            "Error: [INVALID_INPUT] --unlock-key-dpapi: DPAPI is Windows' own and this platform is linux (systemd's sealer is --unlock-credential)",
          ],
        ]);
        expect(mockUnlockKeySource.readUnlockKeyDpapi).not.toHaveBeenCalled();
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
        expect(vi.mocked(unlockEngineWithKey).mock.calls.length).toBe(0);
      });

      it("on Windows the key is read through readUnlockKeyDpapi before the vault opens and unlocks the daemon's own engine, no standing warning", async () => {
        const { loadUnlockedEngine, unlockEngineWithKey } =
          await import("../utils/vault-loader.js");
        const { startServer } = await import("@harpoc/rest-api");
        stubPlatform("win32");

        await run(["--session", "memory", "--rest", "--unlock-key-dpapi", DPAPI_FILE]);

        expectNoKeyBytes();
        expect(mockUnlockKeySource.readUnlockKeyDpapi.mock.calls).toEqual([[DPAPI_FILE]]);
        expect(mockUnlockKeySource.readUnlockKeyFile).not.toHaveBeenCalled();
        expect(mockUnlockKeySource.readUnlockCredential.mock.calls.length).toBe(0);
        await expectUnlockedWithKey();
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
        const [read] = mockUnlockKeySource.readUnlockKeyDpapi.mock.invocationCallOrder;
        const [unlocked] = vi.mocked(unlockEngineWithKey).mock.invocationCallOrder;
        const [served] = vi.mocked(startServer).mock.invocationCallOrder;
        expect(read as number).toBeLessThan(unlocked as number);
        expect(unlocked as number).toBeLessThan(served as number);
        expect(spies.errorSpy.mock.calls).toEqual([[MEMORY_SESSION]]);
        expect(spies.exitSpy).not.toHaveBeenCalled();
      });
    });
  });

  // ── --session and the B-flag conflict (the memory session, B5) ──

  describe("--session and the B-flag conflict", () => {
    const KEY_FILE = "/etc/harpoc/unlock.key";
    const AT_LEAST_ONE =
      "Error: At least one of --mcp, --mcp-http, --rest, --oauth-refresh or --cert-renew is required.";
    const conflictLine = (flag: string): string =>
      `Error: [SESSION_MODE_CONFLICT] ${VaultError.sessionModeConflict(flag).message}`;

    beforeEach(() => {
      mockUnlockKeySource.readUnlockKeyFile.mockResolvedValue(new Uint8Array(32));
      mockUnlockKeySource.readUnlockCredential.mockResolvedValue(new Uint8Array(32));
    });

    afterEach(() => {
      mockUnlockKeySource.readUnlockKeyFile.mockReset();
      mockUnlockKeySource.readUnlockCredential.mockReset();
    });

    it("--session memory --rest builds the engine in memory mode and prints the memory session's line once it opens", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
      const { startServer } = await import("@harpoc/rest-api");
      const { TokenRotationScheduler } = await import("@harpoc/core");

      await run(["--session", "memory", "--rest"]);

      expect(vi.mocked(loadUnlockedEngine).mock.calls).toEqual([
        ["/mock/.harpoc", { sessionMode: "memory" }],
      ]);
      expect(spies.errorSpy.mock.calls).toEqual([[MEMORY_SESSION]]);
      const [loaded] = vi.mocked(loadUnlockedEngine).mock.invocationCallOrder;
      const [line] = spies.errorSpy.mock.invocationCallOrder;
      const [served] = vi.mocked(startServer).mock.invocationCallOrder;
      expect(loaded as number).toBeLessThan(line as number);
      expect(line as number).toBeLessThan(served as number);
      expect(TokenRotationScheduler).not.toHaveBeenCalled();
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });

    // Model A untouched: file mode, the default, calls the loader exactly as before.
    it.each([[["--rest"]], [["--session", "file", "--rest"]]])(
      "%j loads the session as before: the loader gets the vault directory alone, no memory line",
      async (argv) => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

        await run(argv);

        expect(vi.mocked(loadUnlockedEngine).mock.calls).toEqual([["/mock/.harpoc"]]);
        expect(spies.errorSpy).not.toHaveBeenCalled();
        expect(spies.exitSpy).not.toHaveBeenCalled();
      },
    );

    it("--session memory beside an unlock key source builds the key-unlocked engine in memory mode", async () => {
      const { loadUnlockedEngine, unlockEngineWithKey } = await import("../utils/vault-loader.js");

      await run(["--session", "memory", "--rest", "--unlock-credential", "harpoc-unlock"]);

      const calls = vi.mocked(unlockEngineWithKey).mock.calls;
      expect(calls.length).toBe(1);
      expect(calls[0]?.[0]).toBe("/mock/.harpoc");
      expect(calls[0]?.[2]).toEqual({ sessionMode: "memory" });
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(spies.errorSpy.mock.calls).toEqual([[MEMORY_SESSION]]);
    });

    it.each([
      { value: "nonsense", argv: ["--session", "nonsense", "--rest"] },
      { value: "MEMORY", argv: ["--session", "MEMORY", "--rest"] },
      { value: "", argv: ["--session", "", "--rest"] },
      { value: "--rest", argv: ["--session", "--rest"] },
    ])(
      "refuses --session $value INVALID_INPUT naming the two modes, before the transport check or any read",
      async ({ value, argv }) => {
        const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

        await expect(run(argv)).rejects.toThrow("process.exit");
        expect(spies.exitSpy.mock.calls).toEqual([[1]]);
        expect(spies.errorSpy.mock.calls).toEqual([
          [
            `Error: [INVALID_INPUT] --session: ${JSON.stringify(value)} is not a session mode (memory or file)`,
          ],
        ]);
        expect(assertRuntimeDir).not.toHaveBeenCalled();
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      },
    );

    // Review Focus 5: each B flag in file mode is refused at parse, before the flag's own checks
    // (the spec grammar, the readers, the runtime directory's empty-path refusal, the ssh-agent
    // requirement) and before the vault opens.
    it.each([
      { flag: "--issue-token", argv: ["--rest", "--issue-token", "not-a-spec"] },
      { flag: "--unlock-credential", argv: ["--rest", "--unlock-credential", "harpoc-unlock"] },
      { flag: "--unlock-key-file", argv: ["--rest", "--unlock-key-file", KEY_FILE] },
      { flag: "--proxy", argv: ["--proxy", "--runtime-dir", ""] },
      { flag: "--ssh-agent", argv: ["--ssh-agent"] },
    ])(
      "$flag in file mode (the default) is refused SESSION_MODE_CONFLICT naming it, nothing read or loaded",
      async ({ flag, argv }) => {
        const { loadUnlockedEngine, unlockEngineWithKey } =
          await import("../utils/vault-loader.js");
        const { TokenRotationScheduler } = await import("@harpoc/core");

        await expect(run(argv)).rejects.toThrow("process.exit");
        expect(spies.exitSpy.mock.calls).toEqual([[1]]);
        expect(spies.errorSpy.mock.calls).toEqual([[conflictLine(flag)]]);
        expect(
          VaultError.sessionModeConflict(flag).message.startsWith(
            `${flag} requires --session memory`,
          ),
        ).toBe(true);
        expect(mockUnlockKeySource.readUnlockKeyFile).not.toHaveBeenCalled();
        expect(mockUnlockKeySource.readUnlockCredential.mock.calls.length).toBe(0);
        expect(assertRuntimeDir).not.toHaveBeenCalled();
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
        expect(vi.mocked(unlockEngineWithKey).mock.calls.length).toBe(0);
        expect(TokenRotationScheduler).not.toHaveBeenCalled();
      },
    );

    it("an explicit --session file is file mode: --proxy is refused the same way", async () => {
      await expect(run(["--session", "file", "--rest", "--proxy"])).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([[conflictLine("--proxy")]]);
    });

    it.each([
      {
        flag: "--issue-token",
        argv: ["--ssh-agent", "--proxy", "--unlock-key-file", KEY_FILE, "--issue-token", "x"],
      },
      {
        flag: "--unlock-credential",
        argv: ["--proxy", "--ssh-agent", "--rest", "--unlock-credential", "harpoc-unlock"],
      },
      { flag: "--proxy", argv: ["--ssh-agent", "--proxy"] },
    ])(
      "several B flags in file mode: the first in the check's order is named ($flag)",
      async ({ flag, argv }) => {
        await expect(run(argv)).rejects.toThrow("process.exit");
        expect(spies.errorSpy.mock.calls).toEqual([[conflictLine(flag)]]);
      },
    );

    // Model A's line is byte-identical: --session is not a start mode.
    it("--session memory alone meets the at-least-one-mode refusal, its line unchanged", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

      await expect(run(["--session", "memory"])).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls[0]).toEqual([AT_LEAST_ONE]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    });
  });

  // ── --issue-token (the issuer-side token rotation, B5) ─────────

  describe("--issue-token", () => {
    const platform = process.platform;
    let dir: string;

    /** A spec for `agent`, its token file in this row's own directory. */
    function spec(agent: string, extra = ""): string {
      return `agent=${agent},file=${join(dir, `${agent}.jwt`)},scope=use,secrets=db-*${extra}`;
    }

    /** What the parser makes of `spec(agent)`. */
    function parsed(agent: string, ttlMinutes = 1440): Record<string, unknown> {
      return {
        agent,
        file: join(dir, `${agent}.jwt`),
        scope: ["use"],
        secrets: ["db-*"],
        ttlMinutes,
      };
    }

    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "harpoc-server-issue-token-"));
      stubPlatform("linux");
    });

    afterEach(() => {
      stubPlatform(platform);
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    it("one spec: the scheduler is built on the memory-mode engine with the parsed spec and started before any listener", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
      const { startServer } = await import("@harpoc/rest-api");
      const { TokenRotationScheduler } = await import("@harpoc/core");

      await run(["--session", "memory", "--rest", "--issue-token", spec("alice")]);

      expect(vi.mocked(loadUnlockedEngine).mock.calls).toEqual([
        ["/mock/.harpoc", { sessionMode: "memory" }],
      ]);
      expect(rotationSchedulerCtorCalls).toEqual([
        {
          engine: mockEngine,
          specs: [parsed("alice")],
          options: { onError: expect.any(Function) },
        },
      ]);
      expect(mockRotationScheduler.start).toHaveBeenCalledTimes(1);
      const [loaded] = vi.mocked(loadUnlockedEngine).mock.invocationCallOrder;
      const [built] = vi.mocked(TokenRotationScheduler).mock.invocationCallOrder;
      const [started] = mockRotationScheduler.start.mock.invocationCallOrder;
      const [served] = vi.mocked(startServer).mock.invocationCallOrder;
      expect(loaded as number).toBeLessThan(built as number);
      expect(built as number).toBeLessThan(started as number);
      expect(started as number).toBeLessThan(served as number);
      expect(spies.errorSpy.mock.calls).toEqual([
        [MEMORY_SESSION],
        ["[harpoc] token rotation: 1 token file written (alice), re-minted at half its TTL"],
      ]);
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });

    it("the listeners wait for the first mint: startServer is not called before start() resolves", async () => {
      const { startServer } = await import("@harpoc/rest-api");
      let release: () => void = () => undefined;
      mockRotationScheduler.start.mockReturnValueOnce(
        new Promise<void>((resolve) => {
          release = resolve;
        }),
      );

      const started = run(["--session", "memory", "--rest", "--issue-token", spec("alice")]);
      await vi.waitFor(() => expect(mockRotationScheduler.start).toHaveBeenCalledTimes(1));
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(startServer).not.toHaveBeenCalled();
      release();
      await started;

      expect(startServer).toHaveBeenCalledTimes(1);
    });

    it("two specs: one scheduler for both, in order; the line names both agents", async () => {
      await run([
        "--session",
        "memory",
        "--rest",
        "--issue-token",
        spec("alice"),
        "--issue-token",
        spec("bob", ",ttl=60"),
      ]);

      expect(rotationSchedulerCtorCalls.map((call) => call.specs)).toEqual([
        [parsed("alice"), parsed("bob", 60)],
      ]);
      expect(spies.errorSpy).toHaveBeenCalledWith(
        "[harpoc] token rotation: 2 token files written (alice, bob), each re-minted at half its TTL",
      );
    });

    // A consumer of the proxy alone uses the token there: no listener couples with --issue-token.
    it("beside --proxy alone the rotation starts before the proxy listens", async () => {
      await run(["--session", "memory", "--proxy", "--issue-token", spec("alice")]);

      const [started] = mockRotationScheduler.start.mock.invocationCallOrder;
      const [listening] = mockEgressProxy.listenTcp.mock.invocationCallOrder;
      expect(started as number).toBeLessThan(listening as number);
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });

    it("a refused first mint is a start failure: the code's line, exit 1, the engine destroyed, no listener", async () => {
      const { startServer } = await import("@harpoc/rest-api");
      const refusal = VaultError.agentNotFound("alice");
      mockRotationScheduler.start.mockRejectedValueOnce(refusal);

      await expect(
        run(["--session", "memory", "--rest", "--issue-token", spec("alice")]),
      ).rejects.toThrow("process.exit");
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([
        [MEMORY_SESSION],
        [`Error: [AGENT_NOT_FOUND] ${refusal.message}`],
      ]);
      expect(startServer).not.toHaveBeenCalled();
      expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
    });

    it("SIGTERM stops the rotation first: before the refresh drain, every stop row and destroy", async () => {
      const onSpy = vi.spyOn(process, "on");
      spies.exitSpy.mockImplementation(() => undefined as never);

      await run([
        "--session",
        "memory",
        "--rest",
        "--oauth-refresh",
        "--issue-token",
        spec("alice"),
      ]);
      const sigtermCall = onSpy.mock.calls.find((call) => call[0] === "SIGTERM");
      (sigtermCall?.[1] as () => void)();
      await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));

      expect(mockRotationScheduler.stop).toHaveBeenCalledTimes(1);
      const rotationStop = mockRotationScheduler.stop.mock.invocationCallOrder[0] as number;
      const refreshStop = mockScheduler.stop.mock.invocationCallOrder[0] as number;
      const restRow = mockEngine.auditServerStop.mock.invocationCallOrder[0] as number;
      const destroy = mockEngine.destroy.mock.invocationCallOrder[0] as number;
      expect(rotationStop).toBeLessThan(refreshStop);
      expect(refreshStop).toBeLessThan(restRow);
      expect(restRow).toBeLessThan(destroy);

      onSpy.mockRestore();
    });

    it("the shutdown awaits the rotation's stop: nothing else stops while a mint is in flight", async () => {
      const onSpy = vi.spyOn(process, "on");
      spies.exitSpy.mockImplementation(() => undefined as never);
      let releaseStop: () => void = () => undefined;
      mockRotationScheduler.stop.mockReturnValueOnce(
        new Promise<void>((resolve) => {
          releaseStop = resolve;
        }),
      );

      await run(["--session", "memory", "--rest", "--issue-token", spec("alice")]);
      const sigtermCall = onSpy.mock.calls.find((call) => call[0] === "SIGTERM");
      (sigtermCall?.[1] as () => void)();
      await vi.waitFor(() => expect(mockRotationScheduler.stop).toHaveBeenCalled());
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(mockEngine.auditServerStop).not.toHaveBeenCalled();
      expect(mockEngine.destroy).not.toHaveBeenCalled();

      releaseStop();
      await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
      expect(mockEngine.destroy).toHaveBeenCalledTimes(1);

      onSpy.mockRestore();
    });

    it("onError prints the agent and the code alone, a non-VaultError as INTERNAL_ERROR; silent once shutdown began", async () => {
      const onSpy = vi.spyOn(process, "on");
      spies.exitSpy.mockImplementation(() => undefined as never);
      const needle = "needle-4a1f-not-for-stderr";

      await run(["--session", "memory", "--rest", "--issue-token", spec("alice")]);
      const specs = rotationSchedulerCtorCalls[0]?.specs as unknown[];
      const options = rotationSchedulerCtorCalls[0]?.options as {
        onError: (spec: unknown, err: unknown) => void;
      };
      spies.errorSpy.mockClear();
      options.onError(specs[0], new VaultError(ErrorCode.TOKEN_REVOKED, `Token revoked ${needle}`));
      options.onError(specs[0], new Error(`EACCES: open '${needle}.tmp'`));
      options.onError(specs[0], needle);
      expect(spies.stderr().includes(needle)).toBe(false);
      expect(spies.errorSpy.mock.calls).toEqual([
        ["Warning: --issue-token agent=alice: TOKEN_REVOKED"],
        ["Warning: --issue-token agent=alice: INTERNAL_ERROR"],
        ["Warning: --issue-token agent=alice: INTERNAL_ERROR"],
      ]);

      const sigtermCall = onSpy.mock.calls.find((call) => call[0] === "SIGTERM");
      (sigtermCall?.[1] as () => void)();
      await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
      spies.errorSpy.mockClear();
      options.onError(specs[0], VaultError.vaultLocked());
      expect(spies.errorSpy).not.toHaveBeenCalled();

      onSpy.mockRestore();
    });

    it("a spec over the token cap is refused INVALID_INPUT naming ttl, before the vault opens", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

      await expect(
        run(["--session", "memory", "--rest", "--issue-token", spec("alice", ",ttl=1441")]),
      ).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([
        ["Error: [INVALID_INPUT] --issue-token: ttl exceeds the 24 h token cap (1440)"],
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    });

    it("a missing token-file directory is refused INVALID_INPUT naming the file, before the vault opens", async () => {
      const { loadUnlockedEngine } = await import("../utils/vault-loader.js");
      const missing = join(dir, "missing", "alice.jwt");

      await expect(
        run([
          "--session",
          "memory",
          "--rest",
          "--issue-token",
          `agent=alice,file=${missing},scope=use,secrets=db-*`,
        ]),
      ).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([
        [
          `Error: [INVALID_INPUT] --issue-token: file ${missing}: no such directory: ${join(dir, "missing")}`,
        ],
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    });

    it("the directory is checked after the option parses: a port typo reports the port", async () => {
      const missing = join(dir, "missing", "alice.jwt");

      await expect(
        run([
          "--session",
          "memory",
          "--rest",
          "--port",
          "abc",
          "--issue-token",
          `agent=alice,file=${missing},scope=use,secrets=db-*`,
        ]),
      ).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls[0]).toEqual([
        'Error: [INVALID_INPUT] Invalid port "abc". Must be 1-65535.',
      ]);
    });

    // B7 lifts RA-B5-4's refusal: the token file inherits the consumer directory's access list.
    it("on Windows --issue-token builds and starts the scheduler as on Linux", async () => {
      const { TokenRotationScheduler } = await import("@harpoc/core");
      stubPlatform("win32");

      await run(["--session", "memory", "--rest", "--issue-token", spec("alice")]);

      expect(TokenRotationScheduler).toHaveBeenCalledTimes(1);
      expect(rotationSchedulerCtorCalls[0]?.specs).toEqual([parsed("alice")]);
      expect(mockRotationScheduler.start).toHaveBeenCalledTimes(1);
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });

    it("on Windows a spec typo still names its field: the grammar precedes the platform", async () => {
      stubPlatform("win32");

      await expect(
        run(["--session", "memory", "--rest", "--issue-token", "agent=alice"]),
      ).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([
        [
          "Error: [INVALID_INPUT] --issue-token: file is missing (agent, file, scope and secrets are required)",
        ],
      ]);
    });

    // Model A's line is byte-identical: --issue-token is not a start mode.
    it("--issue-token is not a start mode: beside --session memory alone it meets the at-least-one line", async () => {
      const { TokenRotationScheduler } = await import("@harpoc/core");

      await expect(run(["--session", "memory", "--issue-token", spec("alice")])).rejects.toThrow(
        "process.exit",
      );
      expect(spies.errorSpy.mock.calls[0]).toEqual([
        "Error: At least one of --mcp, --mcp-http, --rest, --oauth-refresh or --cert-renew is required.",
      ]);
      expect(TokenRotationScheduler).not.toHaveBeenCalled();
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
    const { createStdioServerFactory, startMcpHttpServer } = await import("@harpoc/mcp-server");

    await run(["--mcp", "--mcp-http"]);

    expect(createStdioServerFactory).toHaveBeenCalled();
    expect(startMcpHttpServer).toHaveBeenCalled();
  });

  // ── REST mode ───────────────────────────────────────────────────

  it("starts REST server with --rest", async () => {
    const { startServer } = await import("@harpoc/rest-api");

    await run(["--rest"]);

    expect(startServer).toHaveBeenCalledWith({
      engine: mockEngine,
      port: 3000,
      hostname: "127.0.0.1",
      allowedHosts: [],
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
      allowedHosts: [],
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
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--rest"]);

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    expect(sigintCall).toBeDefined();
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => {
      expect(spies.exitSpy).toHaveBeenCalledWith(0);
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
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--mcp"]);
    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
    expect(mockRestOAuthManager.cancelPendingFlows).not.toHaveBeenCalled();

    onSpy.mockRestore();
  });

  // ── Web UI ──────────────────────────────────────────────────────

  it("--ui requires --rest", async () => {
    await expect(run(["--ui"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith("Error: --ui requires --rest.");
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
    expect(spies.errorSpy).toHaveBeenCalledWith(
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
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith("Error: --ui-token-ttl requires --ui.");
  });

  it("--ui-token-ttl refuses a non-integer value", async () => {
    await expect(run(["--rest", "--ui", "--ui-token-ttl", "ten"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenCalledWith(
      "Error: --ui-token-ttl must be a whole number of minutes (>= 1).",
    );
  });

  it("--ui-token-ttl refuses a value over the 24 h cap — never clamps", async () => {
    await expect(run(["--rest", "--ui", "--ui-token-ttl", "1441"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenCalledWith(
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
      expect(spies.errorSpy).toHaveBeenCalledWith(
        "Error: --ui-token-ttl must be a whole number of minutes (>= 1).",
      );
      expect(mockEngine.createToken).not.toHaveBeenCalled();
    },
  );

  it("--port refuses a hex form", async () => {
    await expect(run(["--rest", "--port", "0x1f90"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenCalledWith(
      'Error: [INVALID_INPUT] Invalid port "0x1f90". Must be 1-65535.',
    );
  });

  it("the port options are parsed by parseIntOption, not an exit-in-place helper (P1F-3 tripwire)", () => {
    const source = readFileSync(new URL("./server.ts", import.meta.url), "utf8");
    expect(source).not.toContain("function parsePort");
    expect(source).toContain("parseIntOption(");
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
    expect(spies.errorSpy).toHaveBeenCalledWith(
      "Error: --ui-token-ttl must be a whole number of minutes (>= 1).",
    );
    expect(mockEngine.createToken).not.toHaveBeenCalled();
  });

  it("the launch warning names the 24 h cap when the flag is absent", async () => {
    await run(["--rest", "--ui"]);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      "[harpoc] The link grants admin access until the token expires (24 h cap). Do not share it.",
    );
  });

  it("the launch warning names the actual validity under --ui-token-ttl", async () => {
    await run(["--rest", "--ui", "--ui-token-ttl", "30"]);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      "[harpoc] The link grants admin access until the token expires (30 min). Do not share it.",
    );
  });

  // ── Dual mode ───────────────────────────────────────────────────

  it("starts both MCP and REST with --mcp --rest", async () => {
    const { createStdioServerFactory } = await import("@harpoc/mcp-server");
    const { startServer } = await import("@harpoc/rest-api");

    await run(["--mcp", "--rest"]);

    expect(createStdioServerFactory).toHaveBeenCalled();
    expect(startServer).toHaveBeenCalled();
  });

  it("redirects console.log to stderr in dual mode", async () => {
    await run(["--mcp", "--rest"]);

    // After dual-mode init, console.log should be console.error
    expect(console.log).toBe(console.error);
  });

  // ── OAuth refresh scheduler ─────────────────────────────────────

  it("--oauth-refresh alone is a valid start mode and starts the scheduler", async () => {
    const { TokenRefreshScheduler } = await import("@harpoc/oauth-proxy");

    await run(["--oauth-refresh"]);

    expect(TokenRefreshScheduler).toHaveBeenCalledTimes(1);
    expect(schedulerCtorCalls[0]?.engine).toBe(mockEngine);
    expect(mockScheduler.start).toHaveBeenCalledTimes(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("OAuth token refresh scheduler running"),
    );
    expect(spies.exitSpy).not.toHaveBeenCalled();
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

  // D9/R26: startServer binds first and writes its row after, so a bind that
  // fails rejects instead of killing the process on an unhandled 'error'
  // event. The command's own fatal path is what the operator sees.
  it("a rejected REST bind reaches the fatal path: the error on stderr, exit 1, engine destroyed", async () => {
    const { startServer } = await import("@harpoc/rest-api");
    (startServer as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("listen EADDRINUSE: address already in use 127.0.0.1:3000"),
    );

    await expect(run(["--rest"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      "Error: listen EADDRINUSE: address already in use 127.0.0.1:3000",
    );
    expect(mockEngine.destroy).toHaveBeenCalled();
  });

  it("onRefreshError prints a Warning: line to stderr", async () => {
    await run(["--oauth-refresh"]);

    const options = schedulerCtorCalls[0]?.options as {
      onRefreshError: (secretId: string, err: unknown) => void;
    };
    options.onRefreshError("secret-1", new Error("provider offline"));

    expect(spies.errorSpy).toHaveBeenCalledWith(
      "Warning: OAuth token refresh failed (secret-1): provider offline",
    );
  });

  it("onRefreshError is suppressed once shutdown began (review T6)", async () => {
    const onSpy = vi.spyOn(process, "on");
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--oauth-refresh"]);
    const options = schedulerCtorCalls[0]?.options as {
      onRefreshError: (secretId: string, err: unknown) => void;
    };

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    (sigintCall?.[1] as () => void)();
    await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));

    spies.errorSpy.mockClear();
    // A drain-window failure (e.g. vaultLocked racing the teardown) must not
    // print a spurious warning while the process is already exiting.
    options.onRefreshError("secret-1", new Error("vault locked"));
    expect(spies.errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("Warning:"));

    onSpy.mockRestore();
  });

  it("SIGINT shutdown stops the scheduler before destroying the engine", async () => {
    const onSpy = vi.spyOn(process, "on");
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--oauth-refresh"]);

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    expect(sigintCall).toBeDefined();
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => {
      expect(spies.exitSpy).toHaveBeenCalledWith(0);
    });
    expect(mockScheduler.stop).toHaveBeenCalledTimes(1);
    const stopOrder = mockScheduler.stop.mock.invocationCallOrder[0] as number;
    const destroyOrder = mockEngine.destroy.mock.invocationCallOrder[0] as number;
    expect(stopOrder).toBeLessThan(destroyOrder);

    onSpy.mockRestore();
  });

  it("shutdown awaits the scheduler drain before destroying the engine (review fix F2)", async () => {
    const onSpy = vi.spyOn(process, "on");
    spies.exitSpy.mockImplementation(() => undefined as never);
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
    await new Promise((resolve) => setImmediate(resolve));
    // The store must stay open while a rotated token may still arrive —
    // pre-fix, shutdown fired stop() without awaiting the drain.
    expect(mockEngine.destroy).not.toHaveBeenCalled();

    releaseDrain();
    await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);

    onSpy.mockRestore();
  });

  it("combined --oauth-refresh --rest: refresh drain precedes restServer.close", async () => {
    const onSpy = vi.spyOn(process, "on");
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--oauth-refresh", "--rest"]);

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    expect(sigintCall).toBeDefined();
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => {
      expect(spies.exitSpy).toHaveBeenCalledWith(0);
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

    expect(spies.exitSpy).not.toHaveBeenCalled();
    expect(CertManager).toHaveBeenCalledTimes(1);
    expect(certManagerCtorCalls[0]?.engine).toBe(mockEngine);
    expect(RenewalScheduler).toHaveBeenCalledTimes(1);
    expect(renewalSchedulerCtorCalls[0]?.engine).toBe(mockEngine);
    expect(mockRenewalScheduler.start).toHaveBeenCalledTimes(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("certificate renewal scheduler running"),
    );
    // The first check fires one interval after start, not at start — the
    // startup line has to say so, or an operator reads silence as failure.
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("first check in ~1 h"));
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
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--cert-renew-port requires --cert-renew"),
    );
  });

  it("exits with error for an invalid --cert-renew-port before loading the vault", async () => {
    const { loadUnlockedEngine } = await import("../utils/vault-loader.js");

    await expect(run(["--cert-renew", "--cert-renew-port", "abc"])).rejects.toThrow("process.exit");

    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      'Error: [INVALID_INPUT] Invalid cert renewal port "abc". Must be 1-65535.',
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
      onRenewError: (secretId: string, err: unknown, phase: "renewal" | "audit") => void;
    };
    options.onRenewError("secret-1", new Error("CA unreachable"), "renewal");

    expect(spies.errorSpy).toHaveBeenCalledWith(
      "Warning: certificate renewal failed (secret-1): CA unreachable",
    );
  });

  it("onRenewError labels an audit-write failure as such, never as a renewal failure", async () => {
    await run(["--cert-renew"]);

    const options = renewalSchedulerCtorCalls[0]?.options as {
      onRenewError: (secretId: string, err: unknown, phase: "renewal" | "audit") => void;
    };
    options.onRenewError("secret-1", new Error("Vault is locked"), "audit");

    expect(spies.errorSpy).toHaveBeenCalledWith(
      "Warning: the failed-renewal audit row could not be written (secret-1): Vault is locked",
    );
    expect(spies.errorSpy).not.toHaveBeenCalledWith(
      expect.stringContaining("certificate renewal failed"),
    );
  });

  it("onRenewError is suppressed once shutdown began", async () => {
    const onSpy = vi.spyOn(process, "on");
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--cert-renew"]);
    const options = renewalSchedulerCtorCalls[0]?.options as {
      onRenewError: (secretId: string, err: unknown, phase: "renewal" | "audit") => void;
    };

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    (sigintCall?.[1] as () => void)();
    await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));

    spies.errorSpy.mockClear();
    options.onRenewError("secret-1", new Error("vault locked"), "renewal");
    expect(spies.errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("Warning:"));

    onSpy.mockRestore();
  });

  it("SIGINT shutdown stops the renewal scheduler before destroying the engine", async () => {
    const onSpy = vi.spyOn(process, "on");
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--cert-renew"]);

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    expect(sigintCall).toBeDefined();
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => {
      expect(spies.exitSpy).toHaveBeenCalledWith(0);
    });
    expect(mockRenewalScheduler.stop).toHaveBeenCalledTimes(1);
    const stopOrder = mockRenewalScheduler.stop.mock.invocationCallOrder[0] as number;
    const destroyOrder = mockEngine.destroy.mock.invocationCallOrder[0] as number;
    expect(stopOrder).toBeLessThan(destroyOrder);

    onSpy.mockRestore();
  });

  it("shutdown awaits the renewal scheduler drain before destroying the engine", async () => {
    const onSpy = vi.spyOn(process, "on");
    spies.exitSpy.mockImplementation(() => undefined as never);
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
    await new Promise((resolve) => setImmediate(resolve));
    // An order abandoned between issuance and storage is lost for good —
    // the store must stay open while a renewal may still be settling.
    expect(mockEngine.destroy).not.toHaveBeenCalled();

    releaseDrain();
    await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);

    onSpy.mockRestore();
  });

  it("combined --cert-renew --rest: renewal drain precedes restServer.close", async () => {
    const onSpy = vi.spyOn(process, "on");
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--cert-renew", "--rest"]);

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    expect(sigintCall).toBeDefined();
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => {
      expect(spies.exitSpy).toHaveBeenCalledWith(0);
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

  it("SIGINT shutdown writes one server.stop per started listener, each before its close, all before destroy (R4/D67)", async () => {
    const onSpy = vi.spyOn(process, "on");
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--rest", "--mcp-http", "--port", "3000", "--mcp-http-port", "3001"]);
    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    (sigintCall?.[1] as () => void)();
    await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));

    expect(mockEngine.auditServerStop).toHaveBeenCalledTimes(2);
    expect(mockEngine.auditServerStop).toHaveBeenCalledWith(
      expect.objectContaining({
        transport: "http",
        tokenless: false,
        port: 3001,
        trigger: "SIGINT",
      }),
    );
    expect(mockEngine.auditServerStop).toHaveBeenCalledWith(
      expect.objectContaining({
        transport: "rest",
        tokenless: false,
        port: 3000,
        trigger: "SIGINT",
      }),
    );
    const [httpRow, restRow] = mockEngine.auditServerStop.mock.invocationCallOrder as number[];
    const httpClose = mockMcpHttpServer.close.mock.invocationCallOrder[0] as number;
    const restClose = mockRestServer.close.mock.invocationCallOrder[0] as number;
    const destroy = mockEngine.destroy.mock.invocationCallOrder[0] as number;
    expect(httpRow).toBeLessThan(httpClose);
    expect(restRow).toBeLessThan(restClose);
    expect(restClose).toBeLessThan(destroy);
    expect(httpClose).toBeLessThan(destroy);

    onSpy.mockRestore();
  });

  it("a stop row that cannot be written does not block the shutdown", async () => {
    const onSpy = vi.spyOn(process, "on");
    spies.exitSpy.mockImplementation(() => undefined as never);
    mockEngine.auditServerStop.mockImplementationOnce(() => {
      throw new Error("vault locked");
    });

    await run(["--rest"]);
    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    (sigintCall?.[1] as () => void)();

    await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
    expect(mockEngine.auditServerStop.mock.results[0]?.type).toBe("throw");
    expect(mockRestServer.close).toHaveBeenCalledTimes(1);
    expect(mockEngine.auditServerStop.mock.invocationCallOrder[0]).toBeLessThan(
      mockRestServer.close.mock.invocationCallOrder[0] as number,
    );
    onSpy.mockRestore();
  });

  it("stdin EOF alone: the stdio stop row with trigger transport_closed, then the full shutdown", async () => {
    const onceSpy = vi.spyOn(process.stdin, "once");
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--mcp", "--allow-tokenless"]);
    const endCall = onceSpy.mock.calls.find((call) => (call[0] as string) === "end");
    expect(endCall).toBeDefined();
    (endCall?.[1] as () => void)();

    await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
    expect(mockEngine.auditServerStop).toHaveBeenCalledTimes(1);
    expect(mockEngine.auditServerStop).toHaveBeenCalledWith(
      expect.objectContaining({
        transport: "stdio",
        tokenless: true,
        trigger: "transport_closed",
      }),
    );
    expect(mockHandle.close).toHaveBeenCalledTimes(1);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
    onceSpy.mockRestore();
  });

  it("stdin EOF under a launch token: the stdio stop row says tokenless false", async () => {
    const onceSpy = vi.spyOn(process.stdin, "once");
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--mcp", "--token-file", "/tmp/launch-token"]);
    const endCall = onceSpy.mock.calls.find((call) => (call[0] as string) === "end");
    (endCall?.[1] as () => void)();

    await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
    expect(mockEngine.auditServerStop).toHaveBeenCalledTimes(1);
    expect(mockEngine.auditServerStop).toHaveBeenCalledWith(
      expect.objectContaining({
        transport: "stdio",
        tokenless: false,
        trigger: "transport_closed",
      }),
    );
    onceSpy.mockRestore();
  });

  it("stdin EOF beside --rest: only the stdio server stops, the REST listener keeps serving", async () => {
    const onSpy = vi.spyOn(process, "on");
    const onceSpy = vi.spyOn(process.stdin, "once");
    spies.exitSpy.mockImplementation(() => undefined as never);

    await run(["--mcp", "--allow-tokenless", "--rest"]);
    const endCall = onceSpy.mock.calls.find((call) => (call[0] as string) === "end");
    (endCall?.[1] as () => void)();
    await vi.waitFor(() => expect(mockHandle.close).toHaveBeenCalledTimes(1));

    expect(mockEngine.auditServerStop).toHaveBeenCalledTimes(1);
    expect(mockEngine.auditServerStop).toHaveBeenCalledWith(
      expect.objectContaining({
        transport: "stdio",
        trigger: "transport_closed",
      }),
    );
    expect(mockRestServer.close).not.toHaveBeenCalled();
    expect(spies.exitSpy).not.toHaveBeenCalled();

    const sigintCall = onSpy.mock.calls.find((call) => call[0] === "SIGINT");
    (sigintCall?.[1] as () => void)();
    await vi.waitFor(() => expect(spies.exitSpy).toHaveBeenCalledWith(0));
    expect(mockEngine.auditServerStop).toHaveBeenCalledTimes(2);
    expect(mockEngine.auditServerStop).toHaveBeenLastCalledWith(
      expect.objectContaining({ transport: "rest", trigger: "SIGINT" }),
    );
    expect(mockHandle.close).toHaveBeenCalledTimes(1);

    onSpy.mockRestore();
    onceSpy.mockRestore();
  });
});
