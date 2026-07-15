import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Hoisted mocks (available inside vi.mock factories) ─────────────

const { mockEngine, mockManager, managerCtorCalls } = vi.hoisted(() => ({
  mockEngine: {
    destroy: vi.fn().mockResolvedValue(undefined),
  },
  mockManager: {
    startAuthorizationCode: vi.fn(),
    startClientCredentials: vi.fn(),
    startDeviceCode: vi.fn(),
    cancelFlow: vi.fn(),
    cancelPendingFlows: vi.fn(),
  },
  managerCtorCalls: [] as { engine: unknown; options: Record<string, unknown> }[],
}));

// ── Module mocks ───────────────────────────────────────────────────

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

vi.mock("../../utils/prompt.js", () => ({
  promptHidden: vi.fn().mockResolvedValue(""),
}));

vi.mock("@harpoc/oauth-proxy", async (importOriginal) => {
  const original = await importOriginal<typeof import("@harpoc/oauth-proxy")>();
  return {
    ...original,
    OAuthManager: vi.fn().mockImplementation((engine: unknown, options: unknown) => {
      managerCtorCalls.push({ engine, options: options as Record<string, unknown> });
      return mockManager;
    }),
    defaultOpenBrowser: vi.fn().mockResolvedValue(undefined),
  };
});

// ── Helpers ────────────────────────────────────────────────────────

import { Command } from "commander";
import { promptHidden } from "../../utils/prompt.js";
import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { defaultOpenBrowser } from "@harpoc/oauth-proxy";
import { registerOAuthConnectCommand } from "./connect.js";

function buildProgram(): Command {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  const oauth = program.command("oauth").description("OAuth");
  registerOAuthConnectCommand(oauth);
  return program;
}

async function run(args: string[]): Promise<void> {
  const program = buildProgram();
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "oauth", "connect", ...args]);
}

const AUTH_RESULT = {
  handle: "secret://gh-token",
  status: "authorized" as const,
  message: "OAuth flow completed successfully for github",
};

// ── Tests ──────────────────────────────────────────────────────────

describe("oauth connect", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnv = process.env.HARPOC_OAUTH_CLIENT_SECRET;

  beforeEach(() => {
    vi.clearAllMocks();
    managerCtorCalls.length = 0;
    delete process.env.HARPOC_OAUTH_CLIENT_SECRET;
    vi.mocked(promptHidden).mockResolvedValue("");
    mockManager.startAuthorizationCode.mockResolvedValue(AUTH_RESULT);
    mockManager.startClientCredentials.mockResolvedValue({
      ...AUTH_RESULT,
      message: "Client credentials flow completed for github",
    });
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    if (savedEnv === undefined) {
      delete process.env.HARPOC_OAUTH_CLIENT_SECRET;
    } else {
      process.env.HARPOC_OAUTH_CLIENT_SECRET = savedEnv;
    }
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
  });

  it("runs authorization_code by default with preset-merged endpoints", async () => {
    await run(["gh-token", "--provider", "github", "--client-id", "client-1"]);

    expect(mockManager.startAuthorizationCode).toHaveBeenCalledTimes(1);
    const [name, config, project] = mockManager.startAuthorizationCode.mock.calls[0] as [
      string,
      { token_endpoint: string; client_secret?: string },
      string | undefined,
    ];
    expect(name).toBe("gh-token");
    expect(config.token_endpoint).toBe("https://github.com/login/oauth/access_token");
    expect(config.client_secret).toBeUndefined();
    expect(project).toBeUndefined();
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("OK: OAuth secret connected"));
    expect(mockEngine.destroy).toHaveBeenCalled();
  });

  it("an empty prompt means a public client (no client_secret)", async () => {
    vi.mocked(promptHidden).mockResolvedValue("");

    await run(["gh-token", "--provider", "github", "--client-id", "client-1"]);

    expect(promptHidden).toHaveBeenCalledTimes(1);
    const config = mockManager.startAuthorizationCode.mock.calls[0]?.[1] as {
      client_secret?: string;
    };
    expect(config.client_secret).toBeUndefined();
  });

  it("uses the prompted client secret", async () => {
    vi.mocked(promptHidden).mockResolvedValue("prompted-secret");

    await run(["gh-token", "--provider", "github", "--client-id", "client-1"]);

    const config = mockManager.startAuthorizationCode.mock.calls[0]?.[1] as {
      client_secret?: string;
    };
    expect(config.client_secret).toBe("prompted-secret");
  });

  it("HARPOC_OAUTH_CLIENT_SECRET wins and the prompt is never shown", async () => {
    process.env.HARPOC_OAUTH_CLIENT_SECRET = "env-secret";

    await run(["gh-token", "--provider", "github", "--client-id", "client-1"]);

    expect(promptHidden).not.toHaveBeenCalled();
    const config = mockManager.startAuthorizationCode.mock.calls[0]?.[1] as {
      client_secret?: string;
    };
    expect(config.client_secret).toBe("env-secret");
  });

  it("--client-credentials runs the client-credentials flow", async () => {
    process.env.HARPOC_OAUTH_CLIENT_SECRET = "cc-secret";

    await run(["cc-token", "--provider", "github", "--client-id", "client-1", "--client-credentials"]);

    expect(mockManager.startClientCredentials).toHaveBeenCalledTimes(1);
    expect(mockManager.startAuthorizationCode).not.toHaveBeenCalled();
  });

  it("client_credentials without a client secret exits with guidance (negative control)", async () => {
    vi.mocked(promptHidden).mockResolvedValue("");

    await expect(
      run(["cc-token", "--provider", "github", "--client-id", "client-1", "--client-credentials"]),
    ).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("client_credentials requires a client secret"),
    );
    expect(mockManager.startClientCredentials).not.toHaveBeenCalled();
    expect(vi.mocked(loadUnlockedEngine)).not.toHaveBeenCalled();
  });

  it("--device and --client-credentials are mutually exclusive", async () => {
    await expect(
      run(["x-token", "--provider", "github", "--client-id", "c", "--device", "--client-credentials"]),
    ).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("mutually exclusive"));
  });

  it("--device prints the user code and resolves only after completion settles", async () => {
    let releaseCompletion: () => void = () => {};
    const completion = new Promise<void>((resolve) => {
      releaseCompletion = resolve;
    });
    mockManager.startDeviceCode.mockResolvedValue({
      handle: "secret://dev-token",
      status: "pending_authorization",
      auth_url: "https://github.com/login/device",
      user_code: "ABCD-1234",
      message: "visit and enter code",
      completion,
    });

    let finished = false;
    const runPromise = run([
      "dev-token",
      "--provider",
      "github",
      "--client-id",
      "client-1",
      "--device",
    ]).then(() => {
      finished = true;
    });

    await vi.waitFor(() => {
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("ABCD-1234"));
    });
    expect(finished).toBe(false);

    releaseCompletion();
    await runPromise;
    expect(finished).toBe(true);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("OK: OAuth secret connected"));
  });

  it("the default openBrowser prints the URL and does not launch a browser", async () => {
    await run(["gh-token", "--provider", "github", "--client-id", "client-1"]);

    const options = managerCtorCalls[0]?.options as {
      openBrowser: (url: string) => Promise<void>;
    };
    await options.openBrowser("https://github.com/login/oauth/authorize?x=1");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("https://github.com/login/oauth/authorize?x=1"),
    );
    expect(defaultOpenBrowser).not.toHaveBeenCalled();
  });

  it("--open additionally launches the browser", async () => {
    await run(["gh-token", "--provider", "github", "--client-id", "client-1", "--open"]);

    const options = managerCtorCalls[0]?.options as {
      openBrowser: (url: string) => Promise<void>;
    };
    await options.openBrowser("https://example.com/auth");

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("https://example.com/auth"));
    expect(defaultOpenBrowser).toHaveBeenCalledWith("https://example.com/auth");
  });

  it("forwards --callback-port and --timeout into OAuthManager options", async () => {
    await run([
      "gh-token",
      "--provider",
      "github",
      "--client-id",
      "client-1",
      "--callback-port",
      "0",
      "--timeout",
      "5",
    ]);

    expect(managerCtorCalls[0]?.options).toMatchObject({
      callbackPort: 0,
      callbackTimeoutMs: 5000,
    });
  });

  it("rejects an invalid --callback-port", async () => {
    await expect(
      run(["gh-token", "--provider", "github", "--client-id", "c", "--callback-port", "70000"]),
    ).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid callback port"));
  });

  it("SIGINT cancels pending flows and destroys the engine", async () => {
    const onceSpy = vi.spyOn(process, "once");
    exitSpy.mockImplementation(() => undefined as never);

    await run(["gh-token", "--provider", "github", "--client-id", "client-1"]);

    const sigintCall = onceSpy.mock.calls.find((call) => call[0] === "SIGINT");
    expect(sigintCall).toBeDefined();
    (sigintCall?.[1] as () => void)();

    expect(mockManager.cancelPendingFlows).toHaveBeenCalled();
    await vi.waitFor(() => {
      expect(exitSpy).toHaveBeenCalledWith(130);
    });
    expect(mockEngine.destroy).toHaveBeenCalled();
    onceSpy.mockRestore();
  });

  it("--json prints a single JSON document to stdout", async () => {
    await run(["gh-token", "--provider", "github", "--client-id", "client-1", "--json"]);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const printed = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(printed).toEqual({
      handle: "secret://gh-token",
      status: "authorized",
      message: "OAuth flow completed successfully for github",
    });
  });
});
