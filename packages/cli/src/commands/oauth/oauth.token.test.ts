import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from "vitest";
import type { VaultApiToken } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    getOAuthTokenStatus: vi.fn().mockReturnValue({
      secret_id: "sid-1",
      provider: "github",
      has_access_token: true,
      access_token_expires_at: null,
      has_refresh_token: true,
      last_refreshed_at: null,
      refresh_status: "ok",
      token_endpoint_auth_method: "client_secret_post",
    }),
    refreshOAuthToken: vi.fn().mockResolvedValue(2_000_000_000_000),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("sid-1"),
}));

import { Command } from "commander";
import { registerOAuthStatusCommand } from "./status.js";
import { registerOAuthRefreshCommand } from "./refresh.js";

function token(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "agent-1",
    vault_id: "vault-1",
    scope: ["read"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
    principal_type: "agent",
    ...overrides,
  };
}

function buildProgram(): Command {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  const oauth = program.command("oauth").description("OAuth");
  registerOAuthStatusCommand(oauth);
  registerOAuthRefreshCommand(oauth);
  return program;
}

async function run(args: string[]): Promise<void> {
  const program = buildProgram();
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "oauth", ...args]);
}

describe("oauth status / refresh — token path", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.getOAuthTokenStatus.mockReturnValue({
      secret_id: "sid-1",
      provider: "github",
      has_access_token: true,
      access_token_expires_at: null,
      has_refresh_token: true,
      last_refreshed_at: null,
      refresh_status: "ok",
      token_endpoint_auth_method: "client_secret_post",
    });
    mockEngine.refreshOAuthToken.mockResolvedValue(2_000_000_000_000);
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
    if (savedEnvToken === undefined) delete process.env.HARPOC_TOKEN;
    else process.env.HARPOC_TOKEN = savedEnvToken;
  });

  it("status requires read and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await run(["status", "secret://gh", "--token", "jwt-value"]);
    expect(mockEngine.getOAuthTokenStatus).toHaveBeenCalledWith(
      "sid-1",
      expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
    );
  });

  it("refresh requires rotate and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run(["refresh", "secret://gh", "--token", "jwt-value"]);
    expect(mockEngine.refreshOAuthToken).toHaveBeenCalledWith(
      "sid-1",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("scope refusals precede handle resolution; tokenless paths pass no caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await expect(run(["refresh", "secret://gh", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(mockEngine.refreshOAuthToken).not.toHaveBeenCalled();

    await run(["status", "secret://gh"]);
    expect(mockEngine.getOAuthTokenStatus).toHaveBeenLastCalledWith("sid-1", undefined);
    await run(["refresh", "secret://gh"]);
    expect(mockEngine.refreshOAuthToken).toHaveBeenLastCalledWith("sid-1", undefined);
  });
});
