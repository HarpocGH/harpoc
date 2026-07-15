import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { VaultError } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    getOAuthTokenStatus: vi.fn(),
    refreshOAuthToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("secret-id-1"),
}));

import { Command } from "commander";
import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerOAuthStatusCommand } from "./status.js";
import { registerOAuthRefreshCommand } from "./refresh.js";

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

describe("oauth status / oauth refresh", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getOAuthTokenStatus.mockReturnValue({
      secret_id: "secret-id-1",
      provider: "github",
      has_access_token: true,
      access_token_expires_at: 1_800_000_000_000,
      has_refresh_token: true,
      last_refreshed_at: null,
      refresh_status: "ok",
    });
    mockEngine.refreshOAuthToken.mockResolvedValue(1_800_000_000_000);
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
  });

  it("status prints token health for the resolved secret", async () => {
    await run(["status", "secret://gh-token"]);

    expect(mockEngine.getOAuthTokenStatus).toHaveBeenCalledWith("secret-id-1");
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining("github"));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining("ok"));
    expect(mockEngine.destroy).toHaveBeenCalled();
  });

  it("status --json prints the raw status object", async () => {
    await run(["status", "secret://gh-token", "--json"]);

    const printed = JSON.parse(logSpy.mock.calls[0]?.[0] as string) as Record<string, unknown>;
    expect(printed.refresh_status).toBe("ok");
    expect(printed.provider).toBe("github");
  });

  it("refresh calls engine.refreshOAuthToken and prints the new expiry", async () => {
    await run(["refresh", "secret://gh-token"]);

    expect(mockEngine.refreshOAuthToken).toHaveBeenCalledWith("secret-id-1");
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("OK: Token refreshed"));
    expect(mockEngine.destroy).toHaveBeenCalled();
  });

  it("refresh reports a provider that returns no expiry", async () => {
    mockEngine.refreshOAuthToken.mockResolvedValue(null);

    await run(["refresh", "secret://gh-token"]);

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("no expiry"));
  });

  it("a sealed vault renders the unlock guidance and exits 1", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(VaultError.vaultLocked());

    await expect(run(["status", "secret://gh-token"])).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Vault is locked"));
  });

  it("refresh surfaces an engine refresh failure via handleError", async () => {
    mockEngine.refreshOAuthToken.mockRejectedValueOnce(
      VaultError.oauthRefreshFailed("Token endpoint returned HTTP 401"),
    );

    await expect(run(["refresh", "secret://gh-token"])).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("OAUTH_REFRESH_FAILED"));
    expect(mockEngine.destroy).toHaveBeenCalled();
  });
});
