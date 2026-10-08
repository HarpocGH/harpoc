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

import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerOAuthStatusCommand } from "./status.js";
import { registerOAuthRefreshCommand } from "./refresh.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => {
    const oauth = program.command("oauth").description("OAuth");
    registerOAuthStatusCommand(oauth);
    registerOAuthRefreshCommand(oauth);
  },
  ["oauth"],
);

describe("oauth status / oauth refresh", () => {
  let spies: CliSpies;

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
      token_endpoint_auth_method: "client_secret_basic",
    });
    mockEngine.refreshOAuthToken.mockResolvedValue(1_800_000_000_000);
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("status prints token health for the resolved secret", async () => {
    await run(["status", "secret://gh-token"]);

    expect(mockEngine.getOAuthTokenStatus).toHaveBeenCalledWith(
      "secret-id-1",
      undefined,
      "secret://gh-token",
    );
    expect(spies.logSpy).toHaveBeenCalledWith(expect.stringContaining("github"));
    expect(spies.logSpy).toHaveBeenCalledWith(expect.stringContaining("ok"));
    expect(mockEngine.destroy).toHaveBeenCalled();
  });

  it("status --json prints the raw status object", async () => {
    await run(["status", "secret://gh-token", "--json"]);

    const printed = JSON.parse(spies.logSpy.mock.calls[0]?.[0] as string) as Record<
      string,
      unknown
    >;
    expect(printed.refresh_status).toBe("ok");
    expect(printed.provider).toBe("github");
    expect(printed.token_endpoint_auth_method).toBe("client_secret_basic");
  });

  it("status prints the configured token-endpoint auth method", async () => {
    await run(["status", "secret://gh-token"]);

    expect(spies.logSpy).toHaveBeenCalledWith(expect.stringContaining("client_secret_basic"));
  });

  it("refresh calls engine.refreshOAuthToken and prints the new expiry", async () => {
    await run(["refresh", "secret://gh-token"]);

    expect(mockEngine.refreshOAuthToken).toHaveBeenCalledWith(
      "secret-id-1",
      undefined,
      "secret://gh-token",
    );
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("OK: Token refreshed"));
    expect(mockEngine.destroy).toHaveBeenCalled();
  });

  it("refresh reports a provider that returns no expiry", async () => {
    mockEngine.refreshOAuthToken.mockResolvedValue(null);

    await run(["refresh", "secret://gh-token"]);

    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("no expiry"));
  });

  it("a sealed vault renders the unlock guidance and exits 1", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(VaultError.vaultLocked());

    await expect(run(["status", "secret://gh-token"])).rejects.toThrow("process.exit");

    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("Vault is locked"));
  });

  it("refresh surfaces an engine refresh failure via handleError", async () => {
    mockEngine.refreshOAuthToken.mockRejectedValueOnce(
      VaultError.oauthRefreshFailed("Token endpoint returned HTTP 401"),
    );

    await expect(run(["refresh", "secret://gh-token"])).rejects.toThrow("process.exit");

    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("OAUTH_REFRESH_FAILED"));
    expect(mockEngine.destroy).toHaveBeenCalled();
  });
});
