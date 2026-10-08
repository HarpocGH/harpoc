import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

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

import { registerOAuthStatusCommand } from "./status.js";
import { registerOAuthRefreshCommand } from "./refresh.js";
import { resolveSecretId } from "../../utils/vault-loader.js";
import { buildCli, spyCli, tokenFixture, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => {
    const oauth = program.command("oauth").description("OAuth");
    registerOAuthStatusCommand(oauth);
    registerOAuthRefreshCommand(oauth);
  },
  ["oauth"],
);

describe("oauth status / refresh — token path", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
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
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("status requires read and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
    await run(["status", "secret://gh", "--token", "jwt-value"]);
    expect(mockEngine.getOAuthTokenStatus).toHaveBeenCalledWith(
      "sid-1",
      expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
      "secret://gh",
    );
  });

  it("refresh requires rotate and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["rotate"] }));
    await run(["refresh", "secret://gh", "--token", "jwt-value"]);
    expect(mockEngine.refreshOAuthToken).toHaveBeenCalledWith(
      "sid-1",
      expect.objectContaining({ interface: "cli" }),
      "secret://gh",
    );
  });

  it("scope refusals precede handle resolution; tokenless paths pass no caller", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
    await expect(run(["refresh", "secret://gh", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(mockEngine.refreshOAuthToken).not.toHaveBeenCalled();
    expect(resolveSecretId).not.toHaveBeenCalled();

    await run(["status", "secret://gh"]);
    expect(mockEngine.getOAuthTokenStatus).toHaveBeenLastCalledWith(
      "sid-1",
      undefined,
      "secret://gh",
    );
    await run(["refresh", "secret://gh"]);
    expect(mockEngine.refreshOAuthToken).toHaveBeenLastCalledWith(
      "sid-1",
      undefined,
      "secret://gh",
    );
  });
});
