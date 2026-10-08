import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    listSecrets: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerSecretListCommand } from "./list.js";
import { buildCli, spyCli, tokenFixture, type CliSpies } from "../../__fixtures__/cli-harness.js";

const INFO = {
  handle: "secret://api-key",
  name: "api-key",
  type: "api_key",
  project: null,
  status: "active",
  version: 1,
  createdAt: 0,
  updatedAt: 0,
  expiresAt: null,
  rotatedAt: null,
};

describe("secret list — token path", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.listSecrets.mockReturnValue([
      { ...INFO, name: "db-key" },
      { ...INFO, name: "mail-key", handle: "secret://mail-key" },
    ]);
    mockEngine.verifyToken.mockReturnValue(tokenFixture());
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  const run = buildCli(
    (program) => registerSecretListCommand(program.command("secret")),
    ["secret", "list"],
  );

  it("tokenless path is unchanged", async () => {
    await run([]);
    expect(mockEngine.listSecrets).toHaveBeenCalledWith(undefined, undefined);
  });

  it("passes the caller and defaults the project filter to the token's project", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["list"], project: "api" }));
    await run(["--token", "jwt-value"]);
    expect(mockEngine.listSecrets).toHaveBeenCalledWith("api", {
      principal_type: "agent",
      principal_id: "agent-1",
      project: "api",
      interface: "cli",
    });
  });

  it("refuses a cross-project --project against a project-scoped token", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["list"], project: "api" }));
    await expect(run(["--project", "other", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("[ACCESS_DENIED]"));
    expect(mockEngine.listSecrets).not.toHaveBeenCalled();
  });

  it("treats --project '' as absent (H4) — the token's project still applies", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["list"], project: "api" }));
    await run(["--project", "", "--token", "jwt-value"]);
    expect(mockEngine.listSecrets).toHaveBeenCalledWith("api", expect.anything());
  });

  it('tokenless --project "" keeps its fail-closed empty filter (no normalization)', async () => {
    mockEngine.listSecrets.mockReturnValue([]);
    await run(["--project", ""]);
    expect(mockEngine.verifyToken).not.toHaveBeenCalled();
    expect(mockEngine.listSecrets).toHaveBeenCalledWith("", undefined);
  });

  it("filters results by the token's secret-name patterns", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["list"], secrets: ["db-*"] }));
    await run(["--json", "--token", "jwt-value"]);
    const printed = JSON.parse(
      (console.log as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0])).join("\n"),
    ) as Array<{ name: string }>;
    expect(printed.map((s) => s.name)).toEqual(["db-key"]);
  });
});
