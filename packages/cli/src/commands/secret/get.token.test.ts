import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    getSecretInfo: vi.fn(),
    getSecretValue: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerSecretGetCommand } from "./get.js";
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

describe("secret get — token path", () => {
  let spies: CliSpies;
  let stdoutWriteSpy: MockInstance;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getSecretInfo.mockResolvedValue(INFO);
    mockEngine.getSecretValue.mockResolvedValue(new TextEncoder().encode("v"));
    mockEngine.verifyToken.mockReturnValue(tokenFixture());
    spies = spyCli();
    stdoutWriteSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    spies.restore();
    stdoutWriteSpy.mockRestore();
  });

  const run = buildCli(
    (program) => registerSecretGetCommand(program.command("secret")),
    ["secret", "get"],
  );

  it("tokenless path is unchanged: no verify, no caller", async () => {
    await run(["secret://api-key"]);
    expect(mockEngine.verifyToken).not.toHaveBeenCalled();
    expect(mockEngine.getSecretInfo).toHaveBeenCalledWith("secret://api-key", undefined);
  });

  it("info read passes the cli caller under read scope", async () => {
    await run(["secret://api-key", "--token", "jwt-value"]);
    expect(mockEngine.getSecretInfo).toHaveBeenCalledWith("secret://api-key", {
      principal_type: "agent",
      principal_id: "agent-1",
      interface: "cli",
    });
  });

  it("--value passes the cli caller under read scope (design decision 3)", async () => {
    await run(["secret://api-key", "--value", "--token", "jwt-value"]);
    expect(mockEngine.getSecretValue).toHaveBeenCalledWith("secret://api-key", {
      principal_type: "agent",
      principal_id: "agent-1",
      interface: "cli",
    });
  });

  it("a use-scoped token is refused before any engine read", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["use"] }));
    await expect(run(["secret://api-key", "--value", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("[ACCESS_DENIED]"));
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(mockEngine.getSecretValue).not.toHaveBeenCalled();
    expect(mockEngine.getSecretInfo).not.toHaveBeenCalled();
  });

  it("reads an ambient HARPOC_TOKEN and refuses an empty one", async () => {
    process.env.HARPOC_TOKEN = "env-jwt";
    await run(["secret://api-key"]);
    expect(mockEngine.verifyToken).toHaveBeenCalledWith("env-jwt");

    process.env.HARPOC_TOKEN = "";
    await expect(run(["secret://api-key"])).rejects.toThrow("process.exit");
  });
});
