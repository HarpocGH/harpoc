import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    revokeToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { VaultError } from "@harpoc/shared";
import { registerAuthRevokeCommand } from "./revoke.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => registerAuthRevokeCommand(program.command("auth")),
  ["auth", "revoke"],
);

describe("auth revoke (registry-authoritative, R9/C33-A)", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("revokes by jti alone — no expiry, no token", async () => {
    await run(["some-jti"]);
    expect(mockEngine.revokeToken).toHaveBeenCalledWith("some-jti");
    expect(mockEngine.revokeToken.mock.calls[0]).toHaveLength(1);
    expect(mockEngine.destroy).toHaveBeenCalled();
  });

  it("ignores an ambient HARPOC_TOKEN entirely — the registry knows the expiry", async () => {
    process.env.HARPOC_TOKEN = "header.payload.signature";
    await run(["some-jti"]);
    expect(mockEngine.revokeToken).toHaveBeenCalledWith("some-jti");
    const warned = spies.errorSpy.mock.calls.some(
      (call) => typeof call[0] === "string" && call[0].startsWith("Warning:"),
    );
    expect(warned).toBe(false);
  });

  it("--token is an unknown option", async () => {
    await expect(run(["some-jti", "--token", "header.payload.signature"])).rejects.toMatchObject({
      code: "commander.unknownOption",
      exitCode: 1,
    });
    expect(mockEngine.revokeToken).not.toHaveBeenCalled();
  });

  it("surfaces the engine's refusal of an unknown jti", async () => {
    mockEngine.revokeToken.mockImplementationOnce(() => {
      throw VaultError.invalidInput("Unknown token jti: nope");
    });
    await expect(run(["nope"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("Unknown token jti: nope"));
    expect(mockEngine.destroy).toHaveBeenCalled();
  });
});
