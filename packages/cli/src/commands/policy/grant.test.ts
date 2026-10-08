import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    grantPolicy: vi.fn().mockReturnValue({
      id: "policy-1",
      principal_type: "agent",
      principal_id: "agent-1",
      permissions: ["read"],
      expires_at: null,
    }),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("secret-id-1"),
}));

import { ErrorCode, VaultError } from "@harpoc/shared";
import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerPolicyGrantCommand } from "./grant.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => registerPolicyGrantCommand(program.command("policy")),
  ["policy", "grant"],
);

describe("policy grant --principal-type validation", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("rejects an invalid principal type with a clean message and grants nothing", async () => {
    await expect(
      run([
        "secret://x",
        "--principal-type",
        "banana",
        "--principal-id",
        "a",
        "--permissions",
        "read",
        "--json",
      ]),
    ).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid principal type"));
    expect(mockEngine.grantPolicy).not.toHaveBeenCalled();
  });

  it.each(["agent", "tool", "project", "user"])("accepts principal type %s", async (type) => {
    await run([
      "secret://x",
      "--principal-type",
      type,
      "--principal-id",
      "a",
      "--permissions",
      "read",
      "--json",
    ]);
    expect(mockEngine.grantPolicy).toHaveBeenCalledWith(
      expect.objectContaining({ principalType: type }),
      "cli-user",
      undefined,
    );
  });

  it("refuses a non-integer --expires as an INVALID_INPUT envelope under --json (P1cF-2)", async () => {
    await expect(
      run([
        "secret://k",
        "--principal-type",
        "agent",
        "--principal-id",
        "a",
        "--permissions",
        "use",
        "--expires",
        "1.5",
        "--json",
      ]),
    ).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: "--expires must be a positive number of minutes",
    });
    expect(mockEngine.grantPolicy).not.toHaveBeenCalled();
  });

  it("--expires is parsed before the vault opens: a typo on a locked vault reports INVALID_INPUT (D1d-5)", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(
      new VaultError(ErrorCode.VAULT_LOCKED, "Vault is locked"),
    );
    try {
      await expect(
        run([
          "secret://k",
          "--principal-type",
          "agent",
          "--principal-id",
          "a",
          "--permissions",
          "use",
          "--expires",
          "5abc",
          "--json",
        ]),
      ).rejects.toThrow("process.exit");
      expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
        error: "INVALID_INPUT",
        message: "--expires must be a positive number of minutes",
      });
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    } finally {
      vi.mocked(loadUnlockedEngine).mockReset();
      vi.mocked(loadUnlockedEngine).mockResolvedValue(mockEngine as never);
    }
  });

  it("an invalid --principal-type is refused as an INVALID_INPUT envelope under --json (P1cF-2)", async () => {
    await expect(
      run([
        "secret://k",
        "--principal-type",
        "bogus",
        "--principal-id",
        "a",
        "--permissions",
        "use",
        "--json",
      ]),
    ).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: 'Invalid principal type: "bogus". Valid: agent, tool, project, user',
    });
    expect(mockEngine.grantPolicy).not.toHaveBeenCalled();
  });

  it("an unknown permission is refused as an INVALID_INPUT envelope under --json (P1cF-2)", async () => {
    await expect(
      run([
        "secret://k",
        "--principal-type",
        "agent",
        "--principal-id",
        "a",
        "--permissions",
        "bogus",
        "--json",
      ]),
    ).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: 'Invalid permission: "bogus". Valid: list, read, use, create, rotate, revoke, admin',
    });
    expect(mockEngine.grantPolicy).not.toHaveBeenCalled();
  });
});
