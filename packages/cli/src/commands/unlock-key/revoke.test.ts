import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VaultError } from "@harpoc/shared";

const { mockEngine, mockPromptPassword } = vi.hoisted(() => ({
  mockEngine: {
    unlock: vi.fn(),
    revokeUnlockKey: vi.fn(),
    destroy: vi.fn(),
  },
  mockPromptPassword: vi.fn(),
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  createEngine: vi.fn().mockReturnValue(mockEngine),
}));
vi.mock("../../utils/prompt.js", () => ({ promptPassword: mockPromptPassword }));

import { createEngine } from "../../utils/vault-loader.js";
import { registerUnlockKeyRevokeCommand } from "./revoke.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const PASSWORD = "revoke-master-pw-1";

const run = buildCli(
  (program) => registerUnlockKeyRevokeCommand(program.command("unlock-key")),
  ["unlock-key", "revoke"],
);

let spies: CliSpies;

beforeEach(() => {
  vi.clearAllMocks();
  mockPromptPassword.mockResolvedValue(PASSWORD);
  mockEngine.unlock.mockResolvedValue(undefined);
  mockEngine.revokeUnlockKey.mockResolvedValue(undefined);
  mockEngine.destroy.mockResolvedValue(undefined);
  spies = spyCli();
});

afterEach(() => {
  spies.restore();
});

describe("harpoc unlock-key revoke", () => {
  it("unlocks with the prompted password and revokes the slot", async () => {
    await run([]);

    expect(mockPromptPassword.mock.calls).toEqual([[]]);
    expect(vi.mocked(createEngine).mock.calls).toEqual([["/mock/.harpoc"]]);
    expect(mockEngine.unlock.mock.calls).toEqual([[PASSWORD]]);
    expect(mockEngine.revokeUnlockKey.mock.calls).toEqual([[]]);
    const [unlocked] = mockEngine.unlock.mock.invocationCallOrder;
    const [revoked] = mockEngine.revokeUnlockKey.mock.invocationCallOrder;
    const [destroyed] = mockEngine.destroy.mock.invocationCallOrder;
    expect(unlocked as number).toBeLessThan(revoked as number);
    expect(revoked as number).toBeLessThan(destroyed as number);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        "OK: Unlock key revoked: --unlock-key-file and --unlock-credential no longer unlock this vault.",
      ],
    ]);
    expect(spies.exitSpy).not.toHaveBeenCalled();
  });

  it("no enrolled key: UNLOCK_KEY_NOT_ENROLLED, exit 1, the engine destroyed", async () => {
    const refusal = VaultError.unlockKeyNotEnrolled();
    mockEngine.revokeUnlockKey.mockRejectedValueOnce(refusal);

    await expect(run([])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Error: [UNLOCK_KEY_NOT_ENROLLED] ${refusal.message}`],
    ]);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("a wrong password revokes nothing", async () => {
    mockEngine.unlock.mockRejectedValueOnce(VaultError.invalidPassword());

    await expect(run([])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([["Error: Invalid password."]]);
    expect(mockEngine.revokeUnlockKey).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });
});
