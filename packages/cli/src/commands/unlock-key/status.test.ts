import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VaultError } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    unlockKeyStatus: vi.fn(),
    destroy: vi.fn(),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerUnlockKeyStatusCommand } from "./status.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const ENROLLED_AT = "2026-11-07T09:30:00.000Z";

const run = buildCli(
  (program) => registerUnlockKeyStatusCommand(program.command("unlock-key")),
  ["unlock-key", "status"],
);

let spies: CliSpies;

beforeEach(() => {
  vi.clearAllMocks();
  mockEngine.unlockKeyStatus.mockResolvedValue({ enrolled: true, enrolledAt: ENROLLED_AT });
  mockEngine.destroy.mockResolvedValue(undefined);
  spies = spyCli();
});

afterEach(() => {
  spies.restore();
});

describe("harpoc unlock-key status", () => {
  it("reports an enrolled key and its date on stdout from the unlocked vault", async () => {
    await run([]);

    expect(vi.mocked(loadUnlockedEngine).mock.calls).toEqual([["/mock/.harpoc"]]);
    expect(mockEngine.unlockKeyStatus.mock.calls).toEqual([[]]);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
    expect(spies.logSpy.mock.calls).toEqual([
      ["Enrolled     yes"],
      [`Enrolled at  ${ENROLLED_AT}`],
    ]);
    expect(spies.errorSpy).not.toHaveBeenCalled();
  });

  it("reports no enrolled key", async () => {
    mockEngine.unlockKeyStatus.mockResolvedValueOnce({ enrolled: false });

    await run([]);

    expect(spies.logSpy.mock.calls).toEqual([["Enrolled     no"], ["Enrolled at  -"]]);
  });

  it.each([
    { status: { enrolled: true, enrolledAt: ENROLLED_AT } },
    { status: { enrolled: false } },
  ])("--json prints the engine's status object as it is: $status", async ({ status }) => {
    mockEngine.unlockKeyStatus.mockResolvedValueOnce(status);

    await run(["--json"]);

    expect(spies.logSpy.mock.calls).toEqual([[JSON.stringify(status, null, 2)]]);
    expect(spies.errorSpy).not.toHaveBeenCalled();
  });

  it("a locked vault is VAULT_LOCKED through the --json envelope", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(VaultError.vaultLocked());

    await expect(run(["--json"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [JSON.stringify({ error: "VAULT_LOCKED", message: "Vault is locked" })],
    ]);
    expect(mockEngine.unlockKeyStatus).not.toHaveBeenCalled();
  });
});
