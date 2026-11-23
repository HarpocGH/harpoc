import { beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { runKeystoreHelper } from "./keystore-helper.js";
import { KeyringWrappingKeyStore, SecretServiceWrappingKeyStore } from "./linux-keystores.js";

vi.mock("./keystore-helper.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./keystore-helper.js")>();
  return { ...actual, runKeystoreHelper: vi.fn(actual.runKeystoreHelper) };
});

const HELPER_TEXT = "helper-text-marker-3f9c";

beforeEach(() => {
  vi.mocked(runKeystoreHelper).mockReset();
});

describe("the Linux stores' failures name the exit status, never what the helper wrote", () => {
  it("a Secret Service read failure names the exit status alone", async () => {
    vi.mocked(runKeystoreHelper).mockResolvedValueOnce({
      stdout: "",
      stderr: `secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY ${HELPER_TEXT}`,
      exitCode: 1,
    });

    const err = await expectVaultError(
      () =>
        new SecretServiceWrappingKeyStore({
          executablePath: "/usr/bin/secret-tool",
        }).loadWrappingKey(),
      ErrorCode.SESSION_FILE_ERROR,
    );
    expectAbsent(err.message, HELPER_TEXT);
    expect(err.message).toBe("Session file error: Secret Service read failed (exit 1)");
  });

  it("a kernel keyring search failure names the exit status alone", async () => {
    vi.mocked(runKeystoreHelper).mockResolvedValueOnce({
      stdout: "",
      stderr: `keyctl_search: Permission denied ${HELPER_TEXT}`,
      exitCode: 1,
    });

    const err = await expectVaultError(
      () => new KeyringWrappingKeyStore({ executablePath: "/usr/bin/keyctl" }).loadWrappingKey(),
      ErrorCode.SESSION_FILE_ERROR,
    );
    expectAbsent(err.message, HELPER_TEXT);
    expect(err.message).toBe("Session file error: Kernel keyring search failed (exit 1)");
  });
});
