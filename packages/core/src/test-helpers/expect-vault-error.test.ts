import { ErrorCode, VaultError } from "@harpoc/shared";
import { describe, expect, it } from "vitest";
import { expectVaultError } from "./expect-vault-error.js";

describe("expectVaultError", () => {
  it("returns the VaultError when the call rejects with the expected code", async () => {
    const err = await expectVaultError(
      () => Promise.reject(VaultError.invalidInput("nope")),
      ErrorCode.INVALID_INPUT,
    );
    expect(err).toBeInstanceOf(VaultError);
    expect(err.message).toBe("nope");
  });

  it("captures a synchronous throw too", async () => {
    const err = await expectVaultError(() => {
      throw VaultError.invalidInput("sync");
    }, ErrorCode.INVALID_INPUT);
    expect(err.code).toBe(ErrorCode.INVALID_INPUT);
  });

  // The defect the old idiom had: `expect.fail` inside the `try` was swallowed
  // by its own `catch`, which then reported "AssertionError is not a
  // VaultError" instead of "the call succeeded".
  it("an unexpected success fails naming the success, not a type mismatch", async () => {
    await expect(expectVaultError(() => "fine", ErrorCode.INVALID_INPUT)).rejects.toThrow(
      /but the call succeeded/,
    );
  });

  it("a non-VaultError fails the instance assertion", async () => {
    await expect(
      expectVaultError(() => Promise.reject(new Error("plain")), ErrorCode.INVALID_INPUT),
    ).rejects.toThrow(/expected a VaultError/);
  });

  it("a VaultError with another code fails the code assertion", async () => {
    await expect(
      expectVaultError(
        () => Promise.reject(VaultError.invalidInput("x")),
        ErrorCode.SECRET_NOT_FOUND,
      ),
    ).rejects.toThrow();
  });

  it("invokes the function exactly once", async () => {
    let calls = 0;
    await expectVaultError(() => {
      calls += 1;
      throw VaultError.invalidInput("once");
    }, ErrorCode.INVALID_INPUT);
    expect(calls).toBe(1);
  });
});
