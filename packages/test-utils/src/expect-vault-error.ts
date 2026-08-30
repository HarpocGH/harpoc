import { ErrorCode, VaultError } from "@harpoc/shared";
import { expect } from "vitest";

/**
 * Invoke `fn` once and assert it throws — or rejects with — a VaultError
 * carrying `code`; the error is returned for any further assertion.
 *
 * Replaces `try { await fn(); expect.fail() } catch (e) { expect(e.code)… }`:
 * that shape's `catch` swallowed its own `expect.fail` AssertionError, so an
 * unexpected success surfaced as "AssertionError is not a VaultError" — and a
 * second `expect(fn).toThrow(...)` would have invoked a side-effecting engine
 * call twice. Here the success check sits outside the `try`.
 */
export async function expectVaultError(fn: () => unknown, code: ErrorCode): Promise<VaultError> {
  let thrown: unknown;
  let succeeded = false;
  try {
    await fn();
    succeeded = true;
  } catch (err) {
    thrown = err;
  }
  if (succeeded) {
    expect.fail(`expected a VaultError with code ${code}, but the call succeeded`);
  }
  expect(thrown, `expected a VaultError with code ${code}`).toBeInstanceOf(VaultError);
  const error = thrown as VaultError;
  expect(error.code).toBe(code);
  return error;
}
