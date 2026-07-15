import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { KeychainWrappingKeyStore } from "./keychain-store.js";
import { runKeystoreHelper } from "./keystore-helper.js";
import { KeystoreWrappedSessionKeyProtector } from "./wrapping-key-store.js";

describe("KeychainWrappingKeyStore construction", () => {
  it("has scheme keychain", () => {
    expect(new KeychainWrappingKeyStore().scheme).toBe("keychain");
  });

  it("rejects service/account/keychain values outside the safe charset", () => {
    expect(() => new KeychainWrappingKeyStore({ service: "has space" })).toThrow(VaultError);
    expect(() => new KeychainWrappingKeyStore({ account: 'quo"te' })).toThrow(VaultError);
    expect(() => new KeychainWrappingKeyStore({ keychain: "/tmp/a b.keychain" })).toThrow(
      VaultError,
    );
  });

  it("fails with SESSION_FILE_ERROR when the security binary is missing", async () => {
    const store = new KeychainWrappingKeyStore({
      executablePath: "/nonexistent/harpoc-test/security",
    });
    try {
      await store.loadWrappingKey();
      expect.unreachable("loadWrappingKey should have rejected");
    } catch (err) {
      expect(err).toBeInstanceOf(VaultError);
      expect((err as VaultError).code).toBe(ErrorCode.SESSION_FILE_ERROR);
    }
  });
});

// A CI leg that provisions a tier exports HARPOC_REQUIRE_PLATFORM_TESTS with
// that tier's name: the probe failing is then a FAILURE, not a skip — a
// regressed provisioning step must not silently drop real-path coverage to
// zero while the leg stays green (review T3). Local dev (var unset) skips.
function tierRequired(tier: string): boolean {
  return (process.env["HARPOC_REQUIRE_PLATFORM_TESTS"] ?? "")
    .split(",")
    .map((t) => t.trim())
    .includes(tier);
}

// Thesis §4.6 real platform path. Runs on macOS only, and only where a usable
// keychain answers (CI provisions a disposable unlocked keychain and exports
// HARPOC_TEST_KEYCHAIN; a locked/headless keychain skips — unless the tier is
// required via HARPOC_REQUIRE_PLATFORM_TESTS).
describe.runIf(process.platform === "darwin")("KeychainWrappingKeyStore (macOS)", () => {
  const service = `harpoc.test-wrap.${process.pid}.${Date.now()}`;
  const keychain = process.env["HARPOC_TEST_KEYCHAIN"];
  const storeOptions = (): ConstructorParameters<typeof KeychainWrappingKeyStore>[0] => ({
    service,
    ...(keychain ? { keychain } : {}),
  });
  let available = false;

  beforeAll(async () => {
    let probeError: unknown;
    try {
      const probe = new KeychainWrappingKeyStore(storeOptions());
      await probe.storeWrappingKey(new Uint8Array(randomBytes(32)));
      available = (await probe.loadWrappingKey()) !== null;
    } catch (err) {
      probeError = err;
      available = false;
    }
    if (!available && tierRequired("keychain")) {
      throw new Error(
        `HARPOC_REQUIRE_PLATFORM_TESTS demands the "keychain" tier but its probe failed` +
          (probeError ? `: ${String(probeError)}` : " (read-back returned null)"),
      );
    }
  });

  afterAll(async () => {
    // Best-effort cleanup of the throwaway item.
    await runKeystoreHelper(
      "/usr/bin/security",
      ["-i"],
      `delete-generic-password -s ${service} -a harpoc${keychain ? ` ${keychain}` : ""}\n`,
      { label: "Keychain cleanup", expectZeroExit: false },
    ).catch(() => {});
  });

  it("roundtrips a session key with fresh blobs per wrap", async (ctx) => {
    if (!available) return ctx.skip();
    const protector = new KeystoreWrappedSessionKeyProtector(
      new KeychainWrappingKeyStore(storeOptions()),
    );
    const key = new Uint8Array(randomBytes(32));

    const blob1 = await protector.protect(key);
    const blob2 = await protector.protect(key);
    expect(Buffer.from(blob1).equals(Buffer.from(blob2))).toBe(false);
    expect(Buffer.from(await protector.unprotect(blob1)).equals(Buffer.from(key))).toBe(true);
  });

  it("creates the keychain item once and reuses it", async (ctx) => {
    if (!available) return ctx.skip();
    const store = new KeychainWrappingKeyStore(storeOptions());
    const protector = new KeystoreWrappedSessionKeyProtector(store);

    await protector.protect(new Uint8Array(randomBytes(32)));
    const before = await store.loadWrappingKey();
    await protector.protect(new Uint8Array(randomBytes(32)));
    const after = await store.loadWrappingKey();

    expect(before).not.toBeNull();
    expect(Buffer.from(before as Uint8Array).equals(Buffer.from(after as Uint8Array))).toBe(true);
  });

  it("rejects a tampered blob", async (ctx) => {
    if (!available) return ctx.skip();
    const protector = new KeystoreWrappedSessionKeyProtector(
      new KeychainWrappingKeyStore(storeOptions()),
    );
    const blob = await protector.protect(new Uint8Array(randomBytes(32)));
    const index = Math.floor(blob.length / 2);
    blob[index] = (blob[index] ?? 0) ^ 0xff;
    await expect(protector.unprotect(blob)).rejects.toThrow(VaultError);
  });

  it("unwraps across protector instances (the key lives in the keychain)", async (ctx) => {
    if (!available) return ctx.skip();
    const key = new Uint8Array(randomBytes(32));
    const blob = await new KeystoreWrappedSessionKeyProtector(
      new KeychainWrappingKeyStore(storeOptions()),
    ).protect(key);

    const fresh = new KeystoreWrappedSessionKeyProtector(
      new KeychainWrappingKeyStore(storeOptions()),
    );
    expect(Buffer.from(await fresh.unprotect(blob)).equals(Buffer.from(key))).toBe(true);
  });

  it("returns null for a missing item (clean miss, not an error)", async (ctx) => {
    if (!available) return ctx.skip();
    const store = new KeychainWrappingKeyStore({
      ...storeOptions(),
      service: `${service}.absent`,
    });
    expect(await store.loadWrappingKey()).toBeNull();
  });

  it("enforces the timeout", async (ctx) => {
    if (!available) return ctx.skip();
    const store = new KeychainWrappingKeyStore({ ...storeOptions(), timeoutMs: 1 });
    await expect(store.loadWrappingKey()).rejects.toThrow(/timed out/);
  });
});
