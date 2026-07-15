import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { runKeystoreHelper } from "./keystore-helper.js";
import {
  KeyringWrappingKeyStore,
  SecretServiceWrappingKeyStore,
  findLinuxKeystoreBinary,
} from "./linux-keystores.js";
import { KeystoreWrappedSessionKeyProtector } from "./wrapping-key-store.js";

describe("findLinuxKeystoreBinary", () => {
  it("resolves from /usr/bin first, then /bin", () => {
    expect(findLinuxKeystoreBinary("keyctl", (p) => p === "/usr/bin/keyctl")).toBe(
      "/usr/bin/keyctl",
    );
    expect(findLinuxKeystoreBinary("keyctl", (p) => p === "/bin/keyctl")).toBe("/bin/keyctl");
    expect(
      findLinuxKeystoreBinary("keyctl", (p) => p === "/usr/bin/keyctl" || p === "/bin/keyctl"),
    ).toBe("/usr/bin/keyctl");
  });

  it("returns null when the binary is absent (tier disabled, not an error)", () => {
    expect(findLinuxKeystoreBinary("secret-tool", () => false)).toBeNull();
  });
});

describe("Linux store construction", () => {
  it("reports the correct schemes", () => {
    expect(
      new SecretServiceWrappingKeyStore({ executablePath: "/usr/bin/secret-tool" }).scheme,
    ).toBe("secret-service");
    expect(new KeyringWrappingKeyStore({ executablePath: "/usr/bin/keyctl" }).scheme).toBe(
      "keyring",
    );
  });

  it("fails with SESSION_FILE_ERROR when the bridge binary is missing", async () => {
    for (const store of [
      new SecretServiceWrappingKeyStore({ executablePath: "/nonexistent/harpoc-test/secret-tool" }),
      new KeyringWrappingKeyStore({ executablePath: "/nonexistent/harpoc-test/keyctl" }),
    ]) {
      try {
        await store.loadWrappingKey();
        expect.unreachable("loadWrappingKey should have rejected");
      } catch (err) {
        expect(err).toBeInstanceOf(VaultError);
        expect((err as VaultError).code).toBe(ErrorCode.SESSION_FILE_ERROR);
      }
    }
  });
});

// A CI leg that provisions a tier exports HARPOC_REQUIRE_PLATFORM_TESTS with
// that tier's name: the probe failing is then a FAILURE, not a skip — a
// regressed provisioning step (missing keyutils/libsecret-tools, lost keyring
// possession, dead D-Bus) must not silently drop real-path coverage to zero
// while the leg stays green (review T3). Local dev (var unset) skips.
function tierRequired(tier: string): boolean {
  return (process.env["HARPOC_REQUIRE_PLATFORM_TESTS"] ?? "")
    .split(",")
    .map((t) => t.trim())
    .includes(tier);
}

function assertTierAvailable(tier: string, available: boolean, probeError: unknown): void {
  if (!available && tierRequired(tier)) {
    throw new Error(
      `HARPOC_REQUIRE_PLATFORM_TESTS demands the "${tier}" tier but its probe failed` +
        (probeError ? `: ${String(probeError)}` : ""),
    );
  }
}

// Thesis §4.6 real platform paths. Each tier probes its own availability —
// keyutils may be uninstalled, a Secret Service may not answer on headless
// hosts — and skips where the facility is absent, unless the tier is
// required via HARPOC_REQUIRE_PLATFORM_TESTS.
describe.runIf(process.platform === "linux")("KeyringWrappingKeyStore (Linux)", () => {
  const description = `harpoc:test-wrap:${process.pid}:${Date.now()}`;
  const executablePath = findLinuxKeystoreBinary("keyctl");
  let available = false;

  beforeAll(async () => {
    let probeError: unknown = executablePath ? undefined : "keyctl binary not found";
    if (executablePath) {
      try {
        const probe = new KeyringWrappingKeyStore({ executablePath, description });
        await probe.storeWrappingKey(new Uint8Array(randomBytes(32)));
        available = (await probe.loadWrappingKey()) !== null;
        if (!available) probeError = "read-back returned null";
      } catch (err) {
        probeError = err;
        available = false;
      }
    }
    assertTierAvailable("keyring", available, probeError);
  });

  afterAll(async () => {
    if (!executablePath) return;
    await runKeystoreHelper(executablePath, ["purge", "user", description], "", {
      label: "Keyring cleanup",
      expectZeroExit: false,
    }).catch(() => {});
  });

  it("roundtrips a session key with fresh blobs per wrap", async (ctx) => {
    if (!available) return ctx.skip();
    const protector = new KeystoreWrappedSessionKeyProtector(
      new KeyringWrappingKeyStore({ executablePath: executablePath as string, description }),
    );
    const key = new Uint8Array(randomBytes(32));

    const blob1 = await protector.protect(key);
    const blob2 = await protector.protect(key);
    expect(Buffer.from(blob1).equals(Buffer.from(blob2))).toBe(false);
    expect(Buffer.from(await protector.unprotect(blob1)).equals(Buffer.from(key))).toBe(true);
  });

  it("creates the key once and reuses it", async (ctx) => {
    if (!available) return ctx.skip();
    const store = new KeyringWrappingKeyStore({
      executablePath: executablePath as string,
      description,
    });
    const protector = new KeystoreWrappedSessionKeyProtector(store);

    await protector.protect(new Uint8Array(randomBytes(32)));
    const before = await store.loadWrappingKey();
    await protector.protect(new Uint8Array(randomBytes(32)));
    const after = await store.loadWrappingKey();

    expect(before).not.toBeNull();
    expect(Buffer.from(before as Uint8Array).equals(Buffer.from(after as Uint8Array))).toBe(true);
  });

  it("returns null for a missing key (clean miss, not an error)", async (ctx) => {
    if (!available) return ctx.skip();
    const store = new KeyringWrappingKeyStore({
      executablePath: executablePath as string,
      description: `${description}:absent`,
    });
    expect(await store.loadWrappingKey()).toBeNull();
  });

  it("rejects a tampered blob and unwraps across instances", async (ctx) => {
    if (!available) return ctx.skip();
    const key = new Uint8Array(randomBytes(32));
    const blob = await new KeystoreWrappedSessionKeyProtector(
      new KeyringWrappingKeyStore({ executablePath: executablePath as string, description }),
    ).protect(key);

    const fresh = new KeystoreWrappedSessionKeyProtector(
      new KeyringWrappingKeyStore({ executablePath: executablePath as string, description }),
    );
    expect(Buffer.from(await fresh.unprotect(blob)).equals(Buffer.from(key))).toBe(true);

    const tampered = new Uint8Array(blob);
    const index = Math.floor(tampered.length / 2);
    tampered[index] = (tampered[index] ?? 0) ^ 0xff;
    await expect(fresh.unprotect(tampered)).rejects.toThrow(VaultError);
  });
});

describe.runIf(process.platform === "linux")("SecretServiceWrappingKeyStore (Linux)", () => {
  const service = `harpoc.test-wrap.${process.pid}.${Date.now()}`;
  const executablePath = findLinuxKeystoreBinary("secret-tool");
  let available = false;

  beforeAll(async () => {
    let probeError: unknown = !executablePath
      ? "secret-tool binary not found"
      : (process.env["DBUS_SESSION_BUS_ADDRESS"] ?? "") === ""
        ? "no DBUS_SESSION_BUS_ADDRESS"
        : undefined;
    if (executablePath && probeError === undefined) {
      try {
        const probe = new SecretServiceWrappingKeyStore({ executablePath, service });
        await probe.storeWrappingKey(new Uint8Array(randomBytes(32)));
        available = (await probe.loadWrappingKey()) !== null;
        if (!available) probeError = "read-back returned null";
      } catch (err) {
        probeError = err;
        available = false;
      }
    }
    assertTierAvailable("secret-service", available, probeError);
  });

  afterAll(async () => {
    if (!executablePath) return;
    await runKeystoreHelper(
      executablePath,
      ["clear", "service", service, "account", "harpoc"],
      "",
      { label: "Secret Service cleanup", expectZeroExit: false },
    ).catch(() => {});
  });

  it("roundtrips a session key with fresh blobs per wrap", async (ctx) => {
    if (!available) return ctx.skip();
    const protector = new KeystoreWrappedSessionKeyProtector(
      new SecretServiceWrappingKeyStore({ executablePath: executablePath as string, service }),
    );
    const key = new Uint8Array(randomBytes(32));

    const blob1 = await protector.protect(key);
    const blob2 = await protector.protect(key);
    expect(Buffer.from(blob1).equals(Buffer.from(blob2))).toBe(false);
    expect(Buffer.from(await protector.unprotect(blob1)).equals(Buffer.from(key))).toBe(true);
  });

  it("creates the item once and reuses it", async (ctx) => {
    if (!available) return ctx.skip();
    const store = new SecretServiceWrappingKeyStore({
      executablePath: executablePath as string,
      service,
    });
    const protector = new KeystoreWrappedSessionKeyProtector(store);

    await protector.protect(new Uint8Array(randomBytes(32)));
    const before = await store.loadWrappingKey();
    await protector.protect(new Uint8Array(randomBytes(32)));
    const after = await store.loadWrappingKey();

    expect(before).not.toBeNull();
    expect(Buffer.from(before as Uint8Array).equals(Buffer.from(after as Uint8Array))).toBe(true);
  });

  it("returns null for a missing item (clean miss, not an error)", async (ctx) => {
    if (!available) return ctx.skip();
    const store = new SecretServiceWrappingKeyStore({
      executablePath: executablePath as string,
      service: `${service}.absent`,
    });
    expect(await store.loadWrappingKey()).toBeNull();
  });

  it("rejects a tampered blob and unwraps across instances", async (ctx) => {
    if (!available) return ctx.skip();
    const key = new Uint8Array(randomBytes(32));
    const blob = await new KeystoreWrappedSessionKeyProtector(
      new SecretServiceWrappingKeyStore({ executablePath: executablePath as string, service }),
    ).protect(key);

    const fresh = new KeystoreWrappedSessionKeyProtector(
      new SecretServiceWrappingKeyStore({ executablePath: executablePath as string, service }),
    );
    expect(Buffer.from(await fresh.unprotect(blob)).equals(Buffer.from(key))).toBe(true);

    const tampered = new Uint8Array(blob);
    const index = Math.floor(tampered.length / 2);
    tampered[index] = (tampered[index] ?? 0) ^ 0xff;
    await expect(fresh.unprotect(tampered)).rejects.toThrow(VaultError);
  });
});
