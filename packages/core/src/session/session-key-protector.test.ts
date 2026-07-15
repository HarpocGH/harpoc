import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import {
  DpapiSessionKeyProtector,
  NoneSessionKeyProtector,
  createSessionKeyProtector,
} from "./session-key-protector.js";

describe("NoneSessionKeyProtector", () => {
  it("has scheme none and passes data through unchanged", async () => {
    const protector = new NoneSessionKeyProtector();
    const key = new Uint8Array(randomBytes(32));

    expect(protector.scheme).toBe("none");
    expect(await protector.protect(key)).toBe(key);
    expect(await protector.unprotect(key)).toBe(key);
  });
});

const noBinaries = (): boolean => false;
const probeOf =
  (...present: string[]) =>
  (path: string): boolean =>
    present.includes(path);
const DBUS_ENV = { DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus" };

describe("createSessionKeyProtector", () => {
  it("selects DPAPI on win32", () => {
    expect(createSessionKeyProtector("win32", {}).scheme).toBe("dpapi");
  });

  it("selects Keychain on darwin (security is OS-shipped)", () => {
    expect(createSessionKeyProtector("darwin", {}).scheme).toBe("keychain");
  });

  it("selects none on unsupported platforms (file-permission fallback)", () => {
    expect(createSessionKeyProtector("freebsd", {}, noBinaries).scheme).toBe("none");
    expect(createSessionKeyProtector("aix", {}, noBinaries).scheme).toBe("none");
  });

  it("linux: selects Secret Service when D-Bus and secret-tool are present", () => {
    expect(
      createSessionKeyProtector("linux", DBUS_ENV, probeOf("/usr/bin/secret-tool")).scheme,
    ).toBe("secret-service");
  });

  it("linux: falls back to the kernel keyring without a D-Bus session", () => {
    expect(
      createSessionKeyProtector("linux", {}, probeOf("/usr/bin/secret-tool", "/usr/bin/keyctl"))
        .scheme,
    ).toBe("keyring");
  });

  it("linux: falls back to the kernel keyring when secret-tool is absent", () => {
    expect(createSessionKeyProtector("linux", DBUS_ENV, probeOf("/usr/bin/keyctl")).scheme).toBe(
      "keyring",
    );
  });

  it("linux: resolves bridge binaries from /bin when /usr/bin is absent", () => {
    expect(createSessionKeyProtector("linux", DBUS_ENV, probeOf("/bin/secret-tool")).scheme).toBe(
      "secret-service",
    );
    expect(createSessionKeyProtector("linux", {}, probeOf("/bin/keyctl")).scheme).toBe("keyring");
  });

  it("linux: selects none when no bridge binary exists", () => {
    expect(createSessionKeyProtector("linux", DBUS_ENV, noBinaries).scheme).toBe("none");
  });

  it("linux: HARPOC_SESSION_KEYSTORE=off wins over available tiers", () => {
    expect(
      createSessionKeyProtector(
        "linux",
        { ...DBUS_ENV, HARPOC_SESSION_KEYSTORE: "off" },
        probeOf("/usr/bin/secret-tool", "/usr/bin/keyctl"),
      ).scheme,
    ).toBe("none");
  });

  it("darwin: HARPOC_SESSION_KEYSTORE=off wins over the Keychain", () => {
    expect(createSessionKeyProtector("darwin", { HARPOC_SESSION_KEYSTORE: "off" }).scheme).toBe(
      "none",
    );
  });

  it("HARPOC_SESSION_KEYSTORE=off disables the keystore (case-insensitive)", () => {
    expect(createSessionKeyProtector("win32", { HARPOC_SESSION_KEYSTORE: "off" }).scheme).toBe(
      "none",
    );
    expect(createSessionKeyProtector("win32", { HARPOC_SESSION_KEYSTORE: "OFF" }).scheme).toBe(
      "none",
    );
  });

  it("other HARPOC_SESSION_KEYSTORE values keep the platform default", () => {
    expect(createSessionKeyProtector("win32", { HARPOC_SESSION_KEYSTORE: "on" }).scheme).toBe(
      "dpapi",
    );
    expect(createSessionKeyProtector("win32", { HARPOC_SESSION_KEYSTORE: "" }).scheme).toBe(
      "dpapi",
    );
  });
});

describe.runIf(process.platform === "win32")("DpapiSessionKeyProtector (Windows)", () => {
  it("roundtrips a 32-byte key through DPAPI", async () => {
    const protector = new DpapiSessionKeyProtector();
    const key = new Uint8Array(randomBytes(32));

    const blob = await protector.protect(key);
    expect(blob.length).toBeGreaterThan(key.length);
    expect(Buffer.from(blob).equals(Buffer.from(key))).toBe(false);

    const unwrapped = await protector.unprotect(blob);
    expect(Buffer.from(unwrapped).equals(Buffer.from(key))).toBe(true);
  });

  it("produces different blobs for the same key (fresh randomness per wrap)", async () => {
    const protector = new DpapiSessionKeyProtector();
    const key = new Uint8Array(randomBytes(32));

    const blob1 = await protector.protect(key);
    const blob2 = await protector.protect(key);
    expect(Buffer.from(blob1).equals(Buffer.from(blob2))).toBe(false);
  });

  it("rejects a tampered blob", async () => {
    const protector = new DpapiSessionKeyProtector();
    const blob = await protector.protect(new Uint8Array(randomBytes(32)));
    const index = Math.floor(blob.length / 2);
    blob[index] = (blob[index] ?? 0) ^ 0xff;

    await expect(protector.unprotect(blob)).rejects.toThrow(VaultError);
  });

  it("rejects garbage input to unprotect", async () => {
    const protector = new DpapiSessionKeyProtector();
    await expect(protector.unprotect(new Uint8Array(randomBytes(64)))).rejects.toThrow(VaultError);
  });

  it("rejects empty input", async () => {
    const protector = new DpapiSessionKeyProtector();
    await expect(protector.protect(new Uint8Array(0))).rejects.toThrow(VaultError);
  });

  it("fails with SESSION_FILE_ERROR when the helper executable is missing", async () => {
    const protector = new DpapiSessionKeyProtector({
      executablePath: "C:\\nonexistent\\powershell.exe",
    });
    try {
      await protector.protect(new Uint8Array(randomBytes(32)));
      expect.unreachable("protect should have rejected");
    } catch (err) {
      expect(err).toBeInstanceOf(VaultError);
      expect((err as VaultError).code).toBe(ErrorCode.SESSION_FILE_ERROR);
    }
  });

  it("enforces the timeout", async () => {
    const protector = new DpapiSessionKeyProtector({ timeoutMs: 1 });
    await expect(protector.protect(new Uint8Array(randomBytes(32)))).rejects.toThrow(/timed out/);
  });
});
