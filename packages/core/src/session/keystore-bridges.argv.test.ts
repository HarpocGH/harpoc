import { beforeEach, describe, expect, it, vi } from "vitest";
import type { KeystoreHelperResult } from "./keystore-helper.js";

/**
 * T12: the property that makes the keystore bridges safe — "key material
 * crosses on stdin/stdout, never argv" — was pinned by nothing. The gated
 * real-path suites only check that a key round-trips, which a bridge passing
 * the hex key as a command-line argument does just as well, while making the
 * wrapping key readable by every local process through `ps`/`/proc`.
 *
 * The same goes for DPAPI's user binding: the CurrentUser scope and the
 * domain-separation entropy are what tie a blob to one account, and both could
 * be dropped without a test noticing.
 */

const calls: Array<{ executablePath: string; args: string[]; stdin: string; label: string }> = [];
let nextResult: KeystoreHelperResult = { stdout: "", stderr: "", exitCode: 0 };

vi.mock("./keystore-helper.js", () => ({
  runKeystoreHelper: vi.fn(
    (
      executablePath: string,
      args: readonly string[],
      stdinPayload: string,
      options: { label: string },
    ) => {
      calls.push({
        executablePath,
        args: [...args],
        stdin: stdinPayload,
        label: options.label,
      });
      return Promise.resolve(nextResult);
    },
  ),
}));

const { DpapiSessionKeyProtector } = await import("./session-key-protector.js");
const { KeychainWrappingKeyStore } = await import("./keychain-store.js");
const { SecretServiceWrappingKeyStore, KeyringWrappingKeyStore } =
  await import("./linux-keystores.js");

const KEY = new Uint8Array(32).fill(0xab);
const KEY_HEX = Buffer.from(KEY).toString("hex");
const KEY_B64 = Buffer.from(KEY).toString("base64");

beforeEach(() => {
  calls.length = 0;
  nextResult = { stdout: "", stderr: "", exitCode: 0 };
});

/** Everything a `ps` listing would show for the spawned bridge. */
function commandLine(call: { executablePath: string; args: string[] }): string {
  return [call.executablePath, ...call.args].join(" ");
}

describe("keystore bridges keep key material off the command line (T12)", () => {
  it("DPAPI protect: the key crosses on stdin, base64-encoded", async () => {
    nextResult = { stdout: KEY_B64, stderr: "", exitCode: 0 };
    const protector = new DpapiSessionKeyProtector({ executablePath: "powershell.exe" });

    await protector.protect(KEY);

    expect(calls).toHaveLength(1);
    const call = calls[0] as (typeof calls)[number];
    expect(call.stdin.trim()).toBe(KEY_B64);
    expect(commandLine(call)).not.toContain(KEY_B64);
    expect(commandLine(call)).not.toContain(KEY_HEX);
  });

  it("DPAPI unprotect: the wrapped blob crosses on stdin too", async () => {
    nextResult = { stdout: KEY_B64, stderr: "", exitCode: 0 };
    const protector = new DpapiSessionKeyProtector({ executablePath: "powershell.exe" });
    const blob = new Uint8Array([1, 2, 3, 4]);

    await protector.unprotect(blob);

    const call = calls[0] as (typeof calls)[number];
    expect(call.stdin.trim()).toBe(Buffer.from(blob).toString("base64"));
    expect(commandLine(call)).not.toContain(Buffer.from(blob).toString("base64"));
  });

  it("DPAPI binds the blob to the current user account with a fixed entropy", async () => {
    nextResult = { stdout: KEY_B64, stderr: "", exitCode: 0 };
    await new DpapiSessionKeyProtector({ executablePath: "powershell.exe" }).protect(KEY);

    const script = (calls[0] as (typeof calls)[number]).args.join(" ");
    expect(script).toContain("DataProtectionScope]::CurrentUser");
    expect(script).toContain("harpoc.session-key.v1");
    // LocalMachine would unwrap for every account on the host.
    expect(script).not.toContain("LocalMachine");
    // No cmdlets, no Add-Type: module auto-loading must never run.
    expect(script).not.toContain("Add-Type");
    expect((calls[0] as (typeof calls)[number]).args).toContain("-NoProfile");
  });

  it("Keychain write: the hex key rides the stdin command, not argv", async () => {
    const store = new KeychainWrappingKeyStore({ executablePath: "/usr/bin/security" });

    await store.storeWrappingKey(KEY);

    const call = calls[0] as (typeof calls)[number];
    expect(call.args).toEqual(["-i"]);
    expect(call.stdin).toContain(KEY_HEX);
    expect(commandLine(call)).not.toContain(KEY_HEX);
  });

  it("Secret Service write: the hex key is the stdin payload", async () => {
    const store = new SecretServiceWrappingKeyStore({ executablePath: "/usr/bin/secret-tool" });

    await store.storeWrappingKey(KEY);

    const call = calls[0] as (typeof calls)[number];
    expect(call.stdin).toBe(KEY_HEX);
    expect(commandLine(call)).not.toContain(KEY_HEX);
  });

  it("kernel keyring write: the hex key is the stdin payload", async () => {
    const store = new KeyringWrappingKeyStore({ executablePath: "/usr/bin/keyctl" });

    await store.storeWrappingKey(KEY);

    const call = calls[0] as (typeof calls)[number];
    expect(call.stdin).toBe(KEY_HEX);
    expect(commandLine(call)).not.toContain(KEY_HEX);
    // `keyctl add` would take the payload as an argument; `padd` reads stdin.
    expect(call.args[0]).toBe("padd");
  });

  it("reads never put key material on the command line either", async () => {
    nextResult = { stdout: KEY_HEX, stderr: "", exitCode: 0 };

    await new KeychainWrappingKeyStore({ executablePath: "/usr/bin/security" }).loadWrappingKey();
    await new SecretServiceWrappingKeyStore({
      executablePath: "/usr/bin/secret-tool",
    }).loadWrappingKey();

    for (const call of calls) {
      expect(commandLine(call)).not.toContain(KEY_HEX);
    }
    expect(calls.length).toBe(2);
  });

  it("control: the bridges do carry their non-secret parameters in argv", async () => {
    await new SecretServiceWrappingKeyStore({
      executablePath: "/usr/bin/secret-tool",
      service: "svc-name",
    }).storeWrappingKey(KEY);

    expect(commandLine(calls[0] as (typeof calls)[number])).toContain("svc-name");
  });
});
