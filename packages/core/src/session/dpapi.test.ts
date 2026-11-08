import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { system32Path } from "../win32-paths.js";
import {
  UNLOCK_KEY_DPAPI_ENTROPY,
  dpapiBlobScope,
  dpapiProtect,
  dpapiScript,
  dpapiUnprotect,
} from "./dpapi.js";
import { runKeystoreHelper } from "./keystore-helper.js";
import { DpapiSessionKeyProtector } from "./session-key-protector.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./keystore-helper.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./keystore-helper.js")>();
  return { ...actual, runKeystoreHelper: vi.fn(actual.runKeystoreHelper) };
});

const LABEL = { label: "DPAPI test" };

beforeEach(() => {
  vi.resetAllMocks();
});

/** A version-1 blob header of `length` bytes whose flags word (byte 40) is `flags`. */
function header(length: number, flags: number, version = 1): Uint8Array {
  const bytes = new Uint8Array(length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, version, true);
  view.setUint32(40, flags, true);
  return bytes;
}

describe("dpapiScript", () => {
  it.each(["Protect", "Unprotect"] as const)(
    "%s: BCL calls only at CurrentUser scope with the given entropy, a refusal exit, never LocalMachine, no cmdlet",
    (method) => {
      const script = dpapiScript(method, UNLOCK_KEY_DPAPI_ENTROPY);
      expect(script).toContain(`[System.Security.Cryptography.ProtectedData]::${method}(`);
      expect(script).toContain("[System.Security.Cryptography.DataProtectionScope]::CurrentUser");
      expect(script).toContain(`GetBytes('${UNLOCK_KEY_DPAPI_ENTROPY}')`);
      expect(script).toContain("exit 3");
      expect(script.includes("LocalMachine")).toBe(false);
      expect(/Add-Type|Import-Module|Get-|Set-|Write-Host/.test(script)).toBe(false);
    },
  );

  it("the unlock key's entropy is its own, not the session key's", () => {
    expect(UNLOCK_KEY_DPAPI_ENTROPY).toBe("harpoc.unlock-key.v1");
  });
});

describe("dpapiBlobScope", () => {
  it("reads the scope from the header's flags word and refuses what is no DPAPI blob", () => {
    expect(dpapiBlobScope(header(262, 0))).toBe("user");
    expect(dpapiBlobScope(header(262, 0x4))).toBe("machine");
    expect(dpapiBlobScope(header(262, 0x20000004))).toBe("machine");
    expect(dpapiBlobScope(header(44, 0).subarray(0, 43))).toBeUndefined();
    expect(dpapiBlobScope(header(262, 0, 2))).toBeUndefined();
    expect(dpapiBlobScope(new Uint8Array(32))).toBeUndefined();
  });

  it("reads a view at an offset into a larger buffer", () => {
    const outer = new Uint8Array(300);
    outer.set(header(262, 0x4), 7);
    expect(dpapiBlobScope(outer.subarray(7, 269))).toBe("machine");
  });
});

// Every leg: the helper is never spawned (the input check) or answers through the mock.
describe("the DPAPI bridge's input check and helper failures", () => {
  it("an entropy that is not a plain identifier is refused INVALID_INPUT before any helper runs", async () => {
    const unseal = await expectVaultError(
      () => dpapiUnprotect(new Uint8Array(randomBytes(262)), "x');exit 0;('", LABEL),
      ErrorCode.INVALID_INPUT,
    );
    expect(unseal.message).toBe(
      "DPAPI entropy is not a plain identifier (letters, digits, ., _ and -)",
    );
    await expectVaultError(
      () => dpapiProtect(new Uint8Array(randomBytes(32)), "it's", LABEL),
      ErrorCode.INVALID_INPUT,
    );
    expect(vi.mocked(runKeystoreHelper)).not.toHaveBeenCalled();
  });

  it("a helper exit other than 0 or 3 rejects SESSION_FILE_ERROR naming the exit", async () => {
    vi.mocked(runKeystoreHelper).mockResolvedValueOnce({ stdout: "", stderr: "", exitCode: 1 });
    const error = await expectVaultError(
      () => dpapiUnprotect(new Uint8Array(randomBytes(262)), UNLOCK_KEY_DPAPI_ENTROPY, LABEL),
      ErrorCode.SESSION_FILE_ERROR,
    );
    expect(error.message).toBe("Session file error: DPAPI test failed (exit 1)");
  });

  it("helper output that is not base64 rejects SESSION_FILE_ERROR as malformed", async () => {
    vi.mocked(runKeystoreHelper).mockResolvedValueOnce({
      stdout: "not base64!",
      stderr: "",
      exitCode: 0,
    });
    const error = await expectVaultError(
      () => dpapiProtect(new Uint8Array(randomBytes(32)), UNLOCK_KEY_DPAPI_ENTROPY, LABEL),
      ErrorCode.SESSION_FILE_ERROR,
    );
    expect(error.message).toBe("Session file error: DPAPI test returned malformed output");
  });
});

describe.runIf(process.platform === "win32")("the DPAPI bridge (Windows)", () => {
  it("seals 32 bytes under this account and unseals them in a fresh helper process", async () => {
    const key = new Uint8Array(randomBytes(32));
    const blob = await dpapiProtect(key, UNLOCK_KEY_DPAPI_ENTROPY, LABEL);
    expect(blob.length).toBeGreaterThan(key.length);
    expect(dpapiBlobScope(blob)).toBe("user");
    const unsealed = await dpapiUnprotect(blob, UNLOCK_KEY_DPAPI_ENTROPY, LABEL);
    expect(unsealed !== undefined && Buffer.from(unsealed).equals(Buffer.from(key))).toBe(true);
  });

  it("a blob sealed with another entropy is refused: undefined, nothing thrown", async () => {
    const blob = await dpapiProtect(new Uint8Array(randomBytes(32)), "another.use.v1", LABEL);
    expect(await dpapiUnprotect(blob, UNLOCK_KEY_DPAPI_ENTROPY, LABEL)).toBeUndefined();
  });

  it("the session key protector's blob does not unseal as an unlock key", async () => {
    const blob = await new DpapiSessionKeyProtector().protect(new Uint8Array(randomBytes(32)));
    expect(await dpapiUnprotect(blob, UNLOCK_KEY_DPAPI_ENTROPY, LABEL)).toBeUndefined();
  });

  it("an unlock key blob does not unseal as a session key: the protector refuses SESSION_FILE_ERROR", async () => {
    const blob = await dpapiProtect(
      new Uint8Array(randomBytes(32)),
      UNLOCK_KEY_DPAPI_ENTROPY,
      LABEL,
    );
    await expectVaultError(
      () => new DpapiSessionKeyProtector().unprotect(blob),
      ErrorCode.SESSION_FILE_ERROR,
    );
  });

  it("random bytes the size of a blob are refused: undefined", async () => {
    expect(
      await dpapiUnprotect(new Uint8Array(randomBytes(262)), UNLOCK_KEY_DPAPI_ENTROPY, LABEL),
    ).toBeUndefined();
  });

  it("a LocalMachine blob reads as machine scope (its header's 0x4 flag)", () => {
    const run = spawnSync(
      system32Path("WindowsPowerShell", "v1.0", "powershell.exe"),
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "[void][System.Reflection.Assembly]::Load('System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a');" +
          "[System.Console]::Out.Write([System.Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Protect((New-Object byte[] 32),$null,[System.Security.Cryptography.DataProtectionScope]::LocalMachine)))",
      ],
      { shell: false, windowsHide: true, encoding: "utf8", timeout: 15_000 },
    );
    expect(run.status).toBe(0);
    expect(dpapiBlobScope(new Uint8Array(Buffer.from(run.stdout.trim(), "base64")))).toBe(
      "machine",
    );
  });

  it("empty input is refused SESSION_FILE_ERROR before any helper runs", async () => {
    await expectVaultError(
      () => dpapiUnprotect(new Uint8Array(0), UNLOCK_KEY_DPAPI_ENTROPY, LABEL),
      ErrorCode.SESSION_FILE_ERROR,
    );
  });

  it("a missing helper executable rejects SESSION_FILE_ERROR", async () => {
    await expectVaultError(
      () =>
        dpapiProtect(new Uint8Array(randomBytes(32)), UNLOCK_KEY_DPAPI_ENTROPY, {
          ...LABEL,
          executablePath: "C:\\nonexistent\\powershell.exe",
        }),
      ErrorCode.SESSION_FILE_ERROR,
    );
  });
});
