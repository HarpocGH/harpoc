import { existsSync } from "node:fs";
import { join } from "node:path";
import type { SessionKeyProtectionScheme } from "@harpoc/shared";
import { VaultError } from "@harpoc/shared";
import { wipeBuffer } from "../crypto/random.js";
import { runKeystoreHelper } from "./keystore-helper.js";
import { KeychainWrappingKeyStore } from "./keychain-store.js";
import {
  KeyringWrappingKeyStore,
  SecretServiceWrappingKeyStore,
  findLinuxKeystoreBinary,
} from "./linux-keystores.js";
import { KeystoreWrappedSessionKeyProtector } from "./wrapping-key-store.js";

/**
 * Wraps the session key with an OS-user-bound secret from the platform key
 * store (thesis §4.6 off-host session-file hardening) so that a session file
 * copied off the host is inert. Implementations must never place key material
 * in error messages or logs.
 */
export interface SessionKeyProtector {
  readonly scheme: SessionKeyProtectionScheme;
  /** Wrap a raw session key into an opaque, user-bound blob. */
  protect(key: Uint8Array): Promise<Uint8Array>;
  /** Unwrap a blob produced by protect(). Rejects if the blob cannot be unwrapped. */
  unprotect(blob: Uint8Array): Promise<Uint8Array>;
}

/**
 * Identity protector — the session key is stored raw and guarded by file
 * permissions alone (the pre-keystore behavior, and the fallback on platforms
 * without an implemented key store).
 */
export class NoneSessionKeyProtector implements SessionKeyProtector {
  readonly scheme = "none" as const;

  async protect(key: Uint8Array): Promise<Uint8Array> {
    return key;
  }

  async unprotect(blob: Uint8Array): Promise<Uint8Array> {
    return blob;
  }
}

/**
 * DPAPI secondary entropy: a fixed domain-separation constant, not a secret.
 * It prevents a generic same-user DPAPI unwrap tool from decoding the blob
 * without knowing the application constant; the user-account binding itself
 * comes from DPAPI's CurrentUser scope.
 */
const DPAPI_ENTROPY = "harpoc.session-key.v1";

/** .NET Framework GAC strong name — powershell.exe (5.1) is pinned below, where this identity is guaranteed. */
const DPAPI_ASSEMBLY =
  "System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

/**
 * The helper script uses only fully-qualified BCL static calls — no cmdlets and
 * no Add-Type — so module auto-loading never runs and PSModulePath cannot
 * influence execution. Data crosses as base64 on stdin/stdout, never argv.
 */
function dpapiScript(method: "Protect" | "Unprotect"): string {
  return (
    "$ErrorActionPreference='Stop';" +
    `[void][System.Reflection.Assembly]::Load('${DPAPI_ASSEMBLY}');` +
    "$d=[System.Convert]::FromBase64String([System.Console]::In.ReadToEnd().Trim());" +
    `$e=[System.Text.Encoding]::UTF8.GetBytes('${DPAPI_ENTROPY}');` +
    `$o=[System.Security.Cryptography.ProtectedData]::${method}($d,$e,[System.Security.Cryptography.DataProtectionScope]::CurrentUser);` +
    "[System.Array]::Clear($d,0,$d.Length);" +
    "[System.Console]::Out.Write([System.Convert]::ToBase64String($o));" +
    "[System.Array]::Clear($o,0,$o.Length)"
  );
}

function defaultPowershellPath(): string {
  const systemRoot = process.env["SystemRoot"] ?? "C:\\Windows";
  return join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

export interface DpapiSessionKeyProtectorOptions {
  /** Path to powershell.exe (default: pinned %SystemRoot% Windows PowerShell 5.1 path). */
  executablePath?: string;
  /** Kill the helper and reject after this many milliseconds (default 15000). */
  timeoutMs?: number;
}

/**
 * Windows DPAPI protector. Wraps the session key via
 * `ProtectedData.Protect(..., DataProtectionScope.CurrentUser)` — the OS-shipped
 * Windows PowerShell host is used as the DPAPI bridge (spawned with `shell:false`
 * from a pinned absolute path) so no native addon dependency is introduced.
 */
export class DpapiSessionKeyProtector implements SessionKeyProtector {
  readonly scheme = "dpapi" as const;
  private readonly executablePath: string;
  private readonly timeoutMs: number | undefined;

  constructor(options: DpapiSessionKeyProtectorOptions = {}) {
    this.executablePath = options.executablePath ?? defaultPowershellPath();
    this.timeoutMs = options.timeoutMs;
  }

  async protect(key: Uint8Array): Promise<Uint8Array> {
    return this.run("Protect", key);
  }

  async unprotect(blob: Uint8Array): Promise<Uint8Array> {
    return this.run("Unprotect", blob);
  }

  private async run(method: "Protect" | "Unprotect", input: Uint8Array): Promise<Uint8Array> {
    if (input.length === 0) {
      throw VaultError.sessionFileError(`DPAPI ${method} requires non-empty input`);
    }

    const inputCopy = Buffer.from(input);
    const payload = inputCopy.toString("base64");
    wipeBuffer(inputCopy);

    const options: Parameters<typeof runKeystoreHelper>[3] = { label: `DPAPI ${method}` };
    if (this.timeoutMs !== undefined) {
      options.timeoutMs = this.timeoutMs;
    }
    const result = await runKeystoreHelper(
      this.executablePath,
      ["-NoProfile", "-NonInteractive", "-Command", dpapiScript(method)],
      payload,
      options,
    );

    const text = result.stdout.trim();
    if (!BASE64_PATTERN.test(text)) {
      throw VaultError.sessionFileError(`DPAPI ${method} returned malformed output`);
    }
    return new Uint8Array(Buffer.from(text, "base64"));
  }
}

/**
 * Select the platform protector (thesis §4.6): DPAPI on Windows, Keychain on
 * macOS, Secret Service or the kernel keyring on Linux (two tiers, picked once
 * at construction — see below), none elsewhere (file-permission fallback).
 * `HARPOC_SESSION_KEYSTORE=off` disables keystore wrapping for new session
 * writes (operational opt-out; an already-wrapped file then fails closed and
 * requires a fresh unlock).
 *
 * Linux tier selection is factory-time and synchronous: Secret Service iff a
 * D-Bus session address is present AND `secret-tool` exists at a fixed
 * candidate path; else the kernel keyring iff `keyctl` exists; else none. A
 * runtime failure of the selected tier degrades through the existing
 * write-fallback — never a mid-write cascade to the other tier.
 */
export function createSessionKeyProtector(
  platform: NodeJS.Platform = process.platform,
  env: Record<string, string | undefined> = process.env,
  probeBinary: (path: string) => boolean = existsSync,
): SessionKeyProtector {
  if ((env["HARPOC_SESSION_KEYSTORE"] ?? "").toLowerCase() === "off") {
    return new NoneSessionKeyProtector();
  }
  if (platform === "win32") {
    return new DpapiSessionKeyProtector();
  }
  if (platform === "darwin") {
    return new KeystoreWrappedSessionKeyProtector(new KeychainWrappingKeyStore());
  }
  if (platform === "linux") {
    const secretTool = findLinuxKeystoreBinary("secret-tool", probeBinary);
    if ((env["DBUS_SESSION_BUS_ADDRESS"] ?? "") !== "" && secretTool) {
      return new KeystoreWrappedSessionKeyProtector(
        new SecretServiceWrappingKeyStore({ executablePath: secretTool }),
      );
    }
    const keyctl = findLinuxKeystoreBinary("keyctl", probeBinary);
    if (keyctl) {
      return new KeystoreWrappedSessionKeyProtector(
        new KeyringWrappingKeyStore({ executablePath: keyctl }),
      );
    }
    return new NoneSessionKeyProtector();
  }
  return new NoneSessionKeyProtector();
}
