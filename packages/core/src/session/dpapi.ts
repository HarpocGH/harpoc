import { VaultError } from "@harpoc/shared";
import { wipeBuffer } from "../crypto/random.js";
import { system32Path } from "../win32-paths.js";
import { runKeystoreHelper } from "./keystore-helper.js";
import type { RunKeystoreHelperOptions } from "./keystore-helper.js";

/**
 * DPAPI secondary entropy of the sealed unlock key: a domain-separation constant, not a
 * secret. A blob sealed for another use under the same account (the session key's
 * `harpoc.session-key.v1`, or no entropy at all) does not unseal as an unlock key, and an
 * unlock key blob does not unseal through a generic same-account call without it.
 */
export const UNLOCK_KEY_DPAPI_ENTROPY = "harpoc.unlock-key.v1";

/** .NET Framework GAC strong name — the pinned powershell.exe (5.1) guarantees this identity. */
const DPAPI_ASSEMBLY =
  "System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

/** The helper's exit status when `ProtectedData` refuses the input (another account's blob, another entropy, damage, no master key). */
const DPAPI_REFUSED_EXIT = 3;

/**
 * The DPAPI blob header (version-1 blobs): a `dwVersion` of 1, the provider GUID, the
 * master-key version and GUID, then the `dwFlags` word at byte 40. A blob sealed with
 * `CRYPTPROTECT_LOCAL_MACHINE` carries `0x4` there — measured on Windows 11 25H2
 * (build 26200): `0x0` for `DataProtectionScope.CurrentUser`, `0x4` for `LocalMachine`.
 */
const BLOB_HEADER_BYTES = 44;
const BLOB_FLAGS_OFFSET = 40;
const CRYPTPROTECT_LOCAL_MACHINE = 0x4;

const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const ENTROPY_PATTERN = /^[A-Za-z0-9._-]+$/;

export interface DpapiBridgeOptions {
  /** Operation label for the helper's errors (e.g. "DPAPI unseal"). */
  label: string;
  /** Path to powershell.exe (default: the pinned %SystemRoot% Windows PowerShell 5.1). */
  executablePath?: string;
  /** Kill the helper and reject after this many milliseconds (default 15000). */
  timeoutMs?: number;
}

/**
 * Fully-qualified BCL static calls only — no cmdlets, no Add-Type — as the session key's
 * protector, so module auto-loading never runs. The input crosses as base64 on stdin, the
 * output as base64 on stdout, never argv; a refusal by `ProtectedData` exits
 * `DPAPI_REFUSED_EXIT` with nothing printed. An entropy that is not a plain identifier is
 * `INVALID_INPUT`.
 */
export function dpapiScript(method: "Protect" | "Unprotect", entropy: string): string {
  if (!ENTROPY_PATTERN.test(entropy)) {
    throw VaultError.invalidInput(
      "DPAPI entropy is not a plain identifier (letters, digits, ., _ and -)",
    );
  }
  return (
    "$ErrorActionPreference='Stop';" +
    `[void][System.Reflection.Assembly]::Load('${DPAPI_ASSEMBLY}');` +
    "$d=[System.Convert]::FromBase64String([System.Console]::In.ReadToEnd().Trim());" +
    `$e=[System.Text.Encoding]::UTF8.GetBytes('${entropy}');` +
    `try{$o=[System.Security.Cryptography.ProtectedData]::${method}($d,$e,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)}` +
    `catch{[System.Array]::Clear($d,0,$d.Length);exit ${DPAPI_REFUSED_EXIT}};` +
    "[System.Array]::Clear($d,0,$d.Length);" +
    "[System.Console]::Out.Write([System.Convert]::ToBase64String($o));" +
    "[System.Array]::Clear($o,0,$o.Length)"
  );
}

/**
 * The scope a DPAPI blob's header names — `user` (CurrentUser) or `machine`
 * (`CRYPTPROTECT_LOCAL_MACHINE`, which every local account can unseal) — or undefined for
 * bytes too short or not version 1, which are no DPAPI blob at all.
 */
export function dpapiBlobScope(blob: Uint8Array): "user" | "machine" | undefined {
  if (blob.length < BLOB_HEADER_BYTES) return undefined;
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  if (view.getUint32(0, true) !== 1) return undefined;
  return (view.getUint32(BLOB_FLAGS_OFFSET, true) & CRYPTPROTECT_LOCAL_MACHINE) !== 0
    ? "machine"
    : "user";
}

async function runDpapi(
  method: "Protect" | "Unprotect",
  input: Uint8Array,
  entropy: string,
  options: DpapiBridgeOptions,
): Promise<Uint8Array | undefined> {
  if (input.length === 0) {
    throw VaultError.sessionFileError(`${options.label} requires non-empty input`);
  }
  const script = dpapiScript(method, entropy);
  const inputCopy = Buffer.from(input);
  const payload = inputCopy.toString("base64");
  wipeBuffer(inputCopy);

  const helperOptions: RunKeystoreHelperOptions = {
    label: options.label,
    expectZeroExit: false,
  };
  if (options.timeoutMs !== undefined) helperOptions.timeoutMs = options.timeoutMs;
  const result = await runKeystoreHelper(
    options.executablePath ?? system32Path("WindowsPowerShell", "v1.0", "powershell.exe"),
    ["-NoProfile", "-NonInteractive", "-Command", script],
    payload,
    helperOptions,
  );
  if (result.exitCode === DPAPI_REFUSED_EXIT) return undefined;
  if (result.exitCode !== 0) {
    throw VaultError.sessionFileError(`${options.label} failed (exit ${String(result.exitCode)})`);
  }
  const text = result.stdout.trim();
  if (!BASE64_PATTERN.test(text)) {
    throw VaultError.sessionFileError(`${options.label} returned malformed output`);
  }
  const decoded = Buffer.from(text, "base64");
  const out = new Uint8Array(decoded);
  wipeBuffer(decoded);
  return out;
}

/**
 * Seal `data` with `ProtectedData.Protect(data, entropy, CurrentUser)` under the account
 * this process runs as, through the pinned Windows PowerShell host. A refusal is
 * `SESSION_FILE_ERROR` (the code every DPAPI bridge failure carries); the caller wipes `data`.
 */
export async function dpapiProtect(
  data: Uint8Array,
  entropy: string,
  options: DpapiBridgeOptions,
): Promise<Uint8Array> {
  const blob = await runDpapi("Protect", data, entropy, options);
  if (blob === undefined) {
    throw VaultError.sessionFileError(`${options.label} was refused by DPAPI`);
  }
  return blob;
}

/**
 * Unseal a blob with `ProtectedData.Unprotect(blob, entropy, CurrentUser)`; undefined when
 * DPAPI refuses it (sealed by another account or with another entropy, damaged, or this
 * account's master key unavailable — a profile that is not loaded). A helper that cannot
 * run, times out or prints anything unexpected rejects `SESSION_FILE_ERROR`.
 */
export async function dpapiUnprotect(
  blob: Uint8Array,
  entropy: string,
  options: DpapiBridgeOptions,
): Promise<Uint8Array | undefined> {
  return runDpapi("Unprotect", blob, entropy, options);
}
