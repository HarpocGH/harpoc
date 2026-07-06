import { spawn } from "node:child_process";
import { join } from "node:path";
import type { SessionKeyProtectionScheme } from "@harpoc/shared";
import { VaultError } from "@harpoc/shared";
import { wipeBuffer } from "../crypto/random.js";

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

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_STDOUT_BYTES = 64 * 1024;
const MAX_STDERR_BYTES = 4 * 1024;
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
  private readonly timeoutMs: number;

  constructor(options: DpapiSessionKeyProtectorOptions = {}) {
    this.executablePath = options.executablePath ?? defaultPowershellPath();
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async protect(key: Uint8Array): Promise<Uint8Array> {
    return this.run("Protect", key);
  }

  async unprotect(blob: Uint8Array): Promise<Uint8Array> {
    return this.run("Unprotect", blob);
  }

  private run(method: "Protect" | "Unprotect", input: Uint8Array): Promise<Uint8Array> {
    if (input.length === 0) {
      return Promise.reject(VaultError.sessionFileError(`DPAPI ${method} requires non-empty input`));
    }

    return new Promise<Uint8Array>((resolve, reject) => {
      const child = spawn(
        this.executablePath,
        ["-NoProfile", "-NonInteractive", "-Command", dpapiScript(method)],
        { stdio: ["pipe", "pipe", "pipe"], windowsHide: true },
      );

      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let settled = false;

      const finish = (error: Error | null, output?: Uint8Array): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) {
          child.kill();
          reject(error);
        } else {
          resolve(output as Uint8Array);
        }
      };

      const timer = setTimeout(() => {
        finish(VaultError.sessionFileError(`DPAPI ${method} timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);

      child.on("error", (err) => {
        finish(VaultError.sessionFileError(`DPAPI helper failed to start: ${err.message}`));
      });

      child.stdout.on("data", (chunk: Buffer) => {
        stdoutBytes += chunk.length;
        if (stdoutBytes > MAX_STDOUT_BYTES) {
          finish(VaultError.sessionFileError(`DPAPI ${method} produced oversized output`));
          return;
        }
        stdoutChunks.push(chunk);
      });

      child.stderr.on("data", (chunk: Buffer) => {
        if (stderrBytes < MAX_STDERR_BYTES) {
          stderrChunks.push(chunk);
          stderrBytes += chunk.length;
        }
      });

      child.on("close", (code) => {
        if (settled) return;
        if (code !== 0) {
          const detail = Buffer.concat(stderrChunks)
            .toString("utf8")
            .replace(/\s+/g, " ")
            .trim()
            .slice(0, 200);
          finish(
            VaultError.sessionFileError(
              `DPAPI ${method} failed (exit ${code ?? "unknown"})${detail ? `: ${detail}` : ""}`,
            ),
          );
          return;
        }
        const buffer = Buffer.concat(stdoutChunks);
        const text = buffer.toString("ascii").trim();
        wipeBuffer(buffer);
        if (!BASE64_PATTERN.test(text)) {
          finish(VaultError.sessionFileError(`DPAPI ${method} returned malformed output`));
          return;
        }
        finish(null, new Uint8Array(Buffer.from(text, "base64")));
      });

      // EPIPE when the child dies before reading stdin — the close handler reports it.
      child.stdin.on("error", () => {});
      const inputCopy = Buffer.from(input);
      child.stdin.end(inputCopy.toString("base64"));
      wipeBuffer(inputCopy);
    });
  }
}

/**
 * Select the platform protector: DPAPI on Windows, none elsewhere (thesis §4.6
 * file-permission fallback; Keychain/Secret Service are future work).
 * `HARPOC_SESSION_KEYSTORE=off` disables keystore wrapping for new session
 * writes (operational opt-out; an already-wrapped file then fails closed and
 * requires a fresh unlock).
 */
export function createSessionKeyProtector(
  platform: NodeJS.Platform = process.platform,
  env: Record<string, string | undefined> = process.env,
): SessionKeyProtector {
  if ((env["HARPOC_SESSION_KEYSTORE"] ?? "").toLowerCase() === "off") {
    return new NoneSessionKeyProtector();
  }
  if (platform === "win32") {
    return new DpapiSessionKeyProtector();
  }
  return new NoneSessionKeyProtector();
}
