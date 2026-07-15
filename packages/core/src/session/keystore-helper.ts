import { spawn } from "node:child_process";
import { VaultError } from "@harpoc/shared";
import { wipeBuffer } from "../crypto/random.js";

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_STDOUT_BYTES = 64 * 1024;
const MAX_STDERR_BYTES = 4 * 1024;

export interface RunKeystoreHelperOptions {
  /** Operation label used in error messages (e.g. "DPAPI Protect", "Keychain read"). */
  label: string;
  /** Kill the helper and reject after this many milliseconds (default 15000). */
  timeoutMs?: number;
  /**
   * When true (default), a non-zero exit rejects with the stderr detail. When
   * false, the result is returned and the caller decides — keystore lookups
   * signal a clean miss through non-zero exits.
   */
  expectZeroExit?: boolean;
}

export interface KeystoreHelperResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Run a platform keystore bridge process (thesis §4.6): OS-shipped binary from
 * a pinned absolute path, `shell:false`, key material crossing on stdin/stdout
 * only — never argv — with a hard timeout and output caps. Shared by the DPAPI,
 * Keychain, Secret Service and kernel-keyring bridges.
 */
export function runKeystoreHelper(
  executablePath: string,
  args: readonly string[],
  stdinPayload: string,
  options: RunKeystoreHelperOptions,
): Promise<KeystoreHelperResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const expectZeroExit = options.expectZeroExit ?? true;
  const label = options.label;

  return new Promise<KeystoreHelperResult>((resolve, reject) => {
    const child = spawn(executablePath, args as string[], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;

    const finish = (error: Error | null, output?: KeystoreHelperResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        child.kill();
        reject(error);
      } else {
        resolve(output as KeystoreHelperResult);
      }
    };

    const timer = setTimeout(() => {
      finish(VaultError.sessionFileError(`${label} timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.on("error", (err) => {
      finish(VaultError.sessionFileError(`${label} helper failed to start: ${err.message}`));
    });

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_STDOUT_BYTES) {
        finish(VaultError.sessionFileError(`${label} produced oversized output`));
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
      const stderr = Buffer.concat(stderrChunks).toString("utf8");
      if (code !== 0 && expectZeroExit) {
        const detail = stderr.replace(/\s+/g, " ").trim().slice(0, 200);
        finish(
          VaultError.sessionFileError(
            `${label} failed (exit ${code ?? "unknown"})${detail ? `: ${detail}` : ""}`,
          ),
        );
        return;
      }
      const buffer = Buffer.concat(stdoutChunks);
      const stdout = buffer.toString("utf8");
      wipeBuffer(buffer);
      finish(null, { stdout, stderr, exitCode: code ?? -1 });
    });

    // EPIPE when the child dies before reading stdin — the close handler reports it.
    child.stdin.on("error", () => {});
    child.stdin.end(stdinPayload);
  });
}
