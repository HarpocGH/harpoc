import { spawn } from "node:child_process";
import { MAX_PROCESS_OUTPUT_BYTES } from "@harpoc/shared";
import { CappedOutput } from "./capped-output.js";
import type { NetworkIsolationMechanism } from "./network-isolation.js";
import { requireNetworkIsolation } from "./network-isolation.js";
import { redactSecretEncodings } from "./output-sanitizer.js";

/**
 * Raw result of a captured subprocess spawn, before mapping to a context result.
 * `spawn_failed` covers both a synchronous spawn throw and an async `error`
 * event; the caller decides which ErrorCode to surface.
 */
export interface SpawnCapturedResult {
  exit_code: number | null;
  stdout: string;
  stderr: string;
  timed_out: boolean;
  truncated: boolean;
  signal: string | null;
  spawn_failed: boolean;
  /** Set when the spawn ran inside the network-isolation wrapper. */
  isolation_mechanism?: NetworkIsolationMechanism;
}

export interface SpawnCapturedOptions {
  env: Record<string, string>;
  cwd?: string;
  timeoutMs: number;
  /** Secret strings whose raw value and common encodings are stripped from output. */
  redact?: string[];
  maxOutputBytes?: number;
  /**
   * Wrap the spawn in the platform network-isolation prefix (thesis §4.5.3
   * layer 4). Fail closed: an unavailable platform throws
   * NETWORK_ISOLATION_UNAVAILABLE before any process is spawned.
   */
  networkIsolation?: boolean;
}

/**
 * Spawn a subprocess with no shell (`shell:false`), capture stdout/stderr into
 * capped buffers, enforce a timeout (SIGKILL on exceed) and redact injected
 * credential strings from the captured output. Shared by the process, Git and
 * SSH contexts so the process-mediated capture discipline is defined once.
 *
 * Network isolation is applied here — at the single spawn seam, after the
 * caller's allowlist resolution — so no process-mediated context can forget
 * it: the vault-authored wrapper prefixes the argv, and the resolved pinned
 * command stays the audited payload. The wrapper execs the payload in-place
 * (no fork), so PID, kill and exit-code semantics are unchanged.
 */
export async function spawnCaptured(
  command: string,
  args: string[],
  opts: SpawnCapturedOptions,
): Promise<SpawnCapturedResult> {
  let isolationMechanism: NetworkIsolationMechanism | undefined;
  if (opts.networkIsolation) {
    const wrapped = await requireNetworkIsolation(command, args);
    command = wrapped.command;
    args = wrapped.args;
    isolationMechanism = wrapped.mechanism;
  }
  const cap = opts.maxOutputBytes ?? MAX_PROCESS_OUTPUT_BYTES;
  const stdout = new CappedOutput(cap);
  const stderr = new CappedOutput(cap);
  const redactAll = (text: string): string => {
    let out = text;
    for (const s of opts.redact ?? []) {
      if (s.length > 0) out = redactSecretEncodings(out, s);
    }
    return out;
  };

  return new Promise<SpawnCapturedResult>((resolvePromise) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command, args, {
        shell: false,
        env: opts.env,
        cwd: opts.cwd,
        windowsHide: true,
      });
    } catch {
      resolvePromise({
        exit_code: null,
        stdout: "",
        stderr: "",
        timed_out: false,
        truncated: false,
        signal: null,
        spawn_failed: true,
        isolation_mechanism: isolationMechanism,
      });
      return;
    }

    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, opts.timeoutMs);
    if (timer.unref) timer.unref();

    child.stdout?.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr?.on("data", (chunk: Buffer) => stderr.push(chunk));

    child.on("error", () => {
      clearTimeout(timer);
      resolvePromise({
        exit_code: null,
        stdout: redactAll(stdout.toString()),
        stderr: redactAll(stderr.toString()),
        timed_out: false,
        truncated: stdout.truncated || stderr.truncated,
        signal: null,
        spawn_failed: true,
        isolation_mechanism: isolationMechanism,
      });
    });

    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolvePromise({
        exit_code: code,
        stdout: redactAll(stdout.toString()),
        stderr: redactAll(stderr.toString()),
        timed_out: timedOut,
        truncated: stdout.truncated || stderr.truncated,
        signal: signal ?? null,
        spawn_failed: false,
        isolation_mechanism: isolationMechanism,
      });
    });
  });
}
