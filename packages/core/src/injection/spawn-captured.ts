import { spawn } from "node:child_process";
import { MAX_PROCESS_OUTPUT_BYTES } from "@harpoc/shared";
import { CappedOutput } from "./capped-output.js";
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
}

export interface SpawnCapturedOptions {
  env: Record<string, string>;
  cwd?: string;
  timeoutMs: number;
  /** Secret strings whose raw value and common encodings are stripped from output. */
  redact?: string[];
  maxOutputBytes?: number;
}

/**
 * Spawn a subprocess with no shell (`shell:false`), capture stdout/stderr into
 * capped buffers, enforce a timeout (SIGKILL on exceed) and redact injected
 * credential strings from the captured output. Shared by the process, Git and
 * SSH contexts so the process-mediated capture discipline is defined once.
 */
export function spawnCaptured(
  command: string,
  args: string[],
  opts: SpawnCapturedOptions,
): Promise<SpawnCapturedResult> {
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
      });
    });
  });
}
