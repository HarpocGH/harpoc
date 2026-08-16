import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { join } from "node:path";
import { MAX_PROCESS_OUTPUT_BYTES } from "@harpoc/shared";
import { CappedOutput } from "./capped-output.js";
import type { FsIsolationMechanism } from "./fs-isolation.js";
import { requireIsolation } from "./isolation.js";
import type { NetworkIsolationMechanism } from "./network-isolation.js";
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
  /** Set when the spawn ran inside the filesystem-isolation wrapper. */
  fs_isolation_mechanism?: FsIsolationMechanism;
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
  /**
   * Wrap the spawn in the platform filesystem-isolation prefix (thesis §4.5.3
   * layer 4). Fail closed: an unavailable platform throws
   * FS_ISOLATION_UNAVAILABLE before any process is spawned. Combines with
   * `networkIsolation` — the composer nests the two wrappers.
   */
  fsIsolation?: boolean;
}

/**
 * Grace period after the child's own exit for its stdio streams to flush. A
 * grandchild that inherited stdout/stderr keeps them open, so `'close'` may
 * never arrive; past this the captured output is returned as-is.
 */
const STREAM_FLUSH_GRACE_MS = 1_000;

/** Backstop after a timeout kill: settle even if neither exit nor close lands. */
const KILL_SETTLE_MS = 2_000;

/**
 * Terminate the child AND anything it spawned. Killing only the direct child
 * leaves a grandchild holding the inherited stdio — and, since the child is a
 * process-group leader (POSIX `detached`), the group signal is what reaches
 * the whole tree. On Windows the same job is done by the OS-shipped `taskkill
 * /T`, pinned to System32 and given nothing but a numeric pid.
 */
function killTree(child: ChildProcess): void {
  const pid = child.pid;
  const killDirect = (): void => {
    try {
      child.kill("SIGKILL");
    } catch {
      // The child is already gone.
    }
  };
  if (pid === undefined) {
    killDirect();
    return;
  }
  if (process.platform === "win32") {
    try {
      const taskkill = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "taskkill.exe");
      const killer = spawn(taskkill, ["/pid", String(pid), "/T", "/F"], {
        shell: false,
        windowsHide: true,
        stdio: "ignore",
      });
      killer.on("error", killDirect);
    } catch {
      killDirect();
    }
    return;
  }
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    killDirect();
  }
}

/**
 * Spawn a subprocess with no shell (`shell:false`), capture stdout/stderr into
 * capped buffers, enforce a timeout (SIGKILL on exceed) and redact injected
 * credential strings from the captured output. Shared by the process, Git and
 * SSH contexts so the process-mediated capture discipline is defined once.
 *
 * The returned promise always settles: the timeout kills the child's whole
 * process group, settlement is driven by the child's own `'exit'` with a
 * bounded flush grace (not by `'close'`, which a surviving grandchild holding
 * the inherited stdio can withhold forever), and a post-kill backstop settles
 * even if the kill itself does not take. A pending promise here would strand
 * the caller's `finally` — the plaintext wipe, the ephemeral ssh-agent socket
 * and the identity/known-hosts temp files all hang off it.
 *
 * Isolation — network, filesystem or both — is applied here, at the single
 * spawn seam, after the caller's allowlist resolution, so no process-mediated
 * context can forget it: the vault-authored wrapper prefixes the argv, and the
 * resolved pinned command stays the audited payload. Composing the two
 * dimensions belongs to `requireIsolation`; the seam only reports which
 * mechanisms it got. Each wrapper execs the payload in-place (no fork), so
 * PID, kill and exit-code semantics are unchanged.
 */
export async function spawnCaptured(
  command: string,
  args: string[],
  opts: SpawnCapturedOptions,
): Promise<SpawnCapturedResult> {
  let isolationMechanism: NetworkIsolationMechanism | undefined;
  let fsIsolationMechanism: FsIsolationMechanism | undefined;
  if (opts.networkIsolation === true || opts.fsIsolation === true) {
    const wrapped = await requireIsolation(command, args, {
      network: opts.networkIsolation === true,
      fs: opts.fsIsolation === true,
    });
    command = wrapped.command;
    args = wrapped.args;
    isolationMechanism = wrapped.networkMechanism;
    fsIsolationMechanism = wrapped.fsMechanism;
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
        // POSIX: own process group, so the timeout can signal the whole tree.
        // Windows has no equivalent (detached opens a console there) and uses
        // taskkill /T instead.
        detached: process.platform !== "win32",
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
        fs_isolation_mechanism: fsIsolationMechanism,
      });
      return;
    }

    let timedOut = false;
    let settled = false;
    let flushTimer: NodeJS.Timeout | undefined;
    let backstopTimer: NodeJS.Timeout | undefined;

    const settle = (result: SpawnCapturedResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (flushTimer) clearTimeout(flushTimer);
      if (backstopTimer) clearTimeout(backstopTimer);
      resolvePromise(result);
    };

    const finish = (code: number | null, signal: string | null, spawnFailed: boolean): void => {
      settle({
        // A timed-out child was killed by the vault, so it reports as killed on
        // every platform: Windows has no signals and surfaces the taskkill as
        // an ordinary non-zero exit, which would otherwise read as the payload
        // having chosen that status.
        exit_code: timedOut ? null : code,
        stdout: redactAll(stdout.toString()),
        stderr: redactAll(stderr.toString()),
        timed_out: timedOut,
        truncated: stdout.truncated || stderr.truncated,
        signal: timedOut ? (signal ?? "SIGKILL") : signal,
        spawn_failed: spawnFailed,
        isolation_mechanism: isolationMechanism,
        fs_isolation_mechanism: fsIsolationMechanism,
      });
    };

    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child);
      // A kill that does not take (an unkillable state, a failed taskkill)
      // must not strand the caller: settle with what was captured.
      backstopTimer = setTimeout(() => finish(null, "SIGKILL", false), KILL_SETTLE_MS);
      if (backstopTimer.unref) backstopTimer.unref();
    }, opts.timeoutMs);
    if (timer.unref) timer.unref();

    child.stdout?.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr?.on("data", (chunk: Buffer) => stderr.push(chunk));

    child.on("error", () => {
      finish(null, null, true);
    });

    // 'close' waits for every stdio stream to end — a grandchild that inherited
    // them can hold it back indefinitely, so the child's own 'exit' starts a
    // bounded flush window instead. On the normal path 'close' follows within
    // microseconds and settles immediately with the complete output.
    child.on("exit", (code, signal) => {
      if (settled || flushTimer) return;
      flushTimer = setTimeout(() => finish(code, signal ?? null, false), STREAM_FLUSH_GRACE_MS);
      if (flushTimer.unref) flushTimer.unref();
    });

    child.on("close", (code, signal) => {
      finish(code, signal ?? null, false);
    });
  });
}
