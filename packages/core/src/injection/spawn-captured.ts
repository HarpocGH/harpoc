import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { MAX_PROCESS_OUTPUT_BYTES } from "@harpoc/shared";
import { system32Path } from "../win32-paths.js";
import { CappedOutput } from "./capped-output.js";
import { sweepDescendants } from "./descendant-sweep.js";
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
  /** True when the credential redaction changed stdout or stderr. */
  redacted: boolean;
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

/**
 * Backstop after a timeout kill has been delivered: settle even if neither
 * exit nor close lands. Armed once `killTree` resolves, not at dispatch — a
 * backstop that raced the kill itself settled the spawn before the child's
 * exit under load, and with it skipped the descendant sweep.
 */
const KILL_SETTLE_MS = 2_000;

/** Bound on waiting for the win32 taskkill helper to close before the backstop is armed. */
const KILL_HELPER_TIMEOUT_MS = 10_000;

/**
 * Terminate the child AND anything it spawned. Killing only the direct child
 * leaves a grandchild holding the inherited stdio — and, since the child is a
 * process-group leader (POSIX `detached`), the group signal is what reaches
 * the whole tree. On Windows the same job is done by the OS-shipped `taskkill
 * /T`, pinned to System32 and given nothing but a numeric pid. Resolves once
 * the kill has been delivered: on Windows when the taskkill helper closes
 * (bounded by KILL_HELPER_TIMEOUT_MS), immediately on every other path.
 */
function killTree(child: ChildProcess): Promise<void> {
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
    return Promise.resolve();
  }
  if (process.platform === "win32") {
    return new Promise<void>((resolve) => {
      let killer: ChildProcess;
      try {
        const taskkill = system32Path("taskkill.exe");
        killer = spawn(taskkill, ["/pid", String(pid), "/T", "/F"], {
          shell: false,
          windowsHide: true,
          stdio: "ignore",
        });
      } catch {
        killDirect();
        resolve();
        return;
      }
      let done = false;
      const delivered = (): void => {
        if (done) return;
        done = true;
        clearTimeout(bound);
        resolve();
      };
      const bound = setTimeout(delivered, KILL_HELPER_TIMEOUT_MS);
      if (bound.unref) bound.unref();
      killer.on("error", () => {
        killDirect();
        delivered();
      });
      killer.on("close", delivered);
    });
  }
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    killDirect();
  }
  return Promise.resolve();
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
 * even if the kill itself does not take. On win32 — where the kill is a
 * taskkill helper and a timed-out exit starts the descendant sweep — a spawn
 * whose exit never lands settles within KILL_HELPER_TIMEOUT_MS +
 * KILL_SETTLE_MS (12 s) of the timeout, and one whose exit does land settles
 * within DESCENDANT_SWEEP_TIMEOUT_MS (30 s) of that exit; since the exit
 * itself lands inside the first bound, the collapsed worst case is
 * timeout + 42 s. POSIX has no helper and no sweep: timeout + KILL_SETTLE_MS.
 * A pending promise here would strand the caller's `finally` — the plaintext
 * wipe, the ephemeral ssh-agent socket and the identity/known-hosts temp
 * files all hang off it.
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
    const spawnedAtMs = Date.now();
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
        redacted: false,
        isolation_mechanism: isolationMechanism,
        fs_isolation_mechanism: fsIsolationMechanism,
      });
      return;
    }

    let timedOut = false;
    let settled = false;
    let flushTimer: NodeJS.Timeout | undefined;
    let backstopTimer: NodeJS.Timeout | undefined;
    let sweep: Promise<unknown> | undefined;

    const settle = (result: SpawnCapturedResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (flushTimer) clearTimeout(flushTimer);
      if (backstopTimer) clearTimeout(backstopTimer);
      resolvePromise(result);
    };

    const finish = (code: number | null, signal: string | null, spawnFailed: boolean): void => {
      const emit = (): void => {
        const rawOut = stdout.toString();
        const rawErr = stderr.toString();
        const out = redactAll(rawOut);
        const errText = redactAll(rawErr);
        settle({
          // A timed-out child was killed by the vault, so it reports as killed on
          // every platform: Windows has no signals and surfaces the taskkill as
          // an ordinary non-zero exit, which would otherwise read as the payload
          // having chosen that status.
          exit_code: timedOut ? null : code,
          stdout: out,
          stderr: errText,
          timed_out: timedOut,
          truncated: stdout.truncated || stderr.truncated,
          signal: timedOut ? (signal ?? "SIGKILL") : signal,
          spawn_failed: spawnFailed,
          redacted: out !== rawOut || errText !== rawErr,
          isolation_mechanism: isolationMechanism,
          fs_isolation_mechanism: fsIsolationMechanism,
        });
      };
      if (sweep) void sweep.then(emit, emit);
      else emit();
    };

    const timer = setTimeout(() => {
      timedOut = true;
      // A kill that does not take (an unkillable state, a failed taskkill)
      // must not strand the caller: settle with what was captured — but only
      // once the kill has been delivered, so a slow taskkill cannot settle the
      // spawn ahead of the exit that starts the descendant sweep.
      void killTree(child).then(() => {
        if (settled) return;
        backstopTimer = setTimeout(() => finish(null, "SIGKILL", false), KILL_SETTLE_MS);
        if (backstopTimer.unref) backstopTimer.unref();
      });
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
      if (settled) return;
      // win32 only, after a timeout kill: taskkill /T's descendant snapshot is
      // taken once, so a grandchild created inside that gap outlives the tree
      // kill with the credential in its inherited env. The sweep is bounded and
      // every settlement path waits for it (see finish).
      if (timedOut && process.platform === "win32" && child.pid !== undefined && !sweep) {
        sweep = sweepDescendants(child.pid, { spawnedAtMs, exitedAtMs: Date.now() }).catch(
          () => undefined,
        );
      }
      if (flushTimer) return;
      flushTimer = setTimeout(() => finish(code, signal ?? null, false), STREAM_FLUSH_GRACE_MS);
      if (flushTimer.unref) flushTimer.unref();
    });

    child.on("close", (code, signal) => {
      finish(code, signal ?? null, false);
    });
  });
}
