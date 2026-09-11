import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { MAX_PROCESS_OUTPUT_BYTES, VaultError } from "@harpoc/shared";
import { system32Path } from "../win32-paths.js";
import { CappedOutput } from "./capped-output.js";
import { sweepDescendants } from "./descendant-sweep.js";
import type { DescendantSweepResult } from "./descendant-sweep.js";
import type { FsIsolationMechanism } from "./fs-isolation.js";
import { requireIsolation } from "./isolation.js";
import type { NetworkIsolationMechanism } from "./network-isolation.js";
import { redactSecretEncodings } from "./output-sanitizer.js";
import { isJobWrapperFailure, wrapInJob } from "./win32-job-wrapper.js";
import type { TreeKillMechanism } from "./win32-job-wrapper.js";

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
  /**
   * Set only when the win32 descendant sweep ran after a timed-out spawn: the
   * survivors it killed and whether it failed open — a listing failure, a
   * helper at its bound, the whole sweep at its bound, a rejected sweep, or a
   * child whose exit had still not landed when the spawn settled (the settle
   * backstop starts the sweep itself; a kill the vault never saw take is
   * unconfirmed, whatever the sweep found). Absent on POSIX, on a normal exit
   * and on a spawn failure.
   */
  descendant_sweep?: { killed: number; failed: boolean };
  /**
   * The tier a win32 spawn ran under (2026-09-10): `job` — inside the vault's
   * kill-on-close job wrapper, a timeout kill taking the whole tree with no
   * taskkill, listing or sweep; `taskkill` — today's taskkill + descendant
   * sweep path, because the wrapper was unavailable on this host. Set on every
   * win32 result, the normal exit and the spawn failure included; absent on POSIX.
   */
  tree_kill?: TreeKillMechanism;
  /**
   * Present only when the policy's `strict_tree_exit` applied to this spawn
   * (D2, 2026-09-10): on win32 the job closed on the whole tree at the
   * child's exit; on POSIX its process group was killed after it. Absent
   * otherwise, on every platform.
   */
  strict_tree_exit?: true;
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
   * `networkIsolation` — the composer nests the two primaries or takes one
   * bwrap wrapper.
   */
  fsIsolation?: boolean;
  /**
   * The policy's `strict_tree_exit` (D2, 2026-09-10): nothing the child
   * started outlives the call. win32 — the job wrapper in strict mode; a host
   * without the wrapper refuses the spawn (STRICT_TREE_EXIT_UNAVAILABLE)
   * before it starts. POSIX — the child's process group is killed after its
   * own exit (the timeout path already kills it): a descendant that called
   * `setsid`, or one running as another user (EPERM), escapes — as on the
   * timeout path.
   */
  strictTreeExit?: boolean;
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
 * exit under load, and with it skipped the descendant sweep. On win32 the
 * backstop starts the sweep itself before settling (2026-09-08), so a late or
 * missing exit no longer means no sweep.
 */
const KILL_SETTLE_MS = 2_000;

/** Bound on waiting for the win32 taskkill helper to close before the backstop is armed. */
const KILL_HELPER_TIMEOUT_MS = 10_000;

/**
 * Terminate the child AND anything it spawned. Killing only the direct child
 * leaves a grandchild holding the inherited stdio — and, since the child is a
 * process-group leader (POSIX `detached`), the group signal is what reaches
 * the whole tree. On Windows the same job is done by the OS-shipped `taskkill
 * /T`, pinned to System32 and given nothing but a numeric pid.
 * Resolves once the kill has been delivered: on Windows when the taskkill
 * helper closes (bounded by KILL_HELPER_TIMEOUT_MS) — a helper that ran and
 * exited non-zero first falls back to a direct kill of the child, as a helper
 * that could not be started does (128, a process already gone, is a no-op
 * there) — and immediately on every other path.
 * On the job tier the kill is the direct kill of the wrapper — its job handle
 * closes and the kernel takes the tree — and no taskkill helper runs.
 */
function killTree(child: ChildProcess, treeKill: TreeKillMechanism | undefined): Promise<void> {
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
    if (treeKill === "job") {
      // The wrapper holds the only handle to the job: terminating it closes
      // the handle and the kernel takes every job member with it.
      killDirect();
      return Promise.resolve();
    }
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
      killer.on("close", (code) => {
        if (code !== 0) killDirect();
        delivered();
      });
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
 * taskkill helper and a timed-out spawn is swept for descendants, from the
 * exit when it lands and from the backstop when it does not — the sweep
 * starts within KILL_HELPER_TIMEOUT_MS + KILL_SETTLE_MS (12 s) of the timeout
 * on either path and settlement follows within DESCENDANT_SWEEP_TIMEOUT_MS
 * (30 s) of its start: the worst case is timeout + 42 s. POSIX has no helper
 * and no sweep: timeout + KILL_SETTLE_MS — a pending SIGKILL is delivered
 * before a process returns to user mode, so a child that outlives the group
 * kill by KILL_SETTLE_MS is in an uninterruptible wait and never executes
 * again; the credential it holds is inert (struck 2026-09-08, D3).
 * A pending promise here would strand the caller's `finally` — the plaintext
 * wipe, the ephemeral ssh-agent socket and the identity/known-hosts temp
 * files all hang off it.
 *
 * Isolation — network, filesystem or both — is applied here, at the single
 * spawn seam, after the caller's allowlist resolution, so no process-mediated
 * context can forget it: the vault-authored wrapper prefixes the argv, and the
 * resolved pinned command stays the audited payload. Composing the two
 * dimensions belongs to `requireIsolation`; the seam only reports which
 * mechanisms it got. unshare, setpriv and sandbox-exec exec the payload in
 * place; bwrap stays as a monitor that returns the payload's status and takes
 * it down when the monitor is killed (`--die-with-parent`), and the
 * process-group kill below reaches both — so pid (the kill target), kill and
 * exit-code semantics hold for every wrapper.
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
  // Every win32 spawn runs inside the job wrapper when the host can build and
  // run it (D4), in the mode the policy asks for (D2, 2026-09-10); off win32
  // wrapInJob answers a miss without probing.
  const strict = opts.strictTreeExit === true;
  let treeKill: TreeKillMechanism | undefined;
  const job = await wrapInJob(command, args, strict ? "strict" : "keep");
  if (job.mechanism === "job") {
    command = job.command;
    args = job.args;
    treeKill = "job";
  } else if (process.platform === "win32") {
    // A strict secret never runs on the taskkill tier: the job is the only
    // mechanism that keeps the promise, so its absence refuses the use here —
    // env built, nothing spawned — exactly where isolation refuses.
    if (strict) throw VaultError.strictTreeExitUnavailable(job.reason);
    treeKill = "taskkill";
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
        ...(treeKill ? { tree_kill: treeKill } : {}),
        // The policy that was in force for this spawn, like the isolation
        // booleans on the rows — copied from the policy, not from what the
        // child did (L81, 2026-09-10). Nothing started, so nothing survived.
        ...(strict ? { strict_tree_exit: true as const } : {}),
      });
      return;
    }

    let timedOut = false;
    let exited = false;
    let settled = false;
    let flushTimer: NodeJS.Timeout | undefined;
    let backstopTimer: NodeJS.Timeout | undefined;
    let sweep: Promise<DescendantSweepResult> | undefined;

    const settle = (result: SpawnCapturedResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (flushTimer) clearTimeout(flushTimer);
      if (backstopTimer) clearTimeout(backstopTimer);
      resolvePromise(result);
    };

    // win32 only, after a timeout kill: taskkill /T's descendant snapshot is
    // taken once, so a grandchild created inside that gap outlives the tree
    // kill with the credential in its inherited env. Started once — from the
    // child's exit or, when that never lands, from the settle backstop; the
    // sweep is bounded and every settlement path waits for it (see finish).
    const startSweep = (exitedAtMs: number): void => {
      if (!timedOut || treeKill !== "taskkill" || child.pid === undefined || sweep) return;
      sweep = sweepDescendants(child.pid, { spawnedAtMs, exitedAtMs }).catch(
        (): DescendantSweepResult => ({ killed: 0, failed: true }),
      );
    };

    const finish = (code: number | null, signal: string | null, spawnFailed: boolean): void => {
      const emit = (descendantSweep?: DescendantSweepResult): void => {
        const rawOut = stdout.toString();
        const rawErr = stderr.toString();
        // The wrapper's own failure (its reserved code AND its marker) is a
        // spawn that never ran — what a Node-level ENOENT is today.
        const wrapperFailed = treeKill === "job" && !timedOut && isJobWrapperFailure(code, rawErr);
        const out = redactAll(rawOut);
        const errText = redactAll(rawErr);
        settle({
          // A timed-out child was killed by the vault, so it reports as killed on
          // every platform: Windows has no signals and surfaces the taskkill as
          // an ordinary non-zero exit, which would otherwise read as the payload
          // having chosen that status.
          exit_code: timedOut || wrapperFailed ? null : code,
          stdout: out,
          stderr: errText,
          timed_out: timedOut,
          truncated: stdout.truncated || stderr.truncated,
          signal: timedOut ? (signal ?? "SIGKILL") : signal,
          spawn_failed: spawnFailed || wrapperFailed,
          redacted: out !== rawOut || errText !== rawErr,
          isolation_mechanism: isolationMechanism,
          fs_isolation_mechanism: fsIsolationMechanism,
          ...(treeKill ? { tree_kill: treeKill } : {}),
          ...(strict ? { strict_tree_exit: true as const } : {}),
          // A sweep the child's exit never confirmed is unconfirmed whatever it
          // found: the kill was delivered, but the vault did not see it take.
          ...(descendantSweep
            ? {
                descendant_sweep: {
                  killed: descendantSweep.killed,
                  failed: descendantSweep.failed || !exited,
                },
              }
            : {}),
        });
      };
      if (sweep) void sweep.then(emit, () => emit({ killed: 0, failed: true }));
      else emit();
    };

    const timer = setTimeout(() => {
      timedOut = true;
      // A kill that does not take (an unkillable state, a failed taskkill)
      // must not strand the caller: settle with what was captured — but only
      // once the kill has been delivered, so a slow taskkill cannot settle the
      // spawn ahead of the exit that starts the descendant sweep, and with the
      // sweep run from here when that exit never comes.
      void killTree(child, treeKill).then(() => {
        if (settled) return;
        backstopTimer = setTimeout(() => {
          startSweep(Date.now());
          finish(null, "SIGKILL", false);
        }, KILL_SETTLE_MS);
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
      exited = true;
      // POSIX strict tree exit (D2, 2026-09-10): the child left on its own —
      // take the process group it led (`detached`) with it. The timeout path
      // killed the group already; ESRCH means nobody was left. A descendant
      // that called `setsid`, or one running as another user (EPERM), escapes
      // — as on the timeout path. On win32 the job did this in the kernel.
      if (strict && !timedOut && process.platform !== "win32" && child.pid !== undefined) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          // The group is empty, already gone — or EPERM: a member running as
          // another user, which the escape clause above names (L82).
        }
      }
      if (settled) return;
      startSweep(Date.now());
      if (flushTimer) return;
      flushTimer = setTimeout(() => finish(code, signal ?? null, false), STREAM_FLUSH_GRACE_MS);
      if (flushTimer.unref) flushTimer.unref();
    });

    child.on("close", (code, signal) => {
      finish(code, signal ?? null, false);
    });
  });
}
