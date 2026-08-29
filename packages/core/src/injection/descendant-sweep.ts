/**
 * Second sweep after a win32 tree kill (thesis §4.5.3 layer 4 follow-up).
 * `taskkill /T` snapshots the descendant tree once; a grandchild created
 * between that snapshot and the kill survives with the inherited environment —
 * the credential included. Orphans keep their `ParentProcessId`, so after the
 * child has exited the survivors are exactly the processes still naming its
 * pid as parent and created inside the child's own lifetime: after it was
 * spawned and before it exited. Windows reuses pids quickly and an orphan
 * keeps its `ParentProcessId` for good, so a process that inherits the dead
 * pid can only have newer children (the upper bound), while an orphan of an
 * EARLIER holder of that pid is older than the child itself (the lower bound)
 * — without it a timed-out spawn would kill an unrelated operator process.
 * `exitedAtMs` is taken when `exit` is delivered, milliseconds after the true
 * exit, so a child an inheritor spawns inside that gap falls inside the window
 * — negligible, and documented rather than closed. A clock step can only make
 * the filter skip a real survivor, which degrades to the pre-sweep behaviour.
 * Best-effort and bounded: a failed sweep settles with what was captured, as a
 * failed taskkill does today, and once the bound expires no further helper is
 * spawned — the survivors still standing are left as they were before this
 * sweep existed (fail-open).
 */
import { spawn } from "node:child_process";
import { system32Path } from "../win32-paths.js";

export interface DescendantProcess {
  pid: number;
  createdAtMs: number;
}

/** The child's lifetime: a survivor was created after the spawn and before the exit. */
export interface DescendantLifetime {
  spawnedAtMs: number;
  exitedAtMs: number;
}

export interface DescendantSweepDeps {
  listDescendants(pid: number): Promise<DescendantProcess[]>;
  killPid(pid: number): Promise<void>;
}

export interface DescendantSweepResult {
  killed: number;
  failed: boolean;
}

/**
 * Bound on the whole sweep — the keystore-helper precedent: process start-up
 * stretches about tenfold under the full parallel gate, and a bound the sweep
 * cannot meet is a sweep that never runs. 1.5× the per-helper bound: one
 * listing plus the kills, as before.
 */
export const DESCENDANT_SWEEP_TIMEOUT_MS = 30_000;

const MAX_LISTING_BYTES = 64 * 1024;
/**
 * Per helper (one PowerShell listing, one taskkill). A cold PowerShell host
 * exceeded 4 s under the local parallel gate (2026-08-26) and 10 s on every
 * windows-latest CI run since (PowerShell 5.1 start-up plus the CIM listing on
 * a two-core runner under the full gate; ~250 ms on an idle host) — a bound
 * the helper cannot meet is a sweep that silently fails open (2026-08-29).
 */
const HELPER_TIMEOUT_MS = 20_000;

export async function sweepDescendants(
  pid: number,
  lifetime: DescendantLifetime,
  deps: DescendantSweepDeps = win32SweepDeps(),
  timeoutMs: number = DESCENDANT_SWEEP_TIMEOUT_MS,
): Promise<DescendantSweepResult> {
  if (!Number.isInteger(pid) || pid <= 0) return { killed: 0, failed: true };

  let expired = false;
  let killed = 0;
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<DescendantSweepResult>((resolve) => {
    timer = setTimeout(() => {
      expired = true;
      resolve({ killed, failed: true });
    }, timeoutMs);
    if (timer.unref) timer.unref();
  });

  const run = async (): Promise<DescendantSweepResult> => {
    let survivors: DescendantProcess[];
    try {
      survivors = await deps.listDescendants(pid);
    } catch {
      return { killed, failed: true };
    }
    let failed = false;
    for (const proc of survivors) {
      if (expired) break;
      if (proc.createdAtMs < lifetime.spawnedAtMs || proc.createdAtMs > lifetime.exitedAtMs) {
        continue;
      }
      try {
        await deps.killPid(proc.pid);
        killed += 1;
      } catch {
        failed = true;
      }
    }
    return { killed, failed };
  };

  try {
    return await Promise.race([run(), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** One line per descendant: `<pid> <unix-ms>`. The pid is a validated integer, never operator text. */
function listingScript(pid: number): string {
  return (
    `Get-CimInstance Win32_Process -Filter "ParentProcessId=${String(pid)}" | ` +
    "ForEach-Object { '{0} {1}' -f $_.ProcessId, ([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds() }"
  );
}

interface HelperOutcome {
  code: number | null;
  stdout: string;
}

/** Rejects only when the helper could not be run to completion (spawn error, timeout); the exit code is the caller's to judge. */
function runHelper(
  executable: string,
  args: string[],
  timeoutMs: number = HELPER_TIMEOUT_MS,
): Promise<HelperOutcome> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const finish = (err: Error | null, code: number | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve({ code, stdout: Buffer.concat(chunks).toString("utf8") });
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(new Error("descendant sweep helper timed out"), null);
    }, timeoutMs);
    if (timer.unref) timer.unref();
    child.stdout?.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes <= MAX_LISTING_BYTES) chunks.push(chunk);
    });
    child.on("error", (err) => finish(err, null));
    child.on("close", (code) => finish(null, code));
  });
}

/** taskkill exits 128 for a process that is already gone — the sweep's goal, not a failure. */
const TASKKILL_NOT_FOUND = 128;

export interface Win32SweepDepsOptions {
  /**
   * Per-helper bound; defaults to `HELPER_TIMEOUT_MS`. Product callers pass
   * nothing — the option exists so the live test can prove the sweep against a
   * real process tree on a host whose WMI answers slower than the product is
   * willing to wait (windows-latest under the full gate: > 20 s, vs ~250 ms idle).
   */
  helperTimeoutMs?: number;
}

export function win32SweepDeps(options: Win32SweepDepsOptions = {}): DescendantSweepDeps {
  const powershell = system32Path("WindowsPowerShell", "v1.0", "powershell.exe");
  const taskkill = system32Path("taskkill.exe");
  const helperTimeoutMs = options.helperTimeoutMs ?? HELPER_TIMEOUT_MS;
  return {
    async listDescendants(pid) {
      const { code, stdout } = await runHelper(
        powershell,
        ["-NoProfile", "-NonInteractive", "-Command", listingScript(pid)],
        helperTimeoutMs,
      );
      if (code !== 0) throw new Error(`descendant sweep listing exited ${String(code)}`);
      const found: DescendantProcess[] = [];
      for (const line of stdout.split(/\r?\n/)) {
        const match = /^(\d+) (\d+)$/.exec(line.trim());
        if (match) found.push({ pid: Number(match[1]), createdAtMs: Number(match[2]) });
      }
      return found;
    },
    async killPid(pid) {
      const { code } = await runHelper(
        taskkill,
        ["/pid", String(pid), "/T", "/F"],
        helperTimeoutMs,
      );
      if (code !== 0 && code !== TASKKILL_NOT_FOUND) {
        throw new Error(`descendant sweep kill exited ${String(code)}`);
      }
    },
  };
}
