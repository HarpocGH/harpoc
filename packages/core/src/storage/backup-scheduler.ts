import { ErrorCode, VaultError } from "@harpoc/shared";
import type { VaultEngine } from "../vault-engine.js";
import { freeBackupTime, newestBackupAt, removeBackupTemps } from "./backup-names.js";

export const BACKUP_STOP_DRAIN_TIMEOUT_MS = 10_000;

export interface BackupSchedulerOptions {
  dir: string;
  intervalMs: number;
  keep: number;
  label: string;
  /**
   * A failed sweep, read or run — a file error of the start as `FILE_IO_ERROR`; nothing once the
   * stop began. Default: no-op.
   */
  onError?: (err: unknown) => void;
  now?: () => number;
}

interface Run {
  readonly controller: AbortController;
  settled: Promise<void>;
}

const MAX_INTERVAL_MS = 2_147_483_647;

function directoryFailure(err: unknown): unknown {
  if (err instanceof VaultError) return err;
  const code = err instanceof Error ? (err as NodeJS.ErrnoException).code : undefined;
  return new VaultError(
    ErrorCode.FILE_IO_ERROR,
    `could not read the backup directory (${code ?? "unknown error"})`,
  );
}

/**
 * Scheduled copies of the vault into one directory, one run at a time. The first run is timed
 * from the newest copy not stamped later than now, so a daemon that restarts takes no copy beside
 * a fresh one; each next run is due one interval after the last one's start, whether it succeeded
 * or failed, and never more than one interval away. A run names its copy by the first free second
 * at or after its start. A sealed vault (`VAULT_LOCKED`) ends the schedule.
 */
export class BackupScheduler {
  private readonly now: () => number;
  private live = false;
  private generation = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private current: Run | null = null;

  constructor(
    private readonly engine: Pick<VaultEngine, "backupToDirectory">,
    private readonly options: BackupSchedulerOptions,
  ) {
    const { intervalMs } = options;
    if (!(Number.isFinite(intervalMs) && intervalMs >= 1 && intervalMs <= MAX_INTERVAL_MS)) {
      throw VaultError.invalidInput(
        "backup interval must be between 1 and 2147483647 milliseconds",
      );
    }
    this.now = options.now ?? (() => Date.now());
  }

  /**
   * Removes the temporary files a killed run left in the directory — none while a run is still
   * pending — then arms the first run, timed from the newest copy not stamped later than now (a
   * copy stamped later is left out): at once when there is none, it is one interval old or older,
   * or the directory cannot be read; else when it is one interval old. A failure of the two steps
   * is reported once. A call while the schedule runs does nothing.
   */
  start(): void {
    if (this.live) return;
    this.live = true;
    const generation = ++this.generation;
    const { dir, intervalMs } = this.options;
    let reported = false;
    if (this.current === null) {
      try {
        removeBackupTemps(dir);
      } catch (err) {
        reported = true;
        this.report(directoryFailure(err));
      }
    }
    let delayMs = 0;
    try {
      const now = this.now();
      const anchor = newestBackupAt(dir, now);
      if (anchor !== null) delayMs = Math.max(0, anchor + intervalMs - now);
    } catch (err) {
      if (!reported) this.report(directoryFailure(err));
    }
    this.arm(generation, delayMs);
  }

  /**
   * Ends the schedule. A running copy gets `drainTimeoutMs` to finish; then its signal is aborted
   * and the call still waits until the run has settled, since only that removes the run's
   * temporary file.
   */
  async stop(drainTimeoutMs: number = BACKUP_STOP_DRAIN_TIMEOUT_MS): Promise<void> {
    this.live = false;
    this.generation++;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    const run = this.current;
    if (run === null) return;
    let bound: ReturnType<typeof setTimeout> | undefined;
    const finished = await Promise.race([
      run.settled.then(() => true),
      new Promise<boolean>((resolve) => {
        bound = setTimeout(() => resolve(false), drainTimeoutMs);
        bound.unref();
      }),
    ]);
    clearTimeout(bound);
    if (!finished) run.controller.abort();
    await run.settled;
  }

  get isRunning(): boolean {
    return this.live;
  }

  private arm(generation: number, delayMs: number): void {
    if (generation !== this.generation) return;
    this.timer = setTimeout(() => this.fire(generation), delayMs);
    this.timer.unref();
  }

  private fire(generation: number): void {
    this.timer = null;
    if (this.current !== null) {
      this.arm(generation, this.options.intervalMs);
      return;
    }
    const run: Run = { controller: new AbortController(), settled: Promise.resolve() };
    this.current = run;
    run.settled = this.take(generation, run);
  }

  private async take(generation: number, run: Run): Promise<void> {
    const { dir, intervalMs, keep, label } = this.options;
    const startedAt = this.now();
    let at: Date;
    try {
      at = freeBackupTime(dir, new Date(startedAt));
    } catch {
      at = new Date(startedAt);
    }
    let failure: { err: unknown } | null = null;
    try {
      await this.engine.backupToDirectory(dir, {
        keep,
        label,
        signal: run.controller.signal,
        at,
      });
    } catch (err) {
      failure = { err };
    }
    if (this.current === run) this.current = null;
    if (generation !== this.generation) return;
    if (failure !== null) {
      if (failure.err instanceof VaultError && failure.err.code === ErrorCode.VAULT_LOCKED) {
        this.live = false;
        this.report(failure.err);
        return;
      }
      this.report(failure.err);
    }
    this.arm(generation, Math.min(intervalMs, Math.max(0, startedAt + intervalMs - this.now())));
  }

  private report(err: unknown): void {
    try {
      this.options.onError?.(err);
    } catch {
      // A host hook that throws changes nothing.
    }
  }
}
