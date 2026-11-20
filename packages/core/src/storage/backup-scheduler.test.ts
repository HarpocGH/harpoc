import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { VaultEngine } from "../vault-engine.js";
import { backupFileName } from "./backup-names.js";
import { BACKUP_STOP_DRAIN_TIMEOUT_MS, BackupScheduler } from "./backup-scheduler.js";
import type { BackupSchedulerOptions } from "./backup-scheduler.js";

const T0 = Date.UTC(2026, 10, 19, 10, 15, 0);
const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;
const LABEL = "--backup-dir";
const KEEP = 7;

type Backup = VaultEngine["backupToDirectory"];

interface HeldRun {
  readonly signal: AbortSignal;
  finish(): void;
  fail(err: unknown): void;
}

let dir: string;
let backup: Mock<Backup>;
let onError: Mock<(err: unknown) => void>;
let held: HeldRun[];
let scheduler: BackupScheduler | undefined;

beforeEach(() => {
  vi.useFakeTimers({ now: T0 });
  dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-backup-scheduler-")));
  backup = vi.fn<Backup>(async (target, options) => ({
    file: join(target, backupFileName(options.at as Date)),
  }));
  onError = vi.fn<(err: unknown) => void>();
  held = [];
  scheduler = undefined;
});

afterEach(async () => {
  for (const run of held) run.finish();
  const stopping = scheduler?.stop(0);
  await vi.runAllTimersAsync();
  await stopping;
  vi.restoreAllMocks();
  vi.useRealTimers();
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function place(...names: string[]): void {
  for (const name of names) writeFileSync(join(dir, name), name);
}

function copyAt(at: number): string {
  return backupFileName(new Date(at));
}

function tempOf(at: number): string {
  return `${copyAt(at)}.0123456789ab.tmp`;
}

function holdNextRun(): void {
  backup.mockImplementationOnce(
    (target, options) =>
      new Promise((resolve, reject) => {
        held.push({
          signal: options.signal as AbortSignal,
          finish: () => resolve({ file: join(target, backupFileName(options.at as Date)) }),
          fail: reject,
        });
      }),
  );
}

function heldRun(index: number): HeldRun {
  return held[index] as HeldRun;
}

function writeCopies(durationMs = 0): void {
  backup.mockImplementation(async (target, options) => {
    if (durationMs > 0) await new Promise((resolve) => setTimeout(resolve, durationMs));
    const name = backupFileName(options.at as Date);
    try {
      writeFileSync(join(target, name), name, { flag: "wx" });
    } catch (err) {
      throw new VaultError(
        ErrorCode.FILE_IO_ERROR,
        `could not write the backup (${(err as NodeJS.ErrnoException).code})`,
      );
    }
    return { file: join(target, name) };
  });
}

function unlinkErrno(path: string): string {
  try {
    unlinkSync(path);
  } catch (err) {
    return (err as NodeJS.ErrnoException).code as string;
  }
  throw new Error(`${path} could be unlinked`);
}

function expectReadFailure(reported: unknown, errno: string): void {
  expect(reported).toBeInstanceOf(VaultError);
  expect((reported as VaultError).code).toBe(ErrorCode.FILE_IO_ERROR);
  expect((reported as VaultError).message).toBe(`could not read the backup directory (${errno})`);
}

function startScheduler(overrides: Partial<BackupSchedulerOptions> = {}): BackupScheduler {
  const started = new BackupScheduler(
    { backupToDirectory: backup },
    { dir, intervalMs: HOUR_MS, keep: KEEP, label: LABEL, onError, ...overrides },
  );
  scheduler = started;
  started.start();
  return started;
}

describe("BackupScheduler", () => {
  it("an empty directory is backed up at once", async () => {
    const started = startScheduler();
    await vi.advanceTimersByTimeAsync(0);

    expect(backup).toHaveBeenCalledExactlyOnceWith(dir, {
      keep: KEEP,
      label: LABEL,
      signal: expect.any(AbortSignal),
      at: new Date(T0),
    });
    expect(started.isRunning).toBe(true);
    expect(onError).not.toHaveBeenCalled();
  });

  it("a start beside a fresh copy waits", async () => {
    place(copyAt(T0 - 10 * MINUTE_MS));
    startScheduler();

    await vi.advanceTimersByTimeAsync(50 * MINUTE_MS - 1);
    expect(backup).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(1);
  });

  it("a copy older than the interval is followed at once", async () => {
    place(copyAt(T0 - HOUR_MS - 1_000));
    startScheduler();
    await vi.advanceTimersByTimeAsync(0);

    expect(backup).toHaveBeenCalledTimes(1);
  });

  it("a copy from the future", async () => {
    place(copyAt(T0 + DAY_MS));
    startScheduler();
    await vi.advanceTimersByTimeAsync(0);
    expect(backup).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(HOUR_MS - 1);
    expect(backup).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(2);
  });

  it("a start beside a fresh copy and a copy from the future waits for the fresh one", async () => {
    place(copyAt(T0 - 10 * MINUTE_MS), copyAt(T0 + DAY_MS));
    startScheduler();

    await vi.advanceTimersByTimeAsync(50 * MINUTE_MS - 1);
    expect(backup).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(1);
  });

  it("beside a copy from the future a restarted daemon takes one copy, not one on every start", async () => {
    place(copyAt(T0 + DAY_MS));
    backup.mockImplementation(async (target, options) => {
      const name = backupFileName(options.at as Date);
      writeFileSync(join(target, name), name);
      return { file: join(target, name) };
    });
    const started = startScheduler();
    await vi.advanceTimersByTimeAsync(0);
    expect(backup).toHaveBeenCalledTimes(1);
    expect(readdirSync(dir).sort()).toEqual([copyAt(T0), copyAt(T0 + DAY_MS)]);

    await started.stop();
    await vi.advanceTimersByTimeAsync(20 * MINUTE_MS);
    started.start();
    await vi.advanceTimersByTimeAsync(20 * MINUTE_MS);
    await started.stop();
    started.start();

    await vi.advanceTimersByTimeAsync(20 * MINUTE_MS - 1);
    expect(backup).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(2);
    expect(backup.mock.calls[1]?.[1].at).toEqual(new Date(T0 + HOUR_MS));
  });

  it("a run whose second is taken by a copy stamped ahead takes the next free second", async () => {
    vi.setSystemTime(T0 + 30 * MINUTE_MS);
    place(copyAt(T0), copyAt(T0 + HOUR_MS));
    writeCopies(10_000);
    startScheduler();

    await vi.advanceTimersByTimeAsync(30 * MINUTE_MS - 1);
    expect(backup).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(1);
    expect(backup.mock.calls[0]?.[1].at).toEqual(new Date(T0 + HOUR_MS + 1_000));
    await vi.advanceTimersByTimeAsync(10_000);
    expect(readdirSync(dir)).toContain(copyAt(T0 + HOUR_MS + 1_000));
    expect(onError).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(HOUR_MS - 10_000 - 1);
    expect(backup).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(2);
  });

  it("a series stamped ahead is passed without a failed run", async () => {
    vi.setSystemTime(T0 + 30 * MINUTE_MS);
    place(copyAt(T0), copyAt(T0 + HOUR_MS), copyAt(T0 + 2 * HOUR_MS), copyAt(T0 + 3 * HOUR_MS));
    writeCopies();
    startScheduler();

    await vi.advanceTimersByTimeAsync(30 * MINUTE_MS + 2 * HOUR_MS);
    expect(backup.mock.calls.map((call) => call[1].at)).toEqual([
      new Date(T0 + HOUR_MS + 1_000),
      new Date(T0 + 2 * HOUR_MS + 1_000),
      new Date(T0 + 3 * HOUR_MS + 1_000),
    ]);
    expect(onError).not.toHaveBeenCalled();
  });

  it("the next run is one interval after the last one's start", async () => {
    holdNextRun();
    startScheduler();
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(20 * MINUTE_MS);
    heldRun(0).finish();

    await vi.advanceTimersByTimeAsync(40 * MINUTE_MS - 1);
    expect(backup).toHaveBeenCalledTimes(1);
    holdNextRun();
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(2);
    expect(backup.mock.calls[1]?.[1].at).toEqual(new Date(T0 + HOUR_MS));

    await vi.advanceTimersByTimeAsync(70 * MINUTE_MS);
    heldRun(1).finish();
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(3);
    expect(backup.mock.calls[2]?.[1].at).toEqual(new Date(T0 + 2 * HOUR_MS + 10 * MINUTE_MS));
  });

  it("a failed run is followed by the next", async () => {
    const failure = new VaultError(ErrorCode.FILE_IO_ERROR, "could not write the backup (test)");
    backup.mockRejectedValueOnce(failure);
    const started = startScheduler();
    await vi.advanceTimersByTimeAsync(0);

    expect(onError).toHaveBeenCalledExactlyOnceWith(failure);
    expect(started.isRunning).toBe(true);
    await vi.advanceTimersByTimeAsync(HOUR_MS - 1);
    expect(backup).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(2);
  });

  it("a sealed vault ends the schedule", async () => {
    const sealed = VaultError.vaultLocked();
    backup.mockRejectedValueOnce(sealed);
    const started = startScheduler();
    await vi.advanceTimersByTimeAsync(0);

    expect(onError).toHaveBeenCalledExactlyOnceWith(sealed);
    expect(vi.getTimerCount()).toBe(0);
    expect(started.isRunning).toBe(false);
    await vi.advanceTimersByTimeAsync(DAY_MS);
    expect(backup).toHaveBeenCalledTimes(1);
  });

  it("a run is never started beside a running one", async () => {
    holdNextRun();
    startScheduler();
    await vi.advanceTimersByTimeAsync(0);

    await vi.advanceTimersByTimeAsync(3 * HOUR_MS);
    expect(backup).toHaveBeenCalledTimes(1);
    heldRun(0).finish();
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(2);
  });

  it("stop waits for a running copy, then aborts it", async () => {
    holdNextRun();
    const started = startScheduler();
    await vi.advanceTimersByTimeAsync(0);
    const run = heldRun(0);

    let stopped = false;
    const stopping = started.stop().then(() => {
      stopped = true;
    });
    expect(started.isRunning).toBe(false);
    await vi.advanceTimersByTimeAsync(BACKUP_STOP_DRAIN_TIMEOUT_MS - 1);
    expect(run.signal.aborted).toBe(false);
    expect(stopped).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(run.signal.aborted).toBe(true);
    expect(stopped).toBe(false);

    run.fail(new VaultError(ErrorCode.DATABASE_ERROR, "backup did not finish"));
    await stopping;
    expect(vi.getTimerCount()).toBe(0);
    expect(onError).not.toHaveBeenCalled();
    expect(backup).toHaveBeenCalledTimes(1);
  });

  it("stop resolves once a running copy finishes, without aborting it", async () => {
    holdNextRun();
    const started = startScheduler();
    await vi.advanceTimersByTimeAsync(0);
    const run = heldRun(0);

    const stopping = started.stop();
    await vi.advanceTimersByTimeAsync(5_000);
    run.finish();
    await stopping;

    expect(run.signal.aborted).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(DAY_MS);
    expect(backup).toHaveBeenCalledTimes(1);
  });

  it("stop before the first run leaves no timer", async () => {
    const started = startScheduler();
    expect(vi.getTimerCount()).toBe(1);
    await started.stop();

    expect(vi.getTimerCount()).toBe(0);
    expect(started.isRunning).toBe(false);
    await vi.advanceTimersByTimeAsync(DAY_MS);
    expect(backup).not.toHaveBeenCalled();
  });

  it("an onError that throws stops nothing", async () => {
    mkdirSync(join(dir, tempOf(T0 - 5 * MINUTE_MS)));
    onError.mockImplementation(() => {
      throw new Error("the host's channel failed");
    });
    backup.mockRejectedValueOnce(new VaultError(ErrorCode.FILE_IO_ERROR, "could not write"));
    const started = startScheduler();
    expect(onError).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(0);
    expect(backup).toHaveBeenCalledTimes(1);
    expect(onError).toHaveBeenCalledTimes(2);
    expect(started.isRunning).toBe(true);
    await vi.advanceTimersByTimeAsync(HOUR_MS);
    expect(backup).toHaveBeenCalledTimes(2);
  });

  it("start removes a leftover temporary file before the first run", async () => {
    const copy = copyAt(T0 - 10 * MINUTE_MS);
    place(tempOf(T0 - 5 * MINUTE_MS), copy, "notes.txt");
    startScheduler();

    expect(readdirSync(dir).sort()).toEqual([copy, "notes.txt"]);
    await vi.advanceTimersByTimeAsync(50 * MINUTE_MS - 1);
    expect(backup).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(1);
    expect(onError).not.toHaveBeenCalled();
  });

  it("a sweep that fails is reported and the schedule goes on", async () => {
    const stuck = join(dir, tempOf(T0 - 5 * MINUTE_MS));
    mkdirSync(stuck);
    const errno = unlinkErrno(stuck);
    place(copyAt(T0 - 10 * MINUTE_MS));
    const started = startScheduler();

    expect(onError).toHaveBeenCalledTimes(1);
    expectReadFailure(onError.mock.calls[0]?.[0], errno);
    expect(started.isRunning).toBe(true);
    await vi.advanceTimersByTimeAsync(50 * MINUTE_MS - 1);
    expect(backup).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(1);
  });

  it("a directory that cannot be read at start is reported once and backed up at once", async () => {
    startScheduler({ dir: join(dir, "gone") });

    expect(onError).toHaveBeenCalledTimes(1);
    expectReadFailure(onError.mock.calls[0]?.[0], "ENOENT");
    await vi.advanceTimersByTimeAsync(0);
    expect(backup).toHaveBeenCalledExactlyOnceWith(join(dir, "gone"), expect.anything());
    await vi.advanceTimersByTimeAsync(HOUR_MS);
    expect(backup).toHaveBeenCalledTimes(2);
  });

  it("a clock set back during a run holds the next one no longer than one interval", async () => {
    let shiftMs = 0;
    holdNextRun();
    startScheduler({ now: () => Date.now() + shiftMs });
    await vi.advanceTimersByTimeAsync(0);
    shiftMs = -DAY_MS;
    heldRun(0).finish();

    await vi.advanceTimersByTimeAsync(HOUR_MS - 1);
    expect(backup).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(backup).toHaveBeenCalledTimes(2);
    expect(backup.mock.calls[1]?.[1].at).toEqual(new Date(T0 + HOUR_MS - DAY_MS));
  });

  it("a start during a stop's wait starts no copy beside the running one", async () => {
    holdNextRun();
    const started = startScheduler();
    await vi.advanceTimersByTimeAsync(0);

    const stopping = started.stop();
    started.start();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(backup).toHaveBeenCalledTimes(1);

    heldRun(0).finish();
    await stopping;
    expect(started.isRunning).toBe(true);
    await vi.advanceTimersByTimeAsync(HOUR_MS);
    expect(backup).toHaveBeenCalledTimes(2);
  });

  it("a start made while a copy still runs sweeps nothing", async () => {
    holdNextRun();
    const started = startScheduler();
    await vi.advanceTimersByTimeAsync(0);
    const running = tempOf(T0);
    place(running);

    const stopping = started.stop();
    started.start();
    expect(readdirSync(dir)).toEqual([running]);

    heldRun(0).finish();
    await stopping;
    await started.stop();
    started.start();
    expect(readdirSync(dir)).toEqual([]);
  });

  it("a start beside a running copy reports a directory it cannot read as a file error", async () => {
    const sub = join(dir, "sub");
    mkdirSync(sub);
    holdNextRun();
    const started = startScheduler({ dir: sub });
    await vi.advanceTimersByTimeAsync(0);
    rmSync(sub, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });

    const stopping = started.stop();
    started.start();
    expect(onError).toHaveBeenCalledTimes(1);
    expectReadFailure(onError.mock.calls[0]?.[0], "ENOENT");

    heldRun(0).finish();
    await stopping;
  });

  it("a second start changes nothing", async () => {
    const started = startScheduler();
    started.start();

    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(0);
    expect(backup).toHaveBeenCalledTimes(1);
  });

  it("neither the schedule's timer nor the stop's bound holds the process open", async () => {
    const armed = vi.spyOn(globalThis, "setTimeout");
    holdNextRun();
    const started = startScheduler();
    expect(armed).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(0);

    const stopping = started.stop();
    expect(armed).toHaveBeenCalledTimes(2);
    expect(armed.mock.results.map((result) => (result.value as NodeJS.Timeout).hasRef())).toEqual([
      false,
      false,
    ]);
    heldRun(0).finish();
    await stopping;
  });

  it("an interval that is not 1 to 2147483647 milliseconds is refused", async () => {
    const build = (intervalMs: number): BackupScheduler =>
      new BackupScheduler(
        { backupToDirectory: backup },
        { dir, intervalMs, keep: KEEP, label: LABEL },
      );

    for (const intervalMs of [Number.NaN, 0, -1, Number.POSITIVE_INFINITY, 2_147_483_648]) {
      const refused = await expectVaultError(() => build(intervalMs), ErrorCode.INVALID_INPUT);
      expect(refused.message).toBe("backup interval must be between 1 and 2147483647 milliseconds");
    }
    expect(build(1).isRunning).toBe(false);
    expect(build(2_147_483_647).isRunning).toBe(false);
  });
});
