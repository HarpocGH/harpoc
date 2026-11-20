import { readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";

const COPY_NAME = /^harpoc-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z\.db$/;
const TEMP_NAME = /^(harpoc-\d{8}T\d{6}Z\.db)\.[0-9a-f]{12}\.tmp(?:-journal|-wal|-shm)?$/;
const SIDE_SUFFIXES = ["-journal", "-wal", "-shm"];

/** A copy's name for `at`, in UTC to the second: `harpoc-20261119T101500Z.db`. */
export function backupFileName(at: Date): string {
  return `harpoc-${at.toISOString().slice(0, 19).replace(/[-:]/g, "")}Z.db`;
}

/** The epoch milliseconds a copy's name stands for; null for any other name, a stamp that is no date of the calendar included. */
export function parseBackupFileName(name: string): number | null {
  const match = COPY_NAME.exec(name);
  if (match === null) return null;
  const [, year, month, day, hour, minute, second] = match.map(Number);
  const at = Date.UTC(
    year as number,
    (month as number) - 1,
    day as number,
    hour as number,
    minute as number,
    second as number,
  );
  return backupFileName(new Date(at)) === name ? at : null;
}

/** A run's temporary name — a copy's name, a dot, 12 lower-case hex digits and `.tmp` — or that name with `-journal`, `-wal` or `-shm` after it. */
export function isBackupTempName(name: string): boolean {
  const match = TEMP_NAME.exec(name);
  return match !== null && parseBackupFileName(match[1] as string) !== null;
}

/** The names SQLite can leave beside the database file `path`: its `-journal`, `-wal` and `-shm`. */
export function backupSideNames(path: string): string[] {
  return SIDE_SUFFIXES.map((suffix) => `${path}${suffix}`);
}

/**
 * The newest stamp among the directory's copy names, a stamp later than `notAfter` left out when it
 * is given; null when none is left.
 */
export function newestBackupAt(dir: string, notAfter?: number): number | null {
  let newest: number | null = null;
  for (const name of readdirSync(dir)) {
    const at = parseBackupFileName(name);
    if (at === null || (notAfter !== undefined && at > notAfter)) continue;
    if (newest === null || at > newest) newest = at;
  }
  return newest;
}

/**
 * The first whole second at or after `at` whose copy name no entry of `dir` holds, of the sixty
 * seconds from `at` on; the last of them when all sixty are taken.
 */
export function freeBackupTime(dir: string, at: Date): Date {
  const taken = new Set(readdirSync(dir));
  const first = Math.floor(at.getTime() / 1_000) * 1_000;
  let candidate = new Date(first);
  for (let second = 0; second < 60; second++) {
    candidate = new Date(first + second * 1_000);
    if (!taken.has(backupFileName(candidate))) break;
  }
  return candidate;
}

function unlinkUnlessGone(path: string): void {
  try {
    unlinkSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
}

/** Removes every entry of `dir` that `isBackupTempName` accepts; a name gone already is skipped, any other failure throws. */
export function removeBackupTemps(dir: string): void {
  for (const name of readdirSync(dir)) {
    if (isBackupTempName(name)) unlinkUnlessGone(join(dir, name));
  }
}

/**
 * Removes the oldest copies of `dir` so that at most `keep` stay, `fresh` — the base name of the
 * copy just written — among them whatever its stamp; a name gone already is skipped, any other
 * failure throws.
 */
export function pruneBackups(dir: string, keep: number, fresh: string): void {
  const others = readdirSync(dir)
    .flatMap((name) => {
      const stamp = name === fresh ? null : parseBackupFileName(name);
      return stamp === null ? [] : [{ name, stamp }];
    })
    .sort((a, b) => b.stamp - a.stamp);
  for (const { name } of others.slice(keep - 1)) unlinkUnlessGone(join(dir, name));
}
