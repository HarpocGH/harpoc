/**
 * Run `run` once and return the `code` of what it threw — better-sqlite3's
 * `SqliteError` carries the extended result code (`SQLITE_CONSTRAINT_NOTNULL`,
 * `SQLITE_CONSTRAINT_CHECK`, …) — or undefined when it returned normally or
 * threw something without a string `code`. The constraint pins assert on the
 * code alone; a message would vary with the SQLite build.
 */
export function sqliteErrorCode(run: () => unknown): string | undefined {
  try {
    run();
  } catch (err) {
    const code = (err as { code?: unknown } | null | undefined)?.code;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}
