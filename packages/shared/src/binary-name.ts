/**
 * Basename normalization for command-allowlist classification.
 *
 * Shared by the known-interpreter gate (thesis §4.5.3) and the dedicated-context
 * gate: both decide what a command allowlist entry *is* from its basename, and
 * two derivations of "which binary is this" would eventually let one gate see a
 * name the other misses.
 *
 * Case-insensitive, with Windows executable extensions and trailing version
 * suffixes stripped (`Python3.12.EXE` → `python`). Accepts bare command names
 * and absolute paths (POSIX or Windows separators).
 */

/** Executable extensions stripped before comparison (mirrors the resolver's probe set). */
const EXECUTABLE_EXTENSIONS = [".exe", ".cmd", ".bat", ".com"];

/** Trailing version suffix: `python3`, `python3.12`, `php-8.2`, `perl5.36.0`. */
const VERSION_SUFFIX = /[-_.]?\d+(?:\.\d+)*$/;

export function normalizeBinaryBasename(entry: string): string {
  const basename = entry.trim().split(/[/\\]/).pop() ?? "";
  let name = basename.toLowerCase().replace(/[\s.]+$/, "");
  for (const ext of EXECUTABLE_EXTENSIONS) {
    if (name.endsWith(ext)) {
      name = name.slice(0, -ext.length);
      break;
    }
  }
  const unversioned = name.replace(VERSION_SUFFIX, "");
  return unversioned.length > 0 ? unversioned : name;
}
