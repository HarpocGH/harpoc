/**
 * Known-interpreter detection for command allowlists (thesis §4.5.3).
 *
 * Allowlisting a shell or language interpreter voids the capability ladder for
 * a secret: `bash -c` or `python -c` accepts a free-form program as an
 * ordinary argument, reintroducing exactly the instruction vehicle that
 * shell-less direct execution excludes (L2/L3 collapse). The vault therefore
 * refuses to add a known interpreter to a command allowlist unless the
 * administrator supplies an explicit acknowledgement, and records both the
 * refusal and any acknowledged addition in the audit trail — the collapse must
 * be a deliberate, auditable policy decision, not an incidental one.
 *
 * Detection is by basename: case-insensitive, with Windows executable
 * extensions and trailing version suffixes stripped (`Python3.12.EXE` →
 * `python`). The list is curated, not exhaustive: it names binaries whose
 * ordinary invocation accepts an inline program (the `-c`/`-e` class), spawns
 * an interactive shell, fetches and executes arbitrary packages (the `npx`
 * class) or execs its argument (`env`). A renamed or symlinked interpreter
 * evades basename matching by construction — the gate targets deliberate
 * policy decisions by a trusted administrator, not adversarial evasion, which
 * for on-disk binaries is L4/L5 territory.
 */

/** Basenames of known interpreter binaries (matched after normalization). */
export const KNOWN_INTERPRETERS: ReadonlySet<string> = new Set([
  // POSIX shells
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "csh",
  "tcsh",
  "fish",
  "ash",
  "busybox",
  // Windows shells and script hosts
  "cmd",
  "powershell",
  "pwsh",
  "wscript",
  "cscript",
  // Language runtimes accepting inline programs
  "python",
  "pythonw",
  "py",
  "pypy",
  "node",
  "nodejs",
  "deno",
  "bun",
  "ts-node",
  "tsx",
  "perl",
  "ruby",
  "php",
  "lua",
  "tclsh",
  "awk",
  "gawk",
  "rscript",
  // Package runners (fetch and execute arbitrary packages)
  "npx",
  "pnpx",
  "bunx",
  "uvx",
  "pipx",
  // Exec trampoline (resolves and executes its first argument)
  "env",
]);

/** Executable extensions stripped before comparison (mirrors the resolver's probe set). */
const EXECUTABLE_EXTENSIONS = [".exe", ".cmd", ".bat", ".com"];

/** Trailing version suffix: `python3`, `python3.12`, `php-8.2`, `perl5.36.0`. */
const VERSION_SUFFIX = /[-_.]?\d+(?:\.\d+)*$/;

/**
 * The normalized interpreter name a command-allowlist entry resolves to, or
 * null when the entry does not name a known interpreter. Accepts bare command
 * names and absolute paths (POSIX or Windows separators).
 */
export function knownInterpreterName(entry: string): string | null {
  const basename = entry.trim().split(/[/\\]/).pop() ?? "";
  let name = basename.toLowerCase().replace(/[\s.]+$/, "");
  for (const ext of EXECUTABLE_EXTENSIONS) {
    if (name.endsWith(ext)) {
      name = name.slice(0, -ext.length);
      break;
    }
  }
  const unversioned = name.replace(VERSION_SUFFIX, "");
  const candidate = unversioned.length > 0 ? unversioned : name;
  return KNOWN_INTERPRETERS.has(candidate) ? candidate : null;
}

/**
 * The entries of a command allowlist that name known interpreters,
 * order-preserving and deduplicated. Returns the raw entries as supplied (for
 * error messages and audit detail), not the normalized names.
 */
export function findKnownInterpreters(entries: readonly string[]): string[] {
  const found: string[] = [];
  for (const entry of entries) {
    if (knownInterpreterName(entry) !== null && !found.includes(entry)) {
      found.push(entry);
    }
  }
  return found;
}
