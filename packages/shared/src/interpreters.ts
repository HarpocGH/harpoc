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
 * `python`). Two tiers share one acknowledgement flag and one refusal. Tier
 * one, `KNOWN_INTERPRETERS`: binaries whose ordinary invocation accepts an
 * inline program (the `-c`/`-e` class), spawns an interactive shell, fetches
 * and executes arbitrary packages (the `npx` class) or execs its argument
 * (`env`). Tier two, `EXEC_WRAPPERS` (R6(ii), 2026-09-04): binaries whose
 * argv is itself a command (`sudo`, `xargs`, `nohup`, `timeout`, …) or that
 * exec arbitrary programs from an argument (`find -exec`, `tar --to-command`,
 * `rsync -e`, `make` recipes). Both lists are curated, not exhaustive —
 * illustrative-complete, extended when a case surfaces: the boundary is the
 * deny-by-default absolute-path allowlist, the tiers are an audited speed
 * bump. One list serves every platform, and the entry's own path settles the
 * two names a Windows system directory ships as something else: an entry
 * naming `find` (a text filter) or `timeout` (a sleep) directly inside
 * `\Windows\System32` or `\Windows\SysWOW64` — any drive, either separator —
 * is not a wrapper, on every host, so an acknowledgement row means the same
 * thing wherever the policy was written. A bare `find`, a relative path, a
 * subdirectory of those two, and Git for Windows' own GNU `find.exe` under
 * `usr\bin` (which does have `-exec`) all stay wrappers (D10, 2026-09-06).
 * Basename matching alone is evaded
 * by a rename, but not by a symlink: the policy-write gate resolves each newly
 * added entry on the vault's controlled PATH and matches the target too (a
 * symlink to `sh` is `sh`), the same parity the use-time gate has, so the
 * residual is only what the resolver cannot resolve. The gate targets
 * deliberate policy decisions by a trusted administrator, not adversarial
 * evasion, which for on-disk binaries is L4/L5 territory.
 */

import { normalizeBinaryBasename } from "./binary-name.js";

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

/**
 * Basenames of exec wrappers (matched after normalization) — the second
 * acknowledgement tier. Disjoint from KNOWN_INTERPRETERS by test. The vault's
 * own isolation wrappers (`unshare`, `setpriv`, `bwrap`) belong here too: a
 * user allowlisting one of them as a command hands it arbitrary argv exactly
 * as `sudo` would.
 */
export const EXEC_WRAPPERS: ReadonlySet<string> = new Set([
  // argv is itself a command
  "xargs",
  "sudo",
  "su",
  "doas",
  "nohup",
  "timeout",
  "nice",
  "ionice",
  "setsid",
  "chroot",
  "nsenter",
  "unshare",
  "setpriv",
  "bwrap",
  "systemd-run",
  "stdbuf",
  "chrt",
  "taskset",
  "flock",
  "strace",
  "ltrace",
  "gdb",
  "watch",
  "parallel",
  // executes arbitrary programs named in an argument
  "find",
  "tar",
  "rsync",
  "make",
  // Windows
  "forfiles",
  "runas",
  "schtasks",
]);

/**
 * The two EXEC_WRAPPERS names a Windows system directory ships as something
 * else: `find.exe` there is a text filter and `timeout.exe` a sleep, and
 * neither execs an argument. Keyed on the entry's own path rather than on the
 * host, so an acknowledgement row means the same thing wherever the policy was
 * written — Git for Windows ships GNU `find.exe` (with `-exec`) under
 * `usr\bin`, so the bare name cannot carry the distinction (D10, 2026-09-06).
 */
const SYSTEM_DIRECTORY_EXEMPT: ReadonlySet<string> = new Set(["find", "timeout"]);

/** A drive-rooted entry sitting directly in \Windows\System32 or \Windows\SysWOW64. */
const WINDOWS_SYSTEM_DIRECTORY = /^[a-z]:[/\\]windows[/\\]sys(?:tem32|wow64)[/\\][^/\\]+$/;

/**
 * The normalized interpreter name a command-allowlist entry resolves to, or
 * null when the entry does not name a known interpreter. Accepts bare command
 * names and absolute paths (POSIX or Windows separators).
 */
export function knownInterpreterName(entry: string): string | null {
  const candidate = normalizeBinaryBasename(entry);
  return KNOWN_INTERPRETERS.has(candidate) ? candidate : null;
}

/**
 * The normalized exec-wrapper name a command-allowlist entry resolves to, or
 * null when the entry does not name one. Same normalization as
 * knownInterpreterName; a name is never in both tiers. `find` and `timeout`
 * are exempt when the entry names one of them directly inside a Windows system
 * directory — see SYSTEM_DIRECTORY_EXEMPT.
 */
export function execWrapperName(entry: string): string | null {
  const candidate = normalizeBinaryBasename(entry);
  if (!EXEC_WRAPPERS.has(candidate)) return null;
  if (
    SYSTEM_DIRECTORY_EXEMPT.has(candidate) &&
    WINDOWS_SYSTEM_DIRECTORY.test(entry.trim().toLowerCase())
  ) {
    return null;
  }
  return candidate;
}
