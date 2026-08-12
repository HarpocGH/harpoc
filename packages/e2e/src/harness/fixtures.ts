import { existsSync, realpathSync } from "node:fs";
import { delimiter, join } from "node:path";

const isWin = process.platform === "win32";

/**
 * The child binary used to prove process-mediated injection.
 *
 * `printenv` rather than `node`: the command allowlist pins interpreters behind
 * the §4.5.3 acknowledgement gate, so allowlisting `node` would force the
 * harness to acknowledge an interpreter as routine setup and collapse the
 * L2/L3 capability-ladder split in the very fixture that proves the machinery.
 * `printenv` is not an interpreter, needs no acknowledgement, and prints
 * exactly the injected variables — which is the whole assertion.
 *
 * The harness targets Linux; the Windows candidate exists only so the
 * machinery self-check is runnable on a development host.
 */
const PRINTENV_CANDIDATES = [
  "/usr/bin/printenv",
  "/bin/printenv",
  "C:\\Program Files\\Git\\usr\\bin\\printenv.exe",
];

export function resolvePrintenv(): string {
  for (const candidate of PRINTENV_CANDIDATES) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(
    `no printenv binary found — looked in:\n${PRINTENV_CANDIDATES.map((c) => `  ${c}`).join("\n")}`,
  );
}

/**
 * Windows only. The ssh-injector matches the allowlisted `ssh` against what the
 * process PATH resolves `ssh` to, and the git-injector resolves `ssh` the same
 * way for GIT_SSH_COMMAND (F-6). Only the native Win32-OpenSSH client can read
 * the named-pipe agent — a Git-bundled MSYS ssh silently finds none — so put
 * System32\OpenSSH first, and both the request and the allowlist entry resolve
 * to it. No-op on POSIX, where /usr/bin holds the single ssh.
 */
export function preferNativeSsh(): void {
  if (!isWin) return;
  const dir = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "OpenSSH");
  const parts = (process.env.PATH ?? "").split(delimiter).filter(Boolean);
  if (parts[0]?.toLowerCase() === dir.toLowerCase()) return;
  process.env.PATH = [dir, ...parts.filter((p) => p.toLowerCase() !== dir.toLowerCase())].join(
    delimiter,
  );
}

function resolveOnPath(name: string): string | null {
  const exts = isWin ? ["", ".exe", ".com"] : [""];
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const candidate = join(dir, name + ext);
      if (existsSync(candidate)) {
        try {
          return realpathSync(candidate);
        } catch {
          return candidate;
        }
      }
    }
  }
  return null;
}

/**
 * The absolute ssh/git path to pin in the secret's command_allowlist. Resolved
 * through the same PATH the injector uses so the allowlist entry and the
 * injector's own resolution land on one real file (F-6); the injector realpaths
 * both sides, so returning the realpath here keeps the match exact.
 */
export function resolveSsh(): string {
  preferNativeSsh();
  const p = resolveOnPath("ssh");
  if (!p) throw new Error("no ssh binary found on PATH — install OpenSSH");
  return p;
}

export function resolveGit(): string {
  const p = resolveOnPath("git");
  if (!p) throw new Error("no git binary found on PATH — install git");
  return p;
}
