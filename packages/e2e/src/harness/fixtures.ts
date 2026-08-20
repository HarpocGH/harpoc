import { existsSync } from "node:fs";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { controlledPathDirs, resolveExecutable } from "@harpoc/core";

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

/**
 * The absolute ssh/git path to pin in the secret's command_allowlist. Resolved
 * with the injector's OWN resolver against the same PATH (F-6): a hand-rolled
 * walk here previously accepted directories and non-regular files (existsSync
 * is true for a PATH entry's subdirectory named `git`), pinning a path the
 * injector's resolution would never produce and failing every arm with a
 * misleading COMMAND_NOT_ALLOWED. `resolveExecutable` stats for a regular
 * file, excludes batch files and realpaths — the allowlist entry and the
 * injector land on one real file by construction.
 */
export function resolveSsh(): string {
  preferNativeSsh();
  const p = resolveExecutable("ssh", controlledPathDirs());
  if (!p) throw new Error("no ssh binary found on PATH — install OpenSSH");
  return p;
}

export function resolveGit(): string {
  const p = resolveExecutable("git", controlledPathDirs());
  if (!p) throw new Error("no git binary found on PATH — install git");
  return p;
}

/**
 * The absolute `sftp` path to pin in a secret's command_allowlist for the SFTP
 * context (v1.3). Resolved with the injector's OWN resolver against the same
 * PATH (F-6), and via `preferNativeSsh` on Windows so the native Win32-OpenSSH
 * `sftp.exe` (the only one that can read the named-pipe agent) wins over any
 * MSYS/Git-bundled copy — the same reasoning `resolveSsh` documents.
 */
export function resolveSftp(): string {
  preferNativeSsh();
  const p = resolveExecutable("sftp", controlledPathDirs());
  if (!p) throw new Error("no sftp binary found on PATH — install OpenSSH");
  return p;
}

/**
 * The absolute `docker` path to pin in a secret's command_allowlist for the
 * docker-registry context (v1.3). Same resolver as ssh/git so the allowlist
 * entry and the injector's resolution land on one real file.
 */
export function resolveDocker(): string {
  const p = resolveExecutable("docker", controlledPathDirs());
  if (!p) throw new Error("no docker binary found on PATH — install Docker");
  return p;
}

/**
 * The compiled entry points the out-of-process surfaces spawn. Both are build
 * artifacts, so a missing one is a setup error with an actionable recovery, not
 * a skip: a silently skipped surface would drop a third of the demonstration
 * matrix while the suite stayed green.
 *
 * The MCP server path must keep its `…/mcp-server/dist/index.js` tail — the
 * bin's direct-run guard matches on exactly that suffix and would otherwise
 * load the module without starting a server.
 */
function packageArtifact(pkg: string, relative: string, recovery: string): string {
  const path = fileURLToPath(new URL(`../../../${pkg}/${relative}`, import.meta.url));
  if (!existsSync(path)) {
    throw new Error(`${pkg} is not built (${path} missing)\n  run: ${recovery}`);
  }
  return path;
}

export function resolveMcpServerEntry(): string {
  return packageArtifact("mcp-server", "dist/index.js", "npx pnpm build");
}

export function resolveCliEntry(): string {
  return packageArtifact("cli", "dist/index.js", "npx pnpm build");
}

/**
 * The openssl the PKI fixture tests inspect certificates with. Rarely on the
 * Windows PATH; Git-for-Windows bundles one under usr\bin, resolved the same
 * way resolveBash finds its bash.
 */
export function resolveOpenssl(): string {
  const onPath = resolveExecutable("openssl", controlledPathDirs());
  if (onPath) return onPath;
  if (isWin) {
    const candidates: string[] = [];
    const git = resolveExecutable("git", controlledPathDirs());
    if (git) {
      for (const root of [dirname(dirname(git)), dirname(dirname(dirname(git)))]) {
        candidates.push(join(root, "usr", "bin", "openssl.exe"));
      }
    }
    candidates.push("C:\\Program Files\\Git\\usr\\bin\\openssl.exe");
    for (const c of candidates) {
      const p = resolveExecutable(c, []);
      if (p) return p;
    }
  }
  throw new Error("no openssl found — install OpenSSL (Git for Windows bundles one)");
}

/**
 * The bash that runs the fixture generators. On POSIX this is PATH bash. On a
 * Windows dev host `bash` on PATH may resolve to the System32 WSL launcher,
 * which forwards the Windows script path verbatim into the Linux environment
 * ("No such file or directory") — so Git-for-Windows' own bash is derived from
 * the resolved git binary (…\Git\{cmd,mingw64\bin,bin}\git.exe →
 * …\Git\bin\bash.exe) with the standard install locations as fallback; a PATH
 * bash is accepted only when it is not under System32. `bin\bash.exe` — the
 * launcher that bootstraps the MSYS PATH — deliberately precedes
 * `usr\bin\bash.exe`, which runs the script with the ambient Windows PATH and
 * dies on the first coreutil (`dirname: command not found`, live-verified).
 * Dist-free twin for provisioning: scripts/generate-fixtures.mjs — keep the
 * candidate order in sync.
 */
export function resolveBash(): string {
  if (!isWin) {
    const p = resolveExecutable("bash", controlledPathDirs());
    if (!p) throw new Error("no bash found on PATH — install bash");
    return p;
  }
  const candidates: string[] = [];
  const git = resolveExecutable("git", controlledPathDirs());
  if (git) {
    for (const root of [dirname(dirname(git)), dirname(dirname(dirname(git)))]) {
      candidates.push(join(root, "bin", "bash.exe"), join(root, "usr", "bin", "bash.exe"));
    }
  }
  candidates.push(
    "C:\\Program Files\\Git\\bin\\bash.exe",
    "C:\\Program Files\\Git\\usr\\bin\\bash.exe",
  );
  for (const c of candidates) {
    const p = resolveExecutable(c, []);
    if (p) return p;
  }
  const onPath = resolveExecutable("bash", controlledPathDirs());
  if (onPath && !/\\windows\\system32\\/i.test(onPath)) return onPath;
  throw new Error(
    `no usable bash found — the WSL launcher cannot run Windows script paths; install Git for Windows (looked in:\n${candidates.map((c) => `  ${c}`).join("\n")})`,
  );
}
