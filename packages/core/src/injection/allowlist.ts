import { statSync, realpathSync } from "node:fs";
import { delimiter, isAbsolute, join, resolve } from "node:path";
import { VaultError } from "@harpoc/shared";

/**
 * Per-secret allowlist enforcement for the two injection mechanisms.
 *
 * URL allowlisting (request-mediated) constrains the endpoints a credential may
 * be injected into. Command allowlisting (process-mediated) constrains which
 * binaries may be spawned with a credential; enforcement pins the request to a
 * resolved absolute path so bypass requires replacing the binary on disk.
 */

// ---------------------------------------------------------------------------
// URL allowlist
// ---------------------------------------------------------------------------

/**
 * Returns true if `url` is permitted by `patterns`. An empty allowlist is not
 * enforced (returns true) — URL allowlisting is an optional, opt-in layer atop
 * the mandatory SSRF validation.
 *
 * A pattern matches when scheme, host and port match and the pattern path (with
 * `*` wildcards) matches the URL path. A leading `*.` in the pattern host is a
 * subdomain wildcard. Query and fragment are not considered.
 */
export function matchesUrlAllowlist(url: string, patterns: string[]): boolean {
  if (patterns.length === 0) return true;
  let target: URL;
  try {
    target = new URL(url);
  } catch {
    return false;
  }
  return patterns.some((pattern) => matchesUrlPattern(target, pattern));
}

// scheme://host[:port][/path] — host and path may contain `*` wildcards. The
// pattern is parsed directly (not via URL) so wildcards survive intact.
const PATTERN_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/;

function matchesUrlPattern(target: URL, pattern: string): boolean {
  const match = PATTERN_RE.exec(pattern.trim());
  if (!match) return false;
  const scheme = match[1];
  const host = match[2];
  if (scheme === undefined || host === undefined) return false;
  const port = match[3] ?? "";
  const path = match[4] ?? "/";

  if (`${scheme.toLowerCase()}:` !== target.protocol) return false;
  if (port !== target.port) return false;
  if (!matchHost(host, target.hostname)) return false;
  return globMatch(path, target.pathname);
}

function matchHost(patternHost: string, host: string): boolean {
  const p = patternHost.toLowerCase();
  const h = host.toLowerCase();
  if (p === h) return true;
  if (p.startsWith("*.")) {
    const suffix = p.slice(1); // ".example.com"
    return h.endsWith(suffix) && h.length > suffix.length;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Host / host:port allowlist (SSH, Git-over-SSH, database targets)
// ---------------------------------------------------------------------------

/**
 * Returns true if `host` is permitted by `patterns` (bare-host patterns with an
 * optional `*.` subdomain wildcard). An empty allowlist is not enforced (returns
 * true) — like the URL allowlist, this is an optional layer; process-mediated
 * callers (SSH, Git-over-SSH) additionally reject an empty allowlist themselves
 * for fail-safe deny.
 */
export function matchesHostAllowlist(host: string, patterns: string[]): boolean {
  if (patterns.length === 0) return true;
  return patterns.some((p) => matchHost(p.trim(), host));
}

/**
 * Returns true if `host`:`port` is permitted by `patterns`. A pattern may be a
 * bare host (matches any port) or `host:port` (port must match exactly). Host
 * matching supports the `*.` subdomain wildcard. An empty allowlist is not
 * enforced (returns true) — the mandatory floor for the database context is the
 * SSRF check plus TLS verification.
 */
export function matchesHostPortAllowlist(host: string, port: number, patterns: string[]): boolean {
  if (patterns.length === 0) return true;
  return patterns.some((raw) => {
    const p = raw.trim();
    const colon = p.lastIndexOf(":");
    if (colon > 0 && /^\d+$/.test(p.slice(colon + 1))) {
      const patternHost = p.slice(0, colon);
      const patternPort = p.slice(colon + 1);
      if (patternPort !== String(port)) return false;
      return matchHost(patternHost, host);
    }
    return matchHost(p, host);
  });
}

/** Full-anchored glob where `*` matches any run of characters. */
function globMatch(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").split("*").join(".*");
  return new RegExp(`^${escaped}$`).test(value);
}

// ---------------------------------------------------------------------------
// Command allowlist
// ---------------------------------------------------------------------------

/**
 * Executable extensions probed when resolving a bare command name. Windows
 * batch files (`.cmd`/`.bat`) are deliberately absent — see `isWindowsBatchFile`.
 */
const EXECUTABLE_EXTENSIONS = process.platform === "win32" ? ["", ".exe", ".com"] : [""];

/**
 * Windows batch files are never resolvable as commands. Spawning a `.cmd`/`.bat`
 * with `shell:false` is cmd.exe interpretation in disguise: Node versions
 * before the CVE-2024-27980 fix silently wrapped such spawns in cmd.exe — an
 * argument-injection surface that collapses the no-shell property the process
 * context is built on — and patched versions refuse them with EINVAL. The
 * vault enforces the exclusion itself rather than inheriting it from the
 * runtime's version. Checked against the final symlink-resolved path so a
 * symlink cannot smuggle a batch file in.
 */
function isWindowsBatchFile(p: string): boolean {
  return process.platform === "win32" && /\.(cmd|bat)$/i.test(p);
}

/**
 * The vault's own PATH, used both to resolve requested commands and as the
 * child's PATH. The agent controls only the command/args, never this value, so
 * it cannot redirect resolution to a binary it planted on a custom PATH.
 */
export function controlledPathDirs(): string[] {
  const raw = process.env.PATH ?? process.env.Path ?? "";
  return raw.split(delimiter).filter((d) => d.length > 0);
}

function normalizeForCompare(p: string): string {
  return process.platform === "win32" ? p.toLowerCase() : p;
}

/**
 * Resolve a command (bare name or absolute path) to an existing executable's
 * absolute, symlink-resolved path. Returns null when it cannot be resolved.
 * Relative paths containing a separator are rejected (null) — callers must use
 * a bare name resolved against the controlled PATH or an absolute path. On
 * Windows, batch files are never resolved — neither probed for bare names nor
 * accepted as absolute paths.
 */
export function resolveExecutable(command: string, pathDirs: string[]): string | null {
  const candidates: string[] = [];
  if (isAbsolute(command)) {
    candidates.push(command);
  } else if (command.includes("/") || command.includes("\\")) {
    return null;
  } else {
    for (const dir of pathDirs) candidates.push(join(dir, command));
  }

  for (const base of candidates) {
    for (const ext of EXECUTABLE_EXTENSIONS) {
      const full = base + ext;
      try {
        if (statSync(full).isFile()) {
          let resolved: string;
          try {
            resolved = realpathSync(full);
          } catch {
            resolved = resolve(full);
          }
          if (isWindowsBatchFile(resolved)) continue;
          return resolved;
        }
      } catch {
        // not here — keep probing
      }
    }
  }
  return null;
}

/**
 * Enforce the command allowlist and return the resolved absolute path to spawn.
 *
 * Deny-by-default: an empty allowlist rejects every command (Saltzer fail-safe
 * defaults). Both the requested command and each allowlist entry are resolved to
 * absolute paths against the same controlled PATH, then compared, so a bare name
 * and its absolute path are equivalent and PATH-shadowing cannot widen the set.
 *
 * @throws VaultError COMMAND_NOT_ALLOWED when the command is not permitted.
 */
export function resolveAndMatchCommand(
  command: string,
  allowlist: string[],
  pathDirs: string[],
): string {
  if (allowlist.length === 0) {
    throw VaultError.commandNotAllowed(command);
  }

  const resolvedRequest = resolveExecutable(command, pathDirs);
  if (!resolvedRequest) {
    throw VaultError.commandNotAllowed(command);
  }

  const allowed = new Set<string>();
  for (const entry of allowlist) {
    const resolvedEntry = resolveExecutable(entry, pathDirs);
    if (resolvedEntry) allowed.add(normalizeForCompare(resolvedEntry));
  }

  if (!allowed.has(normalizeForCompare(resolvedRequest))) {
    throw VaultError.commandNotAllowed(command);
  }

  return resolvedRequest;
}
