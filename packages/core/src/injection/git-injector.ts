import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ConnectionConfig, GitAction, GitResult, InjectionPolicy } from "@harpoc/shared";
import { DEFAULT_GIT_TIMEOUT_MS, ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import {
  controlledPathDirs,
  matchesHostAllowlist,
  matchesUrlAllowlist,
  resolveAndMatchCommand,
  resolveExecutable,
} from "./allowlist.js";
import { spawnCaptured } from "./spawn-captured.js";
import { EphemeralSshAgent } from "./ssh-agent/index.js";
import { buildSshEnv, isHostKeyFailure, sshHardeningArgs, writeKnownHosts } from "./ssh-common.js";
import { validateUrl } from "./url-validator.js";

/** git args that turn data into an instruction vehicle (config/hook/transport execution).
 *  Matched by name prefix, so both `--template=<dir>` and `--template <dir>` are caught
 *  (the value arg on its own is inert). `--template`/`--separate-git-dir` run hooks /
 *  relocate the git dir at clone time — clone-time local code execution vectors. */
const DANGEROUS_ARG_PREFIXES = [
  "-c",
  "--config",
  "--config-env",
  "--upload-pack",
  "--receive-pack",
  "--exec",
  "--template",
  "--separate-git-dir",
];

/** Shorthands dangerous only for specific operations. `-u` is `--upload-pack` for
 *  `clone` (transport-program execution) but `--set-upstream` for `push` (benign),
 *  so it is blocked per-operation rather than globally. */
const CLONE_DANGEROUS_ARG_PREFIXES = ["-u"];

/** Repository transports that can execute local commands — never allowed. */
const FORBIDDEN_REPO_PREFIXES = ["ext::", "fd::", "file:", "git+"];

/** The bundled askpass helper: prints the username or token from the environment. */
const ASKPASS_HELPER_SRC = `const prompt = (process.argv[2] || "").toLowerCase();
const isUser = prompt.includes("user");
const out = isUser ? (process.env.HARPOC_GIT_USERNAME || "") : (process.env.HARPOC_GIT_PASSWORD || "");
process.stdout.write(out + "\\n");
`;

/**
 * Executes a Git operation, authenticating over HTTPS (request-mediated, via a
 * git-credential/askpass helper) or SSH (process-mediated, via the ephemeral
 * ssh-agent), selected by the repository transport (thesis §4.5.6). The
 * credential never appears in the command output or the agent's context.
 *
 * Security controls realized here:
 *  - Transport allowlisting: only https and ssh remotes; ext::/file:/git+ rejected.
 *  - Dangerous-arg rejection: -c/--config/--upload-pack/... cannot be smuggled in.
 *  - Target allowlist on both transports (URL patterns for HTTPS, host patterns
 *    for SSH — fail-safe deny), plus SSRF + HTTPS-only for HTTPS remotes and
 *    strict pinned host-key verification for SSH remotes.
 *  - Command allowlist: the git binary is pinned to a resolved absolute path.
 */
export class GitInjector {
  constructor(private readonly auditLogger: AuditLogger | null) {}

  async executeWithSecret(
    action: GitAction,
    secretValue: Uint8Array,
    policy: InjectionPolicy,
    config: ConnectionConfig | undefined,
    secretId?: string,
  ): Promise<GitResult> {
    const transport = detectTransport(action.repository);
    if (!transport) {
      this.audit(action, secretId, { error: "GIT_UNSUPPORTED_TRANSPORT" }, false);
      throw VaultError.gitUnsupportedTransport(action.repository);
    }

    assertSafeArgs(action.operation, action.args);
    if (action.working_directory && action.working_directory.startsWith("-")) {
      throw VaultError.invalidGitConfig("working_directory must not start with '-'");
    }

    let gitPath: string;
    try {
      gitPath = resolveAndMatchCommand("git", policy.command_allowlist, controlledPathDirs());
    } catch (err) {
      if (err instanceof VaultError) this.audit(action, secretId, { error: err.code }, false);
      throw err;
    }

    return transport === "https"
      ? this.runHttps(action, gitPath, secretValue, policy, secretId)
      : this.runSsh(action, gitPath, secretValue, policy, config, secretId);
  }

  private async runHttps(
    action: GitAction,
    gitPath: string,
    secretValue: Uint8Array,
    policy: InjectionPolicy,
    secretId: string | undefined,
  ): Promise<GitResult> {
    // Mandatory floor: HTTPS + SSRF. Optional layer: per-secret URL allowlist.
    try {
      await validateUrl(action.repository);
    } catch (err) {
      if (err instanceof VaultError) this.audit(action, secretId, { error: err.code }, false);
      throw err;
    }
    if (!matchesUrlAllowlist(action.repository, policy.url_allowlist)) {
      this.audit(action, secretId, { error: "URL_NOT_ALLOWED" }, false);
      throw VaultError.urlNotAllowed(action.repository);
    }

    const { user, password } = parseGitCredential(secretValue);
    const { args, cwd } = buildGitArgs(action);
    const timeoutMs = action.timeout_ms ?? DEFAULT_GIT_TIMEOUT_MS;
    const askpass = writeAskpass();
    try {
      const env = baseGitEnv(policy.env_allowlist);
      env.GIT_ASKPASS = askpass.launcher;
      env.GIT_TERMINAL_PROMPT = "0";
      env.HARPOC_GIT_USERNAME = user;
      env.HARPOC_GIT_PASSWORD = password;
      // The username is credential material too; a 1–2 char username would
      // shred unrelated output, so such fragments stay unredacted.
      const redact = user.length >= 3 ? [password, user] : [password];
      const networkIsolation = policy.network_isolation === true;
      let r: import("./spawn-captured.js").SpawnCapturedResult;
      try {
        r = await spawnCaptured(gitPath, args, {
          env,
          cwd,
          timeoutMs,
          redact,
          networkIsolation,
        });
      } catch (err) {
        if (err instanceof VaultError) {
          this.audit(
            action,
            secretId,
            { transport: "https", error: err.code, network_isolation: networkIsolation },
            false,
          );
        }
        throw err;
      }
      const result = toGitResult(action, r);
      this.audit(
        action,
        secretId,
        {
          transport: "https",
          exit_code: r.exit_code,
          network_isolation: networkIsolation,
          ...(r.isolation_mechanism ? { isolation_mechanism: r.isolation_mechanism } : {}),
        },
        result.error === undefined,
      );
      return result;
    } finally {
      askpass.dispose();
    }
  }

  private async runSsh(
    action: GitAction,
    gitPath: string,
    secretValue: Uint8Array,
    policy: InjectionPolicy,
    config: ConnectionConfig | undefined,
    secretId: string | undefined,
  ): Promise<GitResult> {
    const host = parseSshHost(action.repository);
    if (!host) {
      this.audit(action, secretId, { error: "INVALID_GIT_CONFIG" }, false);
      throw VaultError.invalidGitConfig("could not parse SSH host from repository");
    }
    // Host allowlist — fail-safe deny (process-mediated posture).
    if (policy.host_allowlist.length === 0 || !matchesHostAllowlist(host, policy.host_allowlist)) {
      this.audit(action, secretId, { host, error: "HOST_NOT_ALLOWED" }, false);
      throw VaultError.hostNotAllowed(host);
    }
    const knownHosts = config?.ssh?.known_hosts;
    if (!knownHosts || knownHosts.length === 0) {
      this.audit(action, secretId, { host, error: "SSH_NOT_CONFIGURED" }, false);
      throw VaultError.sshNotConfigured();
    }
    const sshPath = resolveExecutable("ssh", controlledPathDirs());
    if (!sshPath) {
      throw VaultError.invalidGitConfig("ssh binary not found on the controlled PATH");
    }

    const keyPem = Buffer.from(secretValue).toString("utf8");
    const { args, cwd } = buildGitArgs(action);
    const timeoutMs = action.timeout_ms ?? DEFAULT_GIT_TIMEOUT_MS;
    const kh = writeKnownHosts(knownHosts);

    let agent: EphemeralSshAgent;
    try {
      agent = await EphemeralSshAgent.start(keyPem);
    } catch (err) {
      kh.dispose();
      if (err instanceof VaultError) this.audit(action, secretId, { host, error: err.code }, false);
      throw err;
    }

    try {
      const env = buildSshEnv(agent.authSock, policy.env_allowlist);
      env.GIT_SSH_COMMAND = toCommandString([
        sshPath,
        ...sshHardeningArgs(kh.file, Math.max(1, Math.ceil(timeoutMs / 1000))),
      ]);
      env.GIT_TERMINAL_PROMPT = "0";
      const networkIsolation = policy.network_isolation === true;
      let r: import("./spawn-captured.js").SpawnCapturedResult;
      try {
        r = await spawnCaptured(gitPath, args, {
          env,
          cwd,
          timeoutMs,
          redact: [keyPem],
          networkIsolation,
        });
      } catch (err) {
        if (err instanceof VaultError) {
          this.audit(
            action,
            secretId,
            { transport: "ssh", host, error: err.code, network_isolation: networkIsolation },
            false,
          );
        }
        throw err;
      }

      if (isHostKeyFailure(r.stderr)) {
        this.audit(action, secretId, { host, error: "SSH_HOST_KEY_MISMATCH" }, false);
        throw VaultError.sshHostKeyMismatch(host);
      }

      const result = toGitResult(action, r);
      this.audit(
        action,
        secretId,
        {
          transport: "ssh",
          host,
          exit_code: r.exit_code,
          network_isolation: networkIsolation,
          ...(r.isolation_mechanism ? { isolation_mechanism: r.isolation_mechanism } : {}),
        },
        result.error === undefined,
      );
      return result;
    } finally {
      agent.dispose();
      kh.dispose();
    }
  }

  private audit(
    action: GitAction,
    secretId: string | undefined,
    detail: Record<string, unknown>,
    success: boolean,
  ): void {
    this.auditLogger?.log({
      eventType: "secret.use",
      secretId,
      detail: { context: "git", operation: action.operation, ...detail },
      success,
    });
  }
}

function detectTransport(repository: string): "https" | "ssh" | null {
  const repo = repository.trim();
  if (FORBIDDEN_REPO_PREFIXES.some((p) => repo.toLowerCase().startsWith(p))) return null;
  if (/^https?:\/\//i.test(repo)) return "https";
  if (/^ssh:\/\//i.test(repo)) return "ssh";
  // scp-like: user@host:path
  if (/^[^@/]+@[^:/]+:/.test(repo)) return "ssh";
  return null;
}

function assertSafeArgs(operation: GitAction["operation"], args: string[] | undefined): void {
  const prefixes =
    operation === "clone"
      ? [...DANGEROUS_ARG_PREFIXES, ...CLONE_DANGEROUS_ARG_PREFIXES]
      : DANGEROUS_ARG_PREFIXES;
  for (const arg of args ?? []) {
    const a = arg.trim();
    if (prefixes.some((p) => a === p || a.startsWith(p))) {
      throw VaultError.invalidGitConfig(`disallowed git argument: ${arg}`);
    }
  }
}

function parseSshHost(repository: string): string | null {
  const repo = repository.trim();
  if (/^ssh:\/\//i.test(repo)) {
    try {
      return new URL(repo).hostname || null;
    } catch {
      return null;
    }
  }
  const m = /^[^@/]+@([^:/]+):/.exec(repo);
  return m ? (m[1] ?? null) : null;
}

function parseGitCredential(value: Uint8Array): { user: string; password: string } {
  const s = Buffer.from(value).toString("utf8");
  const i = s.indexOf(":");
  if (i < 0) return { user: "x-access-token", password: s };
  return { user: s.slice(0, i), password: s.slice(i + 1) };
}

function buildGitArgs(action: GitAction): { args: string[]; cwd: string | undefined } {
  const safeArgs = action.args ?? [];
  if (action.operation === "clone") {
    const dest = action.working_directory ? [action.working_directory] : [];
    return { args: ["clone", ...safeArgs, action.repository, ...dest], cwd: undefined };
  }
  const wd = action.working_directory;
  if (!wd) {
    throw VaultError.invalidGitConfig(`working_directory is required for ${action.operation}`);
  }
  assertDirectory(wd);
  return { args: [action.operation, ...safeArgs, action.repository], cwd: wd };
}

function assertDirectory(dir: string): void {
  try {
    if (!statSync(dir).isDirectory()) {
      throw VaultError.invalidGitConfig(`working_directory is not a directory: ${dir}`);
    }
  } catch (err) {
    if (err instanceof VaultError) throw err;
    throw VaultError.invalidGitConfig(`working_directory does not exist: ${dir}`);
  }
}

/** Clean base environment for a spawned git process (HTTPS transport). */
function baseGitEnv(envAllowlist: string[]): Record<string, string> {
  const env: Record<string, string> = {};
  const path = process.env.PATH ?? process.env.Path;
  if (path) env.PATH = path;
  if (process.platform === "win32" && process.env.SystemRoot) {
    env.SystemRoot = process.env.SystemRoot;
  }
  for (const name of envAllowlist) {
    const v = process.env[name];
    if (v !== undefined) env[name] = v;
  }
  return env;
}

/** Vault-authored askpass launcher + helper in a temp dir; credential passed via env, not argv. */
function writeAskpass(): { launcher: string; dispose: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "harpoc-git-"));
  const helper = join(dir, "askpass.mjs");
  writeFileSync(helper, ASKPASS_HELPER_SRC, { mode: 0o700 });
  const node = process.execPath;
  let launcher: string;
  if (process.platform === "win32") {
    launcher = join(dir, "askpass.cmd");
    writeFileSync(launcher, `@"${node}" "${helper}" %*\r\n`, { mode: 0o700 });
  } else {
    launcher = join(dir, "askpass.sh");
    writeFileSync(launcher, `#!/bin/sh\nexec "${node}" "${helper}" "$@"\n`, { mode: 0o700 });
  }
  return {
    launcher,
    dispose: () => {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    },
  };
}

/** Join command parts into a GIT_SSH_COMMAND string, double-quoting parts with whitespace. */
function toCommandString(parts: string[]): string {
  return parts.map((p) => (/\s/.test(p) ? `"${p}"` : p)).join(" ");
}

function toGitResult(
  action: GitAction,
  r: import("./spawn-captured.js").SpawnCapturedResult,
): GitResult {
  return {
    type: "git",
    operation: action.operation,
    exit_code: r.exit_code,
    stdout: r.stdout,
    stderr: r.stderr,
    timed_out: r.timed_out ? true : undefined,
    truncated: r.truncated ? true : undefined,
    signal: r.signal ?? undefined,
    error: r.spawn_failed
      ? ErrorCode.GIT_OPERATION_FAILED
      : r.timed_out
        ? ErrorCode.PROCESS_TIMEOUT
        : undefined,
  };
}
