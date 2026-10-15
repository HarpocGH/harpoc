import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { devNull, tmpdir } from "node:os";
import { join } from "node:path";
import type { ConnectionConfig, GitAction, GitResult, InjectionPolicy } from "@harpoc/shared";
import {
  DEFAULT_GIT_TIMEOUT_MS,
  ErrorCode,
  MIN_REDACTABLE_FRAGMENT,
  VaultError,
} from "@harpoc/shared";
import type { AuditAttribution } from "../audit/attribution.js";
import { withAttribution } from "../audit/attribution.js";
import type { AuditLogger } from "../audit/audit-logger.js";
import {
  controlledPathDirs,
  matchesHostAllowlist,
  matchesUrlAllowlist,
  resolveAndMatchCommand,
  resolveExecutable,
} from "./allowlist.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { EphemeralSshAgent } from "./ssh-agent/index.js";
import {
  assertNativeWin32SshClient,
  buildSshEnv,
  isHostKeyFailure,
  sshHardeningArgs,
  writeIdentityFile,
  writeKnownHosts,
  writeTempSshFile,
} from "./ssh-common.js";
import type { TempSshFile } from "./ssh-common.js";
import { validateUrl } from "./url-validator.js";

/** git args that turn data into an instruction vehicle (config/hook/transport execution).
 *  Matched by name prefix, so both `--template=<dir>` and `--template <dir>` are caught
 *  (the value arg on its own is inert). `--template`/`--separate-git-dir` run hooks /
 *  relocate the git dir at clone time — clone-time local code execution vectors.
 *  A pre-existing hook in a caller-supplied working tree is a separate vector — closed
 *  by the vault-authored core.hooksPath every run carries (N11, createEmptyHooksDir). */
const DANGEROUS_ARG_PREFIXES = [
  "-c",
  "--config",
  "--config-env",
  "--upload-pack",
  "--receive-pack",
  "--exec",
  "--template",
  "--separate-git-dir",
  // Submodule URLs come from the cloned repository, not from the vault: fetching
  // them makes git authenticate to hosts that never passed validateUrl or the
  // URL allowlist. Blocked on every operation.
  "--recurse-submodules",
  "--recursive",
];

/** Options dangerous only for specific operations. `-u` is `--upload-pack` for
 *  `clone` (transport-program execution) but `--set-upstream` for `push`, so it
 *  is blocked per operation rather than globally. */
const CLONE_DANGEROUS_ARG_PREFIXES = [
  "-u",
  // A clone's transfer runs into the relay in full (runRelayedClone); a filter
  // would leave a partial clone whose promisor origin lazy-fetches later
  // without the credential.
  "--filter",
  "--also-filter-submodules",
  // Fetches bundles from an arbitrary URI the URL allowlist never saw.
  "--bundle-uri",
];

/** A relayed push cannot record an upstream in the caller's tree: git writes
 *  the `[branch]` section into the relay's config, which the after-check then
 *  reports as a failed push although the remote moved. */
const PUSH_DANGEROUS_ARG_PREFIXES = ["-u", "--set-upstream"];

/**
 * The short options that take a value, per operation (`git <op> -h`, Git for
 * Windows 2.51 and git 2.54 alike; an optional value is taken only when
 * attached, so it ends the cluster as well): in `-xyz` git reads `-x -y -z`
 * until the first of these, and the rest of the token is its value.
 */
const SHORT_WITH_VALUE: Record<GitAction["operation"], ReadonlySet<string>> = {
  clone: new Set(["j", "o", "b", "u", "c"]),
  pull: new Set(["r", "s", "X", "S", "j", "o"]),
  push: new Set(["o"]),
};

/** Repository transports that can execute local commands — never allowed. */
const FORBIDDEN_REPO_PREFIXES = ["ext::", "fd::", "file:", "git+"];

/**
 * The bundled askpass helper: prints the username or token from the environment,
 * but only when git is asking about the origin the vault validated.
 *
 * git asks askpass for whatever host it ends up talking to — after a 3xx
 * redirect, or for a submodule URL the cloned repository chose. A host-blind
 * helper therefore hands the credential to targets that never passed
 * `validateUrl` or the URL allowlist, which is how target control was reduced to
 * a check on the initially supplied string. The origin (scheme, host and port) of
 * the URL git names in the prompt is compared against the validated one — another
 * port or scheme on the same host is another service — with `URL` dropping the
 * userinfo and each scheme's default port on both sides, as git omits it;
 * anything else is refused (fail closed, including a prompt with no recognizable
 * URL).
 */
const ASKPASS_HELPER_SRC = `const prompt = process.argv[2] || "";
const expected = (process.env.HARPOC_GIT_ORIGIN || "").toLowerCase();
const match = /https?:\\/\\/[^\\s'"]+/i.exec(prompt);
let origin = "";
if (match) {
  try { origin = new URL(match[0]).origin.toLowerCase(); } catch { origin = ""; }
}
if (!expected || origin !== expected) {
  process.stderr.write("harpoc: refusing to supply the credential for an unexpected host\\n");
  process.exit(1);
}
// Classified on the prompt's leading word, not a substring search: git's
// password prompt embeds the username ("Password for 'https://git-user@host': "),
// so an includes("user") test answers a password prompt with the username
// whenever the username itself contains "user".
const isUser = /^\\s*username\\b/i.test(prompt);
const out = isUser ? (process.env.HARPOC_GIT_USERNAME || "") : (process.env.HARPOC_GIT_PASSWORD || "");
process.stdout.write(out + "\\n");
`;

/**
 * Config the vault forces on every HTTPS invocation. `http.followRedirects=false`
 * keeps git on the validated host: git's default (`initial`) follows a 3xx on the
 * initial request, moving the base URL — and with it the credential prompt — to a
 * host the vault never resolved, validated or allowlisted. A stored `git.ca_pem`
 * (D64) adds `http.sslCAInfo=<0600 temp file>` and
 * `http.schannelUseSSLCAInfo=true` — vault-authored, since `-c` is denied to
 * callers and both curl backends honor the pair — and, on win32,
 * `WIN32_PINNED_CA_CONFIG`, so the pin does not ride on the host's
 * `http.sslBackend`.
 *
 * Every invocation on both transports also carries forcedGitConfig — the
 * empty core.hooksPath (N11), credential.helper and core.fsmonitor (S1). These
 * HTTPS keys ride on the network step alone.
 */
const HTTPS_FORCED_CONFIG = ["-c", "http.followRedirects=false"];

/**
 * Beside a pinned CA on win32 the TLS backend is named explicitly, with
 * best-effort revocation: git honours `http.schannel*` only while
 * `http.sslBackend` is `schannel`, and a host whose git has no system config
 * (`GIT_CONFIG_NOSYSTEM`, a portable git) leaves the backend unset — curl's
 * schannel default then verifies the CA file with a strict revocation check that
 * a private CA without CRL/OCSP fails (`CERT_TRUST_REVOCATION_STATUS_UNKNOWN`,
 * exit 128; 2026-09-17). `best-effort` still checks revocation where the CA
 * publishes it, which the OpenSSL backend never does. Unpinned HTTPS keeps the
 * host's backend. The value is Git for Windows' (2.26.0 and later): an upstream
 * build of git parses the key as a boolean and refuses `best-effort`.
 */
const WIN32_PINNED_CA_CONFIG = [
  "-c",
  "http.sslBackend=schannel",
  "-c",
  "http.schannelCheckRevoke=best-effort",
];

/**
 * The global config file every git run reads in place of `~/.gitconfig`: none
 * (S1, face a). Git for Windows refuses Node's `os.devNull` (`\\.\nul`: "unable
 * to access … Invalid argument", exit 128) and opens the NUL device for `NUL`,
 * a file of that name in the working directory notwithstanding; POSIX takes
 * `/dev/null`.
 */
const NULL_GIT_CONFIG = process.platform === "win32" ? "NUL" : devNull;

/**
 * The relay repository's branch that receives the remote's HEAD on a pull, and
 * the namespace the caller's own refs are listed under there (S1, face b).
 */
const RELAY_FETCHED_REF = "refs/heads/harpoc-relay";
const RELAY_LOCAL_REF_PREFIX = "refs/harpoc/local/";

/** Relay files a fetch or push leaves as the vault wrote them (re-checked after the step). */
const RELAY_STABLE_FILES = ["config", "HEAD", "objects/info/alternates"];
/** Files through which git would read configuration from outside the relay's own config. */
const RELAY_CONFIG_REDIRECTS = ["commondir", "config.worktree"];

interface RelayRepo {
  dir: string;
  dispose: () => void;
  /** Throws GIT_OPERATION_FAILED when the relay is no longer what the vault wrote. */
  verify: (phase: "before" | "after") => void;
  /** Rewrites HEAD (a `ref: <name>` or an oid); the checks expect the new value. */
  setHead: (value: string) => void;
}

/**
 * The credential-free local hops — the local `pull` and the clone's local
 * `clone` — read the relay and nothing else: the flags refuse every transport
 * but file for what the vault's argv and a default tree ask for
 * (`transport '<x>' not allowed`), such as a submodule fetch or a
 * partial-clone caller's lazy fetch during a pull. A tree's own
 * `protocol.<name>.allow` still applies to that step, which carries no
 * credential.
 */
const LOCAL_HOP_PROTOCOLS = ["-c", "protocol.allow=never", "-c", "protocol.file.allow=always"];

/** The relay HEAD before (or without) the remote's: git's own default branch. */
const RELAY_DEFAULT_HEAD = "ref: refs/heads/master";
/** Where a clone's relay keeps a detached remote HEAD, so its commit is fetched. */
const RELAY_REMOTE_HEAD_REF = "refs/harpoc/remote-head";

/**
 * The caller options that change what a relay's network fetch asks the remote
 * for, per operation: forwarded to that fetch, normalized, as well as to the
 * local step that reads the relay — anything else acts on the local step alone.
 */
interface FetchOptionSpec {
  /** Flags, forwarded as named. */
  flags: string[];
  /** Options taking a value, forwarded as `--name=value`. */
  valued: string[];
  /** Short flags, forwarded as the long name. */
  short: Record<string, string>;
  /** Short options taking a value, forwarded as `--long=value`. */
  shortValued: Record<string, string>;
  /** Short options whose value ends the cluster (`-ofoo`), forwarded or not. */
  shortWithValue: ReadonlySet<string>;
}

const PULL_FETCH_OPTIONS: FetchOptionSpec = {
  flags: ["--tags", "--unshallow", "--update-shallow", "--ipv4", "--ipv6"],
  valued: ["--depth", "--deepen", "--shallow-since", "--shallow-exclude", "--server-option"],
  short: { t: "--tags", "4": "--ipv4", "6": "--ipv6" },
  shortValued: { o: "--server-option" },
  shortWithValue: SHORT_WITH_VALUE.pull,
};

/** A clone's `-o` is `--origin`: the server option has no short form there. */
const CLONE_FETCH_OPTIONS: FetchOptionSpec = {
  flags: ["--no-tags", "--ipv4", "--ipv6"],
  valued: ["--depth", "--shallow-since", "--shallow-exclude", "--server-option"],
  short: { "4": "--ipv4", "6": "--ipv6" },
  shortValued: {},
  shortWithValue: SHORT_WITH_VALUE.clone,
};

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
 *  - The credential never enters a git process that reads the caller's
 *    repository config (S1): clone, pull and push run their network steps
 *    against a vault-written relay repository (runRelayedClone, runRelayed),
 *    re-validated around each step. A writer running as the same OS user can
 *    still change the relay between that check and git's read; closing that
 *    needs OS-level separation of the credential-bearing step, which the vault
 *    does not provide.
 */
export class GitInjector {
  constructor(private readonly auditLogger: AuditLogger | null) {}

  async executeWithSecret(
    action: GitAction,
    secretValue: Uint8Array,
    policy: InjectionPolicy,
    config: ConnectionConfig | undefined,
    secretId?: string,
    attribution?: AuditAttribution,
  ): Promise<GitResult> {
    const transport = detectTransport(action.repository);
    if (!transport) {
      this.audit(action, secretId, { error: "GIT_UNSUPPORTED_TRANSPORT" }, false, attribution);
      throw VaultError.gitUnsupportedTransport(action.repository);
    }

    assertSafeArgs(action.operation, action.args);
    assertNoPositional(action);
    if (action.working_directory && action.working_directory.startsWith("-")) {
      throw VaultError.invalidGitConfig("working_directory must not start with '-'");
    }

    let gitPath: string;
    try {
      gitPath = resolveAndMatchCommand("git", policy.command_allowlist, controlledPathDirs());
    } catch (err) {
      if (err instanceof VaultError)
        this.audit(action, secretId, { error: err.code }, false, attribution);
      throw err;
    }

    return transport === "https"
      ? this.runHttps(action, gitPath, secretValue, policy, config, secretId, attribution)
      : this.runSsh(action, gitPath, secretValue, policy, config, secretId, attribution);
  }

  private async runHttps(
    action: GitAction,
    gitPath: string,
    secretValue: Uint8Array,
    policy: InjectionPolicy,
    config: ConnectionConfig | undefined,
    secretId: string | undefined,
    attribution: AuditAttribution | undefined,
  ): Promise<GitResult> {
    // Mandatory floor: HTTPS + SSRF. Above it the per-secret URL allowlist, deny-by-default.
    try {
      await validateUrl(action.repository);
    } catch (err) {
      if (err instanceof VaultError)
        this.audit(action, secretId, { error: err.code }, false, attribution);
      throw err;
    }
    if (!matchesUrlAllowlist(action.repository, policy.url_allowlist)) {
      this.audit(action, secretId, { error: "URL_NOT_ALLOWED" }, false, attribution);
      throw VaultError.urlNotAllowed(action.repository);
    }

    const { user, password } = parseGitCredential(secretValue);
    const hooks = createEmptyHooksDir();
    try {
      assertWorkingTree(action);
    } catch (err) {
      hooks.dispose();
      throw err;
    }
    const timeoutMs = action.timeout_ms ?? DEFAULT_GIT_TIMEOUT_MS;
    let askpass: { launcher: string; dispose: () => void };
    try {
      askpass = writeAskpass();
    } catch (err) {
      hooks.dispose();
      throw err;
    }
    let ca: TempSshFile | null = null;
    try {
      ca =
        config?.git === undefined
          ? null
          : writeTempSshFile("harpoc-git-ca-", "ca.pem", config.git.ca_pem);
      const networkConfig = [
        ...HTTPS_FORCED_CONFIG,
        ...(ca
          ? [
              "-c",
              `http.sslCAInfo=${ca.file}`,
              "-c",
              "http.schannelUseSSLCAInfo=true",
              ...(process.platform === "win32" ? WIN32_PINNED_CA_CONFIG : []),
            ]
          : []),
      ];
      const env = baseGitEnv(policy.env_allowlist);
      env.GIT_ASKPASS = askpass.launcher;
      env.GIT_TERMINAL_PROMPT = "0";
      env.HARPOC_GIT_USERNAME = user;
      env.HARPOC_GIT_PASSWORD = password;
      // Binds the credential to the validated origin (see ASKPASS_HELPER_SRC).
      env.HARPOC_GIT_ORIGIN = new URL(action.repository).origin.toLowerCase();
      // The username is credential material too, down to the shared floor
      // (MIN_REDACTABLE_FRAGMENT); shorter fragments stay unredacted.
      const redact = user.length >= MIN_REDACTABLE_FRAGMENT ? [password, user] : [password];
      const networkIsolation = policy.network_isolation === true;
      const fsIsolation = policy.fs_isolation === true;
      let r: SpawnCapturedResult;
      try {
        r = await runPlan(action, gitPath, hooks.dir, networkConfig, env, policy, {
          timeoutMs,
          redact,
          networkIsolation,
          fsIsolation,
          strictTreeExit: policy.strict_tree_exit === true,
        });
      } catch (err) {
        if (err instanceof VaultError) {
          this.audit(
            action,
            secretId,
            {
              transport: "https",
              error: err.code,
              network_isolation: networkIsolation,
              fs_isolation: fsIsolation,
              ...(ca ? { ca_pinned: true } : {}),
            },
            false,
            attribution,
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
          fs_isolation: fsIsolation,
          ...(r.fs_isolation_mechanism ? { fs_isolation_mechanism: r.fs_isolation_mechanism } : {}),
          ...(ca ? { ca_pinned: true } : {}),
          ...(r.redacted ? { sanitized: true } : {}),
          ...(r.descendant_sweep ? { descendant_sweep: r.descendant_sweep } : {}),
          ...(r.tree_kill ? { tree_kill: r.tree_kill } : {}),
          ...(r.strict_tree_exit ? { strict_tree_exit: true } : {}),
        },
        result.error === undefined,
        attribution,
      );
      return result;
    } finally {
      hooks.dispose();
      askpass.dispose();
      ca?.dispose();
    }
  }

  private async runSsh(
    action: GitAction,
    gitPath: string,
    secretValue: Uint8Array,
    policy: InjectionPolicy,
    config: ConnectionConfig | undefined,
    secretId: string | undefined,
    attribution: AuditAttribution | undefined,
  ): Promise<GitResult> {
    const host = parseSshHost(action.repository);
    if (!host) {
      this.audit(action, secretId, { error: "INVALID_GIT_CONFIG" }, false, attribution);
      throw VaultError.invalidGitConfig("could not parse SSH host from repository");
    }
    // Host allowlist — deny-by-default (an empty list refuses).
    if (!matchesHostAllowlist(host, policy.host_allowlist)) {
      this.audit(action, secretId, { host, error: "HOST_NOT_ALLOWED" }, false, attribution);
      throw VaultError.hostNotAllowed(host);
    }
    const knownHosts = config?.ssh?.known_hosts;
    if (!knownHosts || knownHosts.length === 0) {
      this.audit(action, secretId, { host, error: "SSH_NOT_CONFIGURED" }, false, attribution);
      throw VaultError.sshNotConfigured();
    }
    const sshPath = resolveExecutable("ssh", controlledPathDirs());
    if (!sshPath) {
      throw VaultError.invalidGitConfig("ssh binary not found on the controlled PATH");
    }
    try {
      assertNativeWin32SshClient(sshPath);
    } catch (err) {
      if (err instanceof VaultError)
        this.audit(action, secretId, { host, error: err.code }, false, attribution);
      throw err;
    }

    const keyPem = Buffer.from(secretValue).toString("utf8");
    const hooks = createEmptyHooksDir();
    try {
      assertWorkingTree(action);
    } catch (err) {
      hooks.dispose();
      throw err;
    }
    const timeoutMs = action.timeout_ms ?? DEFAULT_GIT_TIMEOUT_MS;
    let kh: TempSshFile;
    try {
      kh = writeKnownHosts(knownHosts);
    } catch (err) {
      hooks.dispose();
      throw err;
    }

    let agent: EphemeralSshAgent;
    try {
      agent = await EphemeralSshAgent.start(keyPem);
    } catch (err) {
      kh.dispose();
      hooks.dispose();
      if (err instanceof VaultError)
        this.audit(action, secretId, { host, error: err.code }, false, attribution);
      throw err;
    }

    let identity: TempSshFile | null = null;
    try {
      identity = writeIdentityFile(agent.publicKeyOpenssh);
      const env = isolateGitConfig(buildSshEnv(agent.authSock, policy.env_allowlist));
      env.GIT_SSH_COMMAND = toGitSshCommand([
        sshPath,
        ...sshHardeningArgs(kh.file, identity.file, Math.max(1, Math.ceil(timeoutMs / 1000))),
      ]);
      env.GIT_TERMINAL_PROMPT = "0";
      const networkIsolation = policy.network_isolation === true;
      const fsIsolation = policy.fs_isolation === true;
      let r: SpawnCapturedResult;
      try {
        r = await runPlan(action, gitPath, hooks.dir, [], env, policy, {
          timeoutMs,
          redact: [keyPem],
          networkIsolation,
          fsIsolation,
          strictTreeExit: policy.strict_tree_exit === true,
        });
      } catch (err) {
        if (err instanceof VaultError) {
          this.audit(
            action,
            secretId,
            {
              transport: "ssh",
              host,
              error: err.code,
              network_isolation: networkIsolation,
              fs_isolation: fsIsolation,
            },
            false,
            attribution,
          );
        }
        throw err;
      }

      if (isHostKeyFailure(r.stderr)) {
        // Security-rejection rows carry the isolation posture like every
        // other post-spawn row — filtering the trail on it must not miss
        // exactly the denials (review fix F8).
        this.audit(
          action,
          secretId,
          {
            transport: "ssh",
            host,
            error: "SSH_HOST_KEY_MISMATCH",
            network_isolation: networkIsolation,
            fs_isolation: fsIsolation,
          },
          false,
          attribution,
        );
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
          fs_isolation: fsIsolation,
          ...(r.fs_isolation_mechanism ? { fs_isolation_mechanism: r.fs_isolation_mechanism } : {}),
          ...(r.redacted ? { sanitized: true } : {}),
          ...(r.descendant_sweep ? { descendant_sweep: r.descendant_sweep } : {}),
          ...(r.tree_kill ? { tree_kill: r.tree_kill } : {}),
          ...(r.strict_tree_exit ? { strict_tree_exit: true } : {}),
        },
        result.error === undefined,
        attribution,
      );
      return result;
    } finally {
      hooks.dispose();
      agent.dispose();
      kh.dispose();
      identity?.dispose();
    }
  }

  private audit(
    action: GitAction,
    secretId: string | undefined,
    detail: Record<string, unknown>,
    success: boolean,
    attribution?: AuditAttribution,
  ): void {
    this.auditLogger?.log(
      withAttribution(
        {
          eventType: "secret.use",
          secretId,
          detail: { context: "git", operation: action.operation, ...detail },
          success,
        },
        attribution,
      ),
    );
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

/**
 * Whether `arg` reaches one of the denied options.
 *
 * Name matching alone is not enough: git resolves any *unambiguous prefix* of a
 * long option, so `--templ=<dir>` reaches `--template` and `--conf=k=v` reaches
 * `--config` while starting with neither string (verified against git 2.51).
 * An argument is therefore denied when it starts with a denied option (the
 * exact and `--opt=value` forms) *or* when its option name is a prefix of one —
 * the same rule git itself applies when expanding it.
 *
 * A single-dash token is a cluster: `-4u<prog>` is `-4 -u <prog>`, and
 * `-qc<k=v>` is `-q -c <k=v>`. Its letters are walked up to the first short
 * option that takes a value (`shortWithValue`), and a denied letter reached on
 * the way — that one included — denies the token.
 */
function reachesDeniedOption(
  arg: string,
  denied: readonly string[],
  shortWithValue: ReadonlySet<string>,
): boolean {
  const a = arg.trim();
  if (denied.some((p) => a === p || a.startsWith(p))) return true;

  if (/^-[^-]/.test(a)) {
    const deniedShort = new Set(denied.filter((p) => /^-[^-]$/.test(p)).map((p) => p[1]));
    for (const ch of a.slice(1)) {
      if (deniedShort.has(ch)) return true;
      if (shortWithValue.has(ch)) break;
    }
  }

  const eq = a.indexOf("=");
  const name = eq >= 0 ? a.slice(0, eq) : a;
  if (!name.startsWith("--") || name.length <= 2) return false;
  return denied.some((p) => p.startsWith("--") && p.startsWith(name));
}

function assertSafeArgs(operation: GitAction["operation"], args: string[] | undefined): void {
  const denied =
    operation === "clone"
      ? [...DANGEROUS_ARG_PREFIXES, ...CLONE_DANGEROUS_ARG_PREFIXES]
      : operation === "push"
        ? [...DANGEROUS_ARG_PREFIXES, ...PUSH_DANGEROUS_ARG_PREFIXES]
        : DANGEROUS_ARG_PREFIXES;
  for (const arg of args ?? []) {
    if (reachesDeniedOption(arg, denied, SHORT_WITH_VALUE[operation])) {
      throw VaultError.invalidGitConfig(`disallowed git argument: ${arg}`);
    }
  }
}

/**
 * A clone without working_directory gives git one positional, the repository,
 * and git takes a second one as the destination: `clone <arg> -- <repository>`
 * clones `<arg>` into a directory named after the validated URL (S5, reproduced
 * on git 2.54 — `--` alone does not close it). With working_directory a third
 * positional is git's own usage error. A push's or a pull's positional would
 * be git's repository, with the vault's `-- <repository>` demoted to a
 * refspec: a push aborts on that refspec before connecting, but only
 * incidentally, and an scp-form repository is a valid refspec, so the
 * credential-free local pull connected to the positional's host. All three
 * therefore take option-shaped arguments only; a value goes in the
 * `--option=value` form.
 */
function assertNoPositional(action: GitAction): void {
  const subject =
    action.operation === "push"
      ? "a push"
      : action.operation === "pull"
        ? "a pull"
        : action.operation === "clone" && !action.working_directory
          ? "a clone without working_directory"
          : null;
  if (subject === null) return;
  for (const arg of action.args ?? []) {
    if (arg === "-" || arg === "--" || arg === "--end-of-options" || !arg.startsWith("-")) {
      throw VaultError.invalidGitConfig(`${subject} takes no positional argument: ${arg}`);
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

/**
 * Config the vault forces on every git invocation, both transports, every step
 * (N11, S1): no hook of the caller's tree runs (an empty vault-authored
 * core.hooksPath), no configured credential helper is asked or told anything
 * (an empty credential.helper resets every helper, URL-scoped ones included),
 * and core.fsmonitor does not run.
 */
function forcedGitConfig(hooksDir: string): string[] {
  return [
    "-c",
    `core.hooksPath=${hooksDir}`,
    "-c",
    "credential.helper=",
    "-c",
    "core.fsmonitor=false",
  ];
}

function assertWorkingTree(action: GitAction): void {
  if (action.operation === "clone") return;
  const wd = action.working_directory;
  if (!wd) {
    throw VaultError.invalidGitConfig(`working_directory is required for ${action.operation}`);
  }
  assertDirectory(wd);
}

interface StepOptions {
  timeoutMs: number;
  redact: string[];
  networkIsolation: boolean;
  fsIsolation: boolean;
  strictTreeExit: boolean;
}

type GitStep = (
  args: string[],
  cwd: string | undefined,
  env: Record<string, string>,
) => Promise<SpawnCapturedResult>;

function succeeded(r: SpawnCapturedResult): boolean {
  return r.exit_code === 0 && !r.timed_out && !r.spawn_failed;
}

/**
 * Every operation is relayed: the credential-bearing steps run against a
 * vault-written relay repository, never in the caller's working tree or clone
 * destination, whose configuration a concurrent writer could plant (S1) — a
 * clone through runRelayedClone, a pull or a push through runRelayed. Every
 * step shares the operation's one timeout budget and the policy's spawn
 * posture.
 */
async function runPlan(
  action: GitAction,
  gitPath: string,
  hooksDir: string,
  networkConfig: string[],
  networkEnv: Record<string, string>,
  policy: InjectionPolicy,
  opts: StepOptions,
): Promise<SpawnCapturedResult> {
  const deadline = Date.now() + opts.timeoutMs;
  const step: GitStep = (args, cwd, env) =>
    spawnCaptured(gitPath, args, {
      env,
      cwd,
      timeoutMs: Math.max(1, deadline - Date.now()),
      redact: opts.redact,
      networkIsolation: opts.networkIsolation,
      fsIsolation: opts.fsIsolation,
      strictTreeExit: opts.strictTreeExit,
    });
  const localEnv = baseGitEnv(policy.env_allowlist);
  localEnv.GIT_TERMINAL_PROMPT = "0";
  if (action.operation === "clone") {
    return runRelayedClone(action, hooksDir, networkConfig, networkEnv, localEnv, step);
  }
  return runRelayed(action, hooksDir, networkConfig, networkEnv, localEnv, step);
}

/**
 * The credential-bearing step of `relay`, re-validated around (createRelayRepo):
 * the forced config, `--git-dir` of the relay, its cwd the relay.
 */
async function networkStep(
  relay: RelayRepo,
  args: string[],
  networkConfig: string[],
  forced: string[],
  networkEnv: Record<string, string>,
  step: GitStep,
): Promise<SpawnCapturedResult> {
  relay.verify("before");
  const r = await step(
    [...networkConfig, ...forced, `--git-dir=${relay.dir}`, ...args],
    relay.dir,
    networkEnv,
  );
  relay.verify("after");
  return r;
}

/** `file://` URL of a local directory: git honours `--depth` only over a transport. */
function fileUrl(dir: string): string {
  const p = dir.replace(/\\/g, "/");
  return p.startsWith("/") ? `file://${p}` : `file:///${p}`;
}

/**
 * A refname the relay's HEAD may name: `refs/` and slash-separated components
 * of letters, digits, `.`, `_`, `-`, none empty, none starting with `.` or
 * ending in `.lock`, no `..` (git's check-ref-format basics). The remote
 * chooses the symref; anything else is not written into the relay, and the
 * advertised oid is taken as a detached HEAD instead.
 */
function isPlainRefname(name: string): boolean {
  return (
    /^refs\/[A-Za-z0-9._/-]+$/.test(name) &&
    !name.includes("..") &&
    name
      .split("/")
      .every((c) => c !== "" && !c.startsWith(".") && !c.endsWith(".lock") && !c.endsWith("."))
  );
}

/** The remote HEAD and object format as `ls-remote --symref <url> HEAD` reports them. */
function parseRemoteHead(stdout: string): {
  symref: string | null;
  oid: string | null;
  objectFormat: "sha1" | "sha256";
} {
  let symref: string | null = null;
  let oid: string | null = null;
  for (const line of stdout.split(/\r?\n/)) {
    const ref = /^ref: (refs\/\S+)\tHEAD$/.exec(line);
    if (ref && isPlainRefname(ref[1] as string)) symref = ref[1] as string;
    const id = /^([0-9a-f]{40}|[0-9a-f]{64})\tHEAD$/.exec(line);
    if (id) oid = id[1] as string;
  }
  return { symref, oid, objectFormat: oid?.length === 64 ? "sha256" : "sha1" };
}

/**
 * A clone (S1, face b — C1.2 fix round 1): the credential never enters a git
 * process whose git dir or cwd is the destination, where a concurrent writer
 * can plant configuration (`filter.<x>.smudge` at checkout, a URL-scoped
 * `http.<url>.proxy` during the transfer) from the moment `git clone` creates
 * it. Two credential-bearing steps run against a vault-written relay:
 * `ls-remote --symref` learns the remote's HEAD and object format (a sha256
 * remote gets a sha256 relay — a fetch across formats fails), and `fetch`
 * takes every branch and tag (`+refs/*:refs/*` under `--mirror`; the remote's
 * detached HEAD as well). The caller's clone is then made from the relay by a
 * credential-free `git clone <args> -- <repository> [dest]` with the relay
 * standing in for the repository (`url.<file://relay>.insteadOf`), so git
 * names the destination after the repository, records it as `origin`, and
 * applies every caller option as it would. The options that shape the
 * transfer reach the fetch too (cloneFetchArgs); the others act on the local
 * clone alone. An empty remote advertises no HEAD; the relay's is then
 * `refs/heads/master`, git's own default.
 */
async function runRelayedClone(
  action: GitAction,
  hooksDir: string,
  networkConfig: string[],
  networkEnv: Record<string, string>,
  localEnv: Record<string, string>,
  step: GitStep,
): Promise<SpawnCapturedResult> {
  const forced = forcedGitConfig(hooksDir);
  const args = action.args ?? [];
  const relayFor = (objectFormat: string) =>
    createRelayRepo({ objectFormat, head: RELAY_DEFAULT_HEAD, refs: [] });
  let relay = relayFor("sha1");
  try {
    const listed = await networkStep(
      relay,
      ["ls-remote", "--symref", "--", action.repository, "HEAD"],
      networkConfig,
      forced,
      networkEnv,
      step,
    );
    if (!succeeded(listed)) return listed;
    const remote = parseRemoteHead(listed.stdout);
    if (remote.objectFormat === "sha256") {
      relay.dispose();
      relay = relayFor("sha256");
    }
    if (remote.symref) relay.setHead(`ref: ${remote.symref}`);
    const mirror = args.some((a) => matchesOption(optionName(a), "--mirror"));
    const noTags = args.some((a) => matchesOption(optionName(a), "--no-tags"));
    const detached = remote.symref === null && remote.oid !== null;
    const refspecs = mirror
      ? ["+refs/*:refs/*"]
      : [
          "+refs/heads/*:refs/heads/*",
          ...(noTags ? [] : ["+refs/tags/*:refs/tags/*"]),
          ...(detached ? [`+HEAD:${RELAY_REMOTE_HEAD_REF}`] : []),
        ];
    const fetched = await networkStep(
      relay,
      [
        "fetch",
        "--quiet",
        "--no-write-fetch-head",
        ...forwardedFetchArgs(args, CLONE_FETCH_OPTIONS),
        "--",
        action.repository,
        ...refspecs,
      ],
      networkConfig,
      forced,
      networkEnv,
      step,
    );
    if (!succeeded(fetched)) return fetched;
    if (detached) relay.setHead(remote.oid as string);
    const cloned = await step(
      [
        ...forced,
        ...LOCAL_HOP_PROTOCOLS,
        "-c",
        `url.${fileUrl(relay.dir)}.insteadOf=${action.repository}`,
        "clone",
        ...args,
        "--",
        action.repository,
        ...(action.working_directory ? [action.working_directory] : []),
      ],
      undefined,
      localEnv,
    );
    return {
      ...cloned,
      stdout: fetched.stdout + cloned.stdout,
      stderr: fetched.stderr + cloned.stderr,
      truncated: fetched.truncated || cloned.truncated,
      redacted: fetched.redacted || cloned.redacted,
    };
  } finally {
    relay.dispose();
  }
}

/**
 * Pull and push (S1, face b): the credential never enters a git process that
 * reads the caller's repository config. The steps run in the working tree —
 * resolving its object directory, its HEAD and its refs, and on a pull the
 * final `pull` from the relay — carry neither the credential nor the agent
 * socket; the one network step (`fetch` of the remote's HEAD, or the `push`)
 * runs with `--git-dir` of the relay repository the vault wrote
 * (createRelayRepo). A step that fails ends the operation with its result.
 */
async function runRelayed(
  action: GitAction,
  hooksDir: string,
  networkConfig: string[],
  networkEnv: Record<string, string>,
  localEnv: Record<string, string>,
  step: GitStep,
): Promise<SpawnCapturedResult> {
  const wd = action.working_directory as string;
  const forced = forcedGitConfig(hooksDir);
  const local = (args: string[]) => step([...forced, ...args], wd, localEnv);

  const probe = await local([
    "rev-parse",
    "--path-format=absolute",
    "--git-path",
    "objects",
    "--git-path",
    "shallow",
    "--show-object-format",
  ]);
  if (!succeeded(probe)) return probe;
  const [objectsDir, shallowFile, objectFormat] = probe.stdout.split(/\r?\n/);
  if (!objectsDir || !shallowFile || (objectFormat !== "sha1" && objectFormat !== "sha256")) {
    throw VaultError.gitOperationFailed("could not resolve the working tree's repository");
  }

  let head = `ref: ${RELAY_FETCHED_REF}`;
  if (action.operation === "push") {
    const symbolic = await local(["symbolic-ref", "-q", "HEAD"]);
    if (symbolic.exit_code === 0) {
      head = `ref: ${symbolic.stdout.trim()}`;
    } else {
      const detached = await local(["rev-parse", "--verify", "HEAD"]);
      if (!succeeded(detached)) return detached;
      head = detached.stdout.trim();
    }
  }

  const listed = await local(["for-each-ref", "--format=%(objectname) %(refname)"]);
  if (!succeeded(listed)) return listed;
  if (listed.truncated) {
    throw VaultError.gitOperationFailed("the working tree's ref listing exceeds the output cap");
  }
  const refs = parseRefListing(
    listed.stdout,
    action.operation === "pull" ? RELAY_LOCAL_REF_PREFIX : "refs/",
  );

  const relay = createRelayRepo({ objectsDir, shallowFile, objectFormat, head, refs });
  try {
    const network = (args: string[]) =>
      networkStep(relay, args, networkConfig, forced, networkEnv, step);
    if (action.operation === "push") {
      return await network(["push", ...(action.args ?? []), "--", action.repository]);
    }
    const fetched = await network([
      "fetch",
      "--quiet",
      "--no-write-fetch-head",
      ...forwardedFetchArgs(action.args ?? [], PULL_FETCH_OPTIONS),
      "--",
      action.repository,
      `+HEAD:${RELAY_FETCHED_REF}`,
    ]);
    if (!succeeded(fetched)) return fetched;
    const merged = await local([
      ...LOCAL_HOP_PROTOCOLS,
      "-c",
      `url.${relay.dir.replace(/\\/g, "/")}.insteadOf=${action.repository}`,
      "pull",
      ...(action.args ?? []),
      "--",
      action.repository,
    ]);
    return {
      ...merged,
      stdout: fetched.stdout + merged.stdout,
      stderr: fetched.stderr + merged.stderr,
      truncated: fetched.truncated || merged.truncated,
      redacted: fetched.redacted || merged.redacted,
    };
  } finally {
    relay.dispose();
  }
}

/** `<oid> <refname>` lines of the caller's refs, renamed under `prefix` for packed-refs. */
function parseRefListing(stdout: string, prefix: string): string[] {
  const out: string[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^([0-9a-f]{40}|[0-9a-f]{64}) refs\/(\S+)$/.exec(line);
    if (m) out.push(`${m[1] as string} ${prefix}${m[2] as string}`);
  }
  return out;
}

/** A long option's name (`--name` of `--name=value`), or "" for anything else. */
function optionName(arg: string): string {
  if (!arg.startsWith("--")) return "";
  const eq = arg.indexOf("=");
  return eq >= 0 ? arg.slice(0, eq) : arg;
}

/** Whether `name` reaches `option` as git resolves it (the name or an abbreviation). */
function matchesOption(name: string, option: string): boolean {
  return name !== "" && (name === option || (name.length > 3 && option.startsWith(name)));
}

/** The caller options a relay's network fetch needs as well, normalized (C1-g). */
function forwardedFetchArgs(args: string[], spec: FetchOptionSpec): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg.startsWith("--")) {
      const name = optionName(arg);
      const eq = arg.indexOf("=");
      const flag = spec.flags.find((o) => matchesOption(name, o));
      if (flag && eq < 0) {
        out.push(flag);
        continue;
      }
      const valued = spec.valued.find((o) => matchesOption(name, o));
      if (valued) {
        const value = eq >= 0 ? arg.slice(eq + 1) : args[++i];
        if (value !== undefined) out.push(`${valued}=${value}`);
      }
      continue;
    }
    if (!/^-[^-]/.test(arg)) continue;
    for (let j = 1; j < arg.length; j++) {
      const ch = arg[j] as string;
      const mapped = spec.short[ch];
      if (mapped) out.push(mapped);
      const valuedLong = spec.shortValued[ch];
      if (valuedLong) {
        const value = j + 1 < arg.length ? arg.slice(j + 1) : args[++i];
        if (value !== undefined) out.push(`${valuedLong}=${value}`);
      }
      if (spec.shortWithValue.has(ch)) break;
    }
  }
  return out;
}

/**
 * The relay repository a network step runs against: bare, its config written
 * here and nowhere else. A pull's or push's borrows the caller's objects
 * through `objects/info/alternates` (the step transfers only what the two
 * sides do not share) and holds the caller's refs in `packed-refs` as
 * negotiation tips (a push's 1:1, so `--all`, `--tags` and `--mirror` see
 * them; a pull's under RELAY_LOCAL_REF_PREFIX); a clone's starts empty.
 * `core.alternateRefsCommand` replaces the `git --git-dir=<caller>
 * for-each-ref` git would otherwise run in the caller's repository — with the
 * credential in its environment — to list the alternate's refs. A shallow
 * caller's `shallow` file is copied. Removed when the call settles.
 *
 * The directory is owner-only on POSIX (mkdtemp(3) creates it 0700); on win32
 * it inherits the ACL of the user's temporary directory. Either way a process
 * running as the same user can write it, so `verify` re-reads it around the
 * network step: "before", every file the vault wrote byte-equal and nothing
 * else at the top level; "after", the files git does not write during a fetch
 * or push (`config`, `HEAD`, the alternates) still byte-equal and no
 * `commondir` or `config.worktree` — the files through which git would read
 * configuration from elsewhere. A mismatch fails the operation
 * (`GIT_OPERATION_FAILED`). This narrows the window; it cannot close it
 * against a same-user writer, which can still change the config between the
 * check and git's read.
 */
function createRelayRepo(opts: {
  objectsDir?: string;
  shallowFile?: string;
  objectFormat: string;
  head: string;
  refs: string[];
}): RelayRepo {
  const { objectsDir, shallowFile, objectFormat, head, refs } = opts;
  const dir = mkdtempSync(join(tmpdir(), "harpoc-git-relay-"));
  const dispose = () => {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  };
  const written = new Map<string, Buffer>();
  const write = (rel: string, content: string | Buffer) => {
    const bytes = typeof content === "string" ? Buffer.from(content, "utf8") : content;
    writeFileSync(join(dir, ...rel.split("/")), bytes);
    written.set(rel, bytes);
  };
  try {
    for (const sub of ["objects/info", "objects/pack", "refs/heads", "refs/tags"]) {
      mkdirSync(join(dir, sub), { recursive: true });
    }
    const sha256 = objectFormat === "sha256";
    write(
      "config",
      [
        "[core]",
        `\trepositoryformatversion = ${sha256 ? "1" : "0"}`,
        "\tbare = true",
        "\talternateRefsCommand = : no alternate refs",
        ...(sha256 ? ["[extensions]", "\tobjectFormat = sha256"] : []),
        "[push]",
        "\tdefault = current",
        "[gc]",
        "\tauto = 0",
        "[maintenance]",
        "\tauto = false",
        "",
      ].join("\n"),
    );
    write("HEAD", `${head}\n`);
    if (objectsDir !== undefined) write("objects/info/alternates", `${objectsDir}\n`);
    write("packed-refs", refs.map((r) => `${r}\n`).join(""));
    if (shallowFile !== undefined && existsSync(shallowFile)) {
      write("shallow", readFileSync(shallowFile));
    }
  } catch (err) {
    dispose();
    throw err;
  }
  const expectedTop = [
    ...new Set(["objects", "refs", ...[...written.keys()].map((rel) => rel.split("/")[0])]),
  ].sort();
  const verify = (phase: "before" | "after") => {
    const unchanged = (rel: string) => {
      try {
        return readFileSync(join(dir, ...rel.split("/"))).equals(written.get(rel) as Buffer);
      } catch {
        return false;
      }
    };
    let intact: boolean;
    if (phase === "before") {
      let top: string[] = [];
      try {
        top = readdirSync(dir).sort();
      } catch {
        /* an unreadable relay is not the vault's */
      }
      intact =
        top.length === expectedTop.length &&
        top.every((name, i) => name === expectedTop[i]) &&
        [...written.keys()].every(unchanged);
    } else {
      intact =
        RELAY_STABLE_FILES.filter((rel) => written.has(rel)).every(unchanged) &&
        RELAY_CONFIG_REDIRECTS.every((name) => !existsSync(join(dir, name)));
    }
    if (!intact) {
      throw VaultError.gitOperationFailed("the relay repository changed outside the vault");
    }
  };
  const setHead = (value: string) => write("HEAD", `${value}\n`);
  return { dir, dispose, verify, setHead };
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

/** Clean base environment for a spawned git process (HTTPS, and every local step). */
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
  return isolateGitConfig(env);
}

/**
 * No system or global git config on any git run (S1, face a): a stock Git for
 * Windows system config names `credential.helper=manager`, which would be told
 * the credential. Set after the allowlist, so an entry cannot reintroduce either.
 */
function isolateGitConfig(env: Record<string, string>): Record<string, string> {
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_CONFIG_GLOBAL = NULL_GIT_CONFIG;
  return env;
}

/**
 * An empty directory git is pointed at through `core.hooksPath` for one run
 * (N11): git looks hooks up there and nowhere else, so nothing in the
 * caller's `.git/hooks` executes. Vault-authored and empty by construction.
 */
function createEmptyHooksDir(): { dir: string; dispose: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "harpoc-git-hooks-"));
  return {
    dir,
    dispose: () => {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    },
  };
}

/** Vault-authored askpass launcher + helper in a temp dir; credential passed via env, not argv. */
function writeAskpass(): { launcher: string; dispose: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "harpoc-git-"));
  const helper = join(dir, "askpass.mjs");
  const node = process.execPath;
  let launcher: string;
  try {
    writeFileSync(helper, ASKPASS_HELPER_SRC, { mode: 0o700 });
    if (process.platform === "win32") {
      launcher = join(dir, "askpass.cmd");
      writeFileSync(launcher, `@"${node}" "${helper}" %*\r\n`, { mode: 0o700 });
    } else {
      launcher = join(dir, "askpass.sh");
      writeFileSync(launcher, `#!/bin/sh\nexec "${node}" "${helper}" "$@"\n`, { mode: 0o700 });
    }
  } catch (err) {
    rmSync(dir, { recursive: true, force: true });
    throw err;
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

/** Characters sh passes through verbatim outside any quoting. */
const SH_NEUTRAL_PART = /^[A-Za-z0-9%+,\-./:=@_]+$/;

/**
 * Build the GIT_SSH_COMMAND string git hands to its bundled sh. On Windows the
 * backslashes are converted to forward slashes first, because sh treats a
 * backslash as an escape — an unconverted "C:\Windows\System32\OpenSSH\ssh.exe"
 * arrives as "C:WindowsSystem32OpenSSHssh.exe" and fails to exec, taking the -i
 * identity and UserKnownHostsFile paths down with it. git and ssh accept
 * forward-slash paths in every one of those positions; POSIX paths carry no
 * backslashes and are unaffected.
 *
 * Every part that is not entirely shell-neutral is single-quoted for sh: single
 * quotes make whitespace, `$`, backtick and embedded double quotes all literal,
 * where double quotes would still let sh expand `$` and backticks inside (a
 * profile path like C:/Users/svc$deploy would arrive mangled). A literal `'`
 * in a part becomes the standard '\'' sequence. This composes with the readconf
 * double-quoting sshHardeningArgs applies to the UserKnownHostsFile VALUE: sh
 * strips the single quotes and hands ssh one argv element whose embedded double
 * quotes then survive for ssh's own whitespace re-tokenization of option values.
 */
function toGitSshCommand(parts: string[]): string {
  const normalized = process.platform === "win32" ? parts.map((p) => p.replace(/\\/g, "/")) : parts;
  return normalized
    .map((p) => (SH_NEUTRAL_PART.test(p) ? p : `'${p.replaceAll("'", "'\\''")}'`))
    .join(" ");
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
