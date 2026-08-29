import type { ConnectionConfig, InjectionPolicy, SftpAction, SftpResult } from "@harpoc/shared";
import { DEFAULT_SSH_TIMEOUT_MS, ErrorCode, VaultError } from "@harpoc/shared";
import { controlledPathDirs, matchesHostAllowlist, resolveAndMatchCommand } from "./allowlist.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { spawnCaptured } from "./spawn-captured.js";
import { EphemeralSshAgent } from "./ssh-agent/index.js";
import {
  buildSshEnv,
  isHostKeyFailure,
  sshHardeningArgs,
  writeIdentityFile,
  writeKnownHosts,
  writeTempSshFile,
} from "./ssh-common.js";
import type { TempSshFile } from "./ssh-common.js";

/**
 * Metadata-only audit projection of an SFTP operation (design §7.2) — never a
 * credential or file content. Every field is request-derived (available before
 * the operation runs), so the same projection covers both a successful use
 * and a denial: `buildSftpAuditDetails` needs only the action, not a result.
 */
export interface SftpAuditDetails {
  host: string;
  operation: string;
  port: number | null;
  remote_path: string;
  local_path: string | null;
}

/** Builds the metadata-only audit projection for an SFTP action. Pure — the
 * engine calls it for both success and failed `secret.use` rows. */
export function buildSftpAuditDetails(action: SftpAction): SftpAuditDetails {
  return {
    host: action.host,
    operation: action.operation,
    port: action.port ?? null,
    remote_path: action.remote_path,
    local_path: action.local_path ?? null,
  };
}

/**
 * Write the single scripted sftp command to a 0600 batch file in a 0700 temp
 * directory (design §6.4) — sftp's own argv carries no path at all beyond the
 * batch file itself, so the vault-authored command is the only thing that
 * reaches the transfer.
 */
function writeBatchFile(content: string): TempSshFile {
  return writeTempSshFile("harpoc-sftp-batch-", "batch", content);
}

/** True if `value` contains any C0 control character (including CR/LF/NUL) —
 * mirrors schemas.ts's `hasControlCharacters`. The schema already refuses
 * these on `remote_path`/`local_path` at the boundary, but core never
 * re-validates a caller-supplied action inside `useSecret`, so this is the
 * injector's own defense in depth — a newline is the one character that
 * could otherwise inject a second scripted batch command. */
function hasBatchControlCharacters(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) <= 0x1f) return true;
  }
  return false;
}

/**
 * Refuse a batch-injection-relevant path shape, then double-quote it for
 * sftp's batch-mode tokenizer (so a path containing whitespace survives as
 * one token). Quoting alone does not neutralize an attacker-controlled path:
 * OpenSSH sftp's batch reader (`makeargv`) strips the surrounding quotes
 * during tokenization, and only then do `parse_getput_flags`/`parse_ls_flags`
 * run `getopt(3)` over the result — so a token that arrived as `"-r"` is an
 * ordinary `-r` option by the time sftp's own flag parser sees it, regardless
 * of the quotes wrapped around it here. Refused, in order:
 *  - a leading `-` — would parse as an sftp option (`-r`/`-a`/`-P`/...)
 *    instead of a path (reachable from either the `remote_path` or
 *    `local_path` slot, on either side of `getopt`'s argument permutation);
 *  - a trailing `\` — immediately before the closing `"` it escapes that
 *    quote inside the double-quoted token, merging this token with whatever
 *    follows and silently retargeting the transfer;
 *  - a `"` — sftp's batch parser has no escape for a quote inside a quoted
 *    token, so an unescapable quote could desync the single scripted
 *    command;
 *  - a control character or newline — the schema already refuses these at
 *    the boundary, but this makes the injector's own defense symmetric with
 *    the checks above (a newline is the one character that could inject a
 *    second scripted command).
 */
function quotePath(path: string): string {
  if (path.startsWith("-")) {
    throw VaultError.invalidInput(
      "sftp path must not start with '-' (would be parsed as an sftp option)",
    );
  }
  if (path.endsWith("\\")) {
    throw VaultError.invalidInput(
      "sftp path must not end with '\\' (would merge with the closing quote)",
    );
  }
  if (path.includes('"')) {
    throw VaultError.invalidInput("sftp path must not contain a double-quote character");
  }
  if (hasBatchControlCharacters(path)) {
    throw VaultError.invalidInput("sftp path must not contain control characters or newlines");
  }
  return `"${path}"`;
}

/**
 * `local_path` is schema-required for upload/download (`refineSftpAction`) —
 * this is defense in depth for a caller that reaches the injector without
 * going through schema validation.
 */
function requireLocalPath(action: SftpAction): string {
  if (!action.local_path) {
    throw VaultError.invalidInput(`local_path is required for ${action.operation}`);
  }
  return action.local_path;
}

/** The single scripted sftp command for the action's operation (design §6.4). */
function buildBatchCommand(action: SftpAction): string {
  const remote = quotePath(action.remote_path);
  switch (action.operation) {
    case "upload":
      return `put ${quotePath(requireLocalPath(action))} ${remote}\n`;
    case "download":
      return `get ${remote} ${quotePath(requireLocalPath(action))}\n`;
    case "list":
      return `ls -l ${remote}\n`;
  }
}

/** Maps a settled spawn result to the process-shaped `SftpResult`, or throws
 * for the outcomes the vault treats as a hard failure rather than a return
 * value: a pinned host-key mismatch, a connect failure (including OpenSSH's
 * generic exit 255 for connection/auth/protocol failure), or (unlike a
 * remote shell command's arbitrary exit status) any other non-zero exit from
 * the sftp client itself — sftp's batch mode aborts and reports failure on
 * the first failed scripted command, so a non-zero exit is always the
 * vault's own signal that the operation did not complete. */
function toSftpResult(r: SpawnCapturedResult, host: string): SftpResult {
  if (isHostKeyFailure(r.stderr)) {
    throw VaultError.sshHostKeyMismatch(host);
  }
  if (r.spawn_failed) {
    throw VaultError.sshConnectFailed(host);
  }
  if (r.timed_out) {
    return {
      type: "sftp",
      exit_code: r.exit_code,
      stdout: r.stdout,
      stderr: r.stderr,
      timed_out: true,
      truncated: r.truncated ? true : undefined,
      signal: r.signal ?? undefined,
      error: ErrorCode.PROCESS_TIMEOUT,
    };
  }
  // OpenSSH clients exit 255 on connection/auth/protocol failure (a failed
  // batch command exits 1) — classify it as the connect failure it is. The
  // host-key check above must keep winning (a pinned-key mismatch also exits
  // 255), and a timeout is the vault's own kill, never a peer connect
  // failure — the same order the ssh injector classifies in.
  if (r.exit_code === 255) {
    throw VaultError.sshConnectFailed(host);
  }
  if (r.exit_code !== 0) {
    throw VaultError.sftpOperationFailed(r.exit_code ?? -1);
  }
  return {
    type: "sftp",
    exit_code: r.exit_code,
    stdout: r.stdout,
    stderr: r.stderr,
    timed_out: undefined,
    truncated: r.truncated ? true : undefined,
    signal: r.signal ?? undefined,
    error: undefined,
  };
}

/**
 * Executes an SFTP file operation with the private key served through an
 * ephemeral in-process ssh-agent — the same agent lifecycle the SSH context
 * uses verbatim (thesis §4.5.7): host allowlist (fail-safe deny), strict
 * host-key verification against the pinned known_hosts (no TOFU), the sftp
 * binary pinned to a resolved absolute path in the command allowlist, and the
 * single scripted operation carried in a vault-authored 0600 batch file
 * rather than sftp argv (sftp has no per-path CLI flags of its own — the
 * batch file is the only way to script `put`/`get`/`ls` non-interactively).
 */
export async function executeSftpAction(
  action: SftpAction,
  secretValue: Uint8Array,
  policy: InjectionPolicy,
  config: ConnectionConfig | undefined,
): Promise<SftpResult> {
  // Defense in depth beside the schema's first-character anchor (mirrors the
  // SSH context): host and user reach argv, so a leading dash must never
  // parse as an option.
  if (action.host.startsWith("-") || action.user.startsWith("-")) {
    throw VaultError.invalidSshConfig("host and user must not start with '-'");
  }

  // Host target allowlist — fail-safe deny (process-mediated posture).
  if (
    policy.host_allowlist.length === 0 ||
    !matchesHostAllowlist(action.host, policy.host_allowlist)
  ) {
    throw VaultError.hostNotAllowed(action.host);
  }

  // Pinned host keys are required — no trust-on-first-use. SFTP reuses the
  // SSH known_hosts list unchanged (design §5.5).
  const knownHosts = config?.ssh?.known_hosts;
  if (!knownHosts || knownHosts.length === 0) {
    throw VaultError.sshNotConfigured();
  }

  // Resolve + allowlist the sftp binary (fail-safe deny, absolute-path pinned).
  const sftpPath = resolveAndMatchCommand("sftp", policy.command_allowlist, controlledPathDirs());

  // The scripted command is built (and its paths validated) before any
  // temp resource is created, so a refused path never leaves a file behind.
  const batchCommand = buildBatchCommand(action);

  const keyPem = Buffer.from(secretValue).toString("utf8");
  const timeoutMs = action.timeout_ms ?? DEFAULT_SSH_TIMEOUT_MS;
  const kh = writeKnownHosts(knownHosts);

  let agent: EphemeralSshAgent;
  try {
    agent = await EphemeralSshAgent.start(keyPem);
  } catch (err) {
    kh.dispose();
    throw err;
  }

  let identity: TempSshFile | null = null;
  let batch: TempSshFile | null = null;
  try {
    identity = writeIdentityFile(agent.publicKeyOpenssh);
    batch = writeBatchFile(batchCommand);

    const args = [
      ...sshHardeningArgs(kh.file, identity.file, Math.max(1, Math.ceil(timeoutMs / 1000))),
      ...(action.port !== undefined ? ["-P", String(action.port)] : []),
      "-oBatchMode=yes",
      "-b",
      batch.file,
      `${action.user}@${action.host}`,
    ];
    const env = buildSshEnv(agent.authSock, policy.env_allowlist);
    const networkIsolation = policy.network_isolation === true;
    const fsIsolation = policy.fs_isolation === true;

    const r = await spawnCaptured(sftpPath, args, {
      env,
      timeoutMs,
      redact: [keyPem],
      networkIsolation,
      fsIsolation,
    });

    return toSftpResult(r, action.host);
  } finally {
    agent.dispose();
    kh.dispose();
    identity?.dispose();
    batch?.dispose();
  }
}
