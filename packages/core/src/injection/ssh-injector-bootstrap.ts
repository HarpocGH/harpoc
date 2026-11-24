import { randomBytes } from "node:crypto";
import type { InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, SSH_BOOTSTRAP_CONNECT_TIMEOUT_SEC, VaultError } from "@harpoc/shared";
import { asciiLowerCase } from "./allowlist.js";
import type { FsIsolationMechanism } from "./fs-isolation.js";
import type { NetworkIsolationMechanism } from "./network-isolation.js";
import { redactCaptured, spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { writeHelperFiles } from "./spawn-captured-helpers.js";
import type { HelperFiles, HelperFilesSpec } from "./spawn-captured-helpers.js";
import {
  buildSshPasswordEnv,
  isHostKeyFailure,
  isSshName,
  knownHostsLines,
  sshPasswordLoginArgs,
  sshPasswordPrompt,
  writeKnownHosts,
} from "./ssh-common.js";
import type { KnownHostsFiles } from "./ssh-common.js";
import type { SshPublicKey } from "./ssh-common-keys.js";
import {
  BOOTSTRAP_REMOTE_COMMAND,
  type BootstrapStatus,
  bootstrapStdin,
  readBootstrapStatus,
  redactedLines,
} from "./ssh-injector-bootstrap-script.js";
import type { TreeKillMechanism } from "./win32-job-wrapper.js";

/**
 * The bootstrap's password helper, which ssh starts through its launcher as `SSH_ASKPASS`. It
 * answers exactly one argument equal to the expected prompt, and then writes the call's word to
 * standard error before the password to standard output, both with `writeSync`, so that there is
 * no answer without the word; anything else exits 1 without a byte.
 */
export const SSH_PASSWORD_HELPER_SRC = `import { writeSync } from "node:fs";
const expected = process.env.HARPOC_SSH_PROMPT ?? "";
const word = process.env.HARPOC_SSH_WORD ?? "";
const password = process.env.HARPOC_SSH_PASSWORD ?? "";
delete process.env.HARPOC_SSH_PASSWORD;
if (
  process.argv.length !== 3 ||
  expected === "" ||
  word === "" ||
  password === "" ||
  process.argv[2] !== expected
) {
  process.exit(1);
}
writeSync(2, "\\n" + word + "\\n");
writeSync(1, password + "\\n");
`;

/** The helper's files; the launcher hands it the null device as its standard input. */
export const SSH_ASKPASS_FILES: HelperFilesSpec = {
  prefix: "harpoc-ssh-askpass-",
  script: "askpass.mjs",
  launcher: { posix: "askpass.sh", win32: "askpass.cmd" },
  source: SSH_PASSWORD_HELPER_SRC,
  nullStdin: true,
};

const NAMES_REFUSED = "host and user must be names of letters, digits, '.', '_' and '-'";
const MARKS_UNDRAWN = "ssh bootstrap could not draw its marks";
const TEMP_FILE_UNPREPARED = "a temporary file of the ssh bootstrap could not be prepared";

/** What the engine hands the bootstrap: the block's target and keys, the opt-in, and the stored password. */
export interface BootstrapCall {
  sshPath: string;
  host: string;
  port: number;
  user: string;
  hostKeys: readonly SshPublicKey[];
  installKey: SshPublicKey;
  sudoers: boolean;
  password: Buffer;
  policy: InjectionPolicy;
  budgetMs: number;
}

/** The spawn seam's fields for the outcome's row, folded as the `ssh` context folds them. */
export interface SpawnAuditFields {
  exit_code: number | null;
  timed_out: boolean;
  truncated?: true;
  network_isolation: boolean;
  isolation_mechanism?: NetworkIsolationMechanism;
  fs_isolation: boolean;
  fs_isolation_mechanism?: FsIsolationMechanism;
  sanitized?: true;
  descendant_sweep?: { killed: number; failed: boolean };
  tree_kill?: TreeKillMechanism;
  strict_tree_exit?: true;
}

/**
 * What one bootstrap call reads its outcome against: the helper's word, the script's frame, the
 * user and the lower-cased host ssh names in its refusal line, and the call's own redaction, which
 * the seam applied to both streams and the reader applies to each fixed text.
 */
export interface BootstrapExpected {
  word: string;
  frame: string;
  user: string;
  host: string;
  redact: (text: string) => string;
}

/**
 * The reading of one bootstrap call. A refused reading carries the error to throw, and for a
 * failed step the script's two status words; nothing in a reading comes from the streams.
 */
export type BootstrapReading =
  | { kind: "not_spawned"; error: VaultError }
  | { kind: "done"; key: "installed" | "present"; sudoers: "written" | "present" | "not_asked" }
  | { kind: "refused"; error: VaultError; status?: BootstrapStatus }
  | { kind: "unconfirmed" };

type Refusal = "password" | "other";

function redactedForms(text: string, redact: (text: string) => string): string[] {
  return redactedLines(`\n${text}`, redact).map((form) => form.slice(1));
}

function countWord(stderr: string, expected: BootstrapExpected): number {
  const forms = new Set(redactedForms(expected.word, expected.redact));
  let count = 0;
  for (const form of forms) count += stderr.split(form).length - 1;
  return count;
}

function lastLine(stderr: string): string {
  const lines = stderr
    .split("\n")
    .map((line) => (line.endsWith("\r") ? line.slice(0, -1) : line))
    .filter((line) => line !== "");
  return lines.at(-1) ?? "";
}

function refusal(line: string, expected: BootstrapExpected): Refusal | null {
  const prefixes = redactedForms(
    `${expected.user}@${expected.host}: Permission denied (`,
    expected.redact,
  );
  const suffixes = redactedForms(").", expected.redact);
  const methods = redactedForms("password", expected.redact);
  let recognised = false;
  let named = false;
  prefixes.forEach((prefix, form) => {
    const suffix = suffixes[form];
    const method = methods[form];
    if (suffix === undefined || method === undefined) return;
    if (line.length < prefix.length + suffix.length) return;
    if (!line.startsWith(prefix) || !line.endsWith(suffix)) return;
    const list = line.slice(prefix.length, line.length - suffix.length);
    if (/[\s()]/.test(list)) return;
    recognised = true;
    if (list.split(",").includes(method)) named = true;
  });
  if (!recognised) return null;
  return named ? "password" : "other";
}

function hostKeyFailed(stderr: string, line: string, expected: BootstrapExpected): boolean {
  return (
    isHostKeyFailure(stderr) ||
    redactedForms("Host key verification failed.", expected.redact).includes(line)
  );
}

function refused(error: VaultError): BootstrapReading {
  return { kind: "refused", error };
}

/**
 * B7's table over what the spawn seam returned, in its order; total and pure. Every reading that
 * keeps the secret rests on something definite: nothing spawned, the script's failed step, no word
 * of the helper, or its word once with exit 255 and ssh's own refusal as the last line; anything
 * the reader cannot place is `unconfirmed`.
 */
export function readBootstrapOutcome(
  seen: SpawnCapturedResult | { notSpawned: VaultError },
  expected: BootstrapExpected,
): BootstrapReading {
  if ("notSpawned" in seen) return { kind: "not_spawned", error: seen.notSpawned };
  if (seen.spawn_failed && !seen.timed_out) {
    return {
      kind: "not_spawned",
      error: VaultError.sshConnectFailed("the ssh client could not be started"),
    };
  }
  if (seen.truncated) return { kind: "unconfirmed" };
  const words = countWord(seen.stderr, expected);
  const session =
    seen.stdout !== "" ||
    (typeof seen.exit_code === "number" && seen.exit_code !== 255 && words >= 1);
  const status = session ? readBootstrapStatus(seen.stdout, expected.frame, expected.redact) : null;
  if (
    status !== null &&
    (status.key === "installed" || status.key === "present") &&
    (status.dropIn === "written" || status.dropIn === "present" || status.dropIn === "not_asked")
  ) {
    return { kind: "done", key: status.key, sudoers: status.dropIn };
  }
  if (status !== null && (status.key === "not_attempted" || status.key === "failed")) {
    return {
      kind: "refused",
      error: VaultError.sshBootstrapStepFailed(status.dropIn, status.key),
      status,
    };
  }
  if (session) return { kind: "unconfirmed" };
  const last = lastLine(seen.stderr);
  const refusalKind = refusal(last, expected);
  if (words === 0) {
    if (hostKeyFailed(seen.stderr, last, expected)) {
      return refused(VaultError.sshHostKeyMismatch());
    }
    if (refusalKind === "password") return refused(VaultError.sshPasswordRefused());
    if (refusalKind === "other") return refused(VaultError.sshPasswordNotOffered());
    return refused(VaultError.sshConnectFailed());
  }
  if (words === 1 && seen.exit_code === 255 && refusalKind !== null) {
    return refused(VaultError.sshPasswordRefused());
  }
  return { kind: "unconfirmed" };
}

/**
 * A reading and the spawn's fields for its row: all of them where the seam returned, the policy's
 * two isolation flags alone where the seam threw, none where nothing reached the seam.
 */
export type BootstrapOutcome = BootstrapReading & {
  spawn?: SpawnAuditFields | Pick<SpawnAuditFields, "network_isolation" | "fs_isolation">;
};

/** Refuses the ssh bootstrap on a Windows vault host; returns on every other. */
export function refuseWindowsVaultHost(): void {
  if (process.platform === "win32") throw VaultError.sshBootstrapOnWindows();
}

const MARK_DRAWS = 64;

function drawMark(redact: (text: string) => string): string | null {
  for (let i = 0; i < MARK_DRAWS; i++) {
    const mark = randomBytes(18).toString("base64url");
    const line = `\n${mark}\n`;
    if (redactedLines(line, redact).every((form) => form === line)) return mark;
  }
  return null;
}

function spawnAuditFields(
  r: SpawnCapturedResult,
  networkIsolation: boolean,
  fsIsolation: boolean,
): SpawnAuditFields {
  return {
    exit_code: r.exit_code,
    timed_out: r.timed_out,
    ...(r.truncated ? { truncated: true } : {}),
    network_isolation: networkIsolation,
    ...(r.isolation_mechanism ? { isolation_mechanism: r.isolation_mechanism } : {}),
    fs_isolation: fsIsolation,
    ...(r.fs_isolation_mechanism ? { fs_isolation_mechanism: r.fs_isolation_mechanism } : {}),
    ...(r.redacted ? { sanitized: true } : {}),
    ...(r.descendant_sweep ? { descendant_sweep: r.descendant_sweep } : {}),
    ...(r.tree_kill ? { tree_kill: r.tree_kill } : {}),
    ...(r.strict_tree_exit ? { strict_tree_exit: true } : {}),
  };
}

function notSpawned(error: VaultError): BootstrapOutcome {
  return { kind: "not_spawned", error };
}

function tempFileUnprepared(): VaultError {
  return new VaultError(ErrorCode.FILE_IO_ERROR, TEMP_FILE_UNPREPARED);
}

/**
 * The bootstrap's one spawn: ssh with password login as its one method, the vault's helper as its
 * forced askpass, and the framed input on its standard input; the outcome read by
 * `readBootstrapOutcome`. Never throws a `VaultError` and returns no byte the host wrote. The
 * helper's and the known-hosts files are removed, and what the seam was handed no longer names
 * the password, on every path once the call settled.
 */
export async function runBootstrap(call: BootstrapCall): Promise<BootstrapOutcome> {
  if (
    !isSshName(call.host) ||
    !isSshName(call.user) ||
    !Number.isInteger(call.port) ||
    call.port < 1 ||
    call.port > 65_535
  ) {
    return notSpawned(VaultError.invalidSshConfig(NAMES_REFUSED));
  }
  const host = asciiLowerCase(call.host);
  const secrets = [call.password.toString("utf8")];
  const redact = (text: string): string => redactCaptured(text, secrets);
  const word = drawMark(redact);
  const frame = drawMark(redact);
  if (word === null || frame === null) {
    return notSpawned(new VaultError(ErrorCode.INTERNAL_ERROR, MARKS_UNDRAWN));
  }
  const expected: BootstrapExpected = { word, frame, user: call.user, host, redact };
  let knownHosts: KnownHostsFiles | undefined;
  let helper: HelperFiles | undefined;
  let env: Record<string, string> | undefined;
  try {
    try {
      knownHosts = writeKnownHosts(knownHostsLines(host, call.port, call.hostKeys));
      helper = writeHelperFiles(SSH_ASKPASS_FILES, tempFileUnprepared);
    } catch {
      return notSpawned(tempFileUnprepared());
    }
    const argv = [
      ...sshPasswordLoginArgs(knownHosts, SSH_BOOTSTRAP_CONNECT_TIMEOUT_SEC),
      "-p",
      String(call.port),
      "-l",
      call.user,
      "--",
      host,
      BOOTSTRAP_REMOTE_COMMAND,
    ];
    env = buildSshPasswordEnv(call.policy.env_allowlist, {
      launcher: helper.launcher,
      prompt: sshPasswordPrompt(call.user, host),
      word,
      password: secrets[0] as string,
    });
    const networkIsolation = call.policy.network_isolation === true;
    const fsIsolation = call.policy.fs_isolation === true;
    let seen: SpawnCapturedResult;
    try {
      seen = await spawnCaptured(call.sshPath, argv, {
        env,
        timeoutMs: call.budgetMs,
        stdin: bootstrapStdin(
          frame,
          call.installKey.line,
          call.sudoers ? call.password : undefined,
        ),
        redact: secrets,
        networkIsolation,
        fsIsolation,
        strictTreeExit: call.policy.strict_tree_exit === true,
      });
    } catch (err) {
      if (!(err instanceof VaultError)) throw err;
      return {
        ...readBootstrapOutcome({ notSpawned: err }, expected),
        spawn: { network_isolation: networkIsolation, fs_isolation: fsIsolation },
      };
    }
    return {
      ...readBootstrapOutcome(seen, expected),
      spawn: spawnAuditFields(seen, networkIsolation, fsIsolation),
    };
  } finally {
    helper?.dispose();
    knownHosts?.dispose();
    if (env !== undefined) delete env.HARPOC_SSH_PASSWORD;
    secrets.length = 0;
  }
}
