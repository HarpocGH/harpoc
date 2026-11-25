import type { InjectionPolicy, RenderEntry } from "@harpoc/shared";
import {
  ErrorCode,
  RENDER_CONNECT_TIMEOUT_SEC,
  SSH_HOST_KEY_TYPES,
  VaultError,
} from "@harpoc/shared";
import { asciiLowerCase, controlledPathDirs, resolveAndMatchCommand } from "./allowlist.js";
import { writeRemoteFile } from "./sftp/sftp-writer.js";
import type { RenderWritten, SftpChannel, SftpWriteOutcome } from "./sftp/sftp-writer.js";
import { redactCaptured, spawnDuplex } from "./spawn-captured.js";
import type { DuplexChild, SpawnCapturedResult } from "./spawn-captured.js";
import { EphemeralSshAgent } from "./ssh-agent/index.js";
import {
  assertNativeWin32SshClient,
  buildSshEnv,
  isSshName,
  knownHostsLines,
  sshSftpSubsystemArgs,
  writeIdentityFile,
  writeKnownHosts,
} from "./ssh-common.js";
import type { KnownHostsFiles, TempSshFile } from "./ssh-common.js";
import { parseSshPublicKey } from "./ssh-common-keys.js";
import type { SshPublicKey } from "./ssh-common-keys.js";
import { hostKeyFailureSeen } from "./ssh-injector-bootstrap.js";
import type { SpawnAuditFields } from "./ssh-injector-bootstrap.js";

const NAMES_REFUSED = "host and user must be names of letters, digits, '.', '_' and '-'";
const TEMP_FILE_UNPREPARED = "a temporary file of the sftp render could not be prepared";
const HOST_KEY_UNREAD = "a render host key line does not parse";

/** The engine's hold on a running render: `signal` ends it at a seal, `written` is what the writer last reported. */
export interface RenderControl {
  readonly signal: AbortSignal;
  written: RenderWritten;
}

/**
 * A judged render: the resolved client, the entry, the key, the content, the list of every
 * value for the error stream's redaction, the budget, and the key's policy with `fs_isolation`
 * and `strict_tree_exit` already combined over the key and the slots.
 */
export interface RenderPlan {
  sshPath: string;
  entry: RenderEntry;
  keyPem: string;
  content: Buffer;
  redact: string[];
  timeoutMs: number;
  policy: InjectionPolicy;
}

export type RenderSpawnFields = Pick<
  SpawnAuditFields,
  | "network_isolation"
  | "isolation_mechanism"
  | "fs_isolation"
  | "fs_isolation_mechanism"
  | "sanitized"
  | "descendant_sweep"
  | "tree_kill"
  | "strict_tree_exit"
>;

export type RenderRun =
  | {
      kind: "not_spawned";
      error: VaultError;
      spawn?: Pick<RenderSpawnFields, "network_isolation" | "fs_isolation">;
    }
  | { kind: "ran"; outcome: SftpWriteOutcome; spawn: RenderSpawnFields };

/** The render's ssh client: `ssh` on the policy's `command_allowlist`, on win32 the native build. */
export async function resolveRenderClient(policy: InjectionPolicy): Promise<string> {
  const sshPath = resolveAndMatchCommand("ssh", policy.command_allowlist, controlledPathDirs());
  assertNativeWin32SshClient(sshPath);
  return sshPath;
}

/**
 * The render's outcome, total and pure: a client that did not start is `connect`; a writer that
 * stopped at `connect` beside ssh's host-key failure is `host_key`; else the writer's. Nothing of
 * the stream is in a reading.
 */
export function readRenderOutcome(
  writer: SftpWriteOutcome,
  seen: SpawnCapturedResult,
  redact: (text: string) => string,
): SftpWriteOutcome {
  if (seen.spawn_failed && !seen.timed_out) return { written: "no", reason: "connect" };
  if (writer.reason === "connect" && hostKeyFailureSeen(seen.stderr, redact)) {
    return { written: "no", reason: "host_key" };
  }
  return writer;
}

function notSpawned(error: VaultError): RenderRun {
  return { kind: "not_spawned", error };
}

function tempFileUnprepared(): VaultError {
  return new VaultError(ErrorCode.FILE_IO_ERROR, TEMP_FILE_UNPREPARED);
}

function renderSpawnFields(
  seen: SpawnCapturedResult,
  networkIsolation: boolean,
  fsIsolation: boolean,
): RenderSpawnFields {
  return {
    network_isolation: networkIsolation,
    ...(seen.isolation_mechanism ? { isolation_mechanism: seen.isolation_mechanism } : {}),
    fs_isolation: fsIsolation,
    ...(seen.fs_isolation_mechanism ? { fs_isolation_mechanism: seen.fs_isolation_mechanism } : {}),
    ...(seen.redacted ? { sanitized: true } : {}),
    ...(seen.descendant_sweep ? { descendant_sweep: seen.descendant_sweep } : {}),
    ...(seen.tree_kill ? { tree_kill: seen.tree_kill } : {}),
    ...(seen.strict_tree_exit ? { strict_tree_exit: true } : {}),
  };
}

/**
 * The render's one spawn: `ssh -s … sftp` pinned to the entry's own host keys, the key through
 * the ephemeral agent, the content written by `writeRemoteFile` over the two-way pipe. Never
 * throws a `VaultError` and returns no byte the host or ssh wrote; a `not_spawned` error reaches
 * the caller as it stands, so its text holds no value. `control.signal` cuts the
 * writer, so that no frame is handed on after it, and then ends the child. The files, the agent,
 * the content and the redaction list are gone on every path once the call settled.
 */
export async function runRender(plan: RenderPlan, control: RenderControl): Promise<RenderRun> {
  const { entry, policy } = plan;
  let knownHosts: KnownHostsFiles | undefined;
  let agent: EphemeralSshAgent | undefined;
  let identity: TempSshFile | undefined;
  let detach: (() => void) | undefined;
  try {
    if (
      !isSshName(entry.host) ||
      !isSshName(entry.user) ||
      !Number.isInteger(entry.port) ||
      entry.port < 1 ||
      entry.port > 65_535
    ) {
      return notSpawned(VaultError.invalidSshConfig(NAMES_REFUSED));
    }
    const hostKeys: SshPublicKey[] = [];
    for (const line of entry.host_keys) {
      const key = parseSshPublicKey(line, SSH_HOST_KEY_TYPES);
      if (key === null) return notSpawned(VaultError.vaultCorrupted(HOST_KEY_UNREAD));
      hostKeys.push(key);
    }
    if (control.signal.aborted) return notSpawned(VaultError.vaultLocked());
    const host = asciiLowerCase(entry.host);
    try {
      knownHosts = writeKnownHosts(knownHostsLines(host, entry.port, hostKeys));
    } catch {
      return notSpawned(tempFileUnprepared());
    }
    try {
      agent = await EphemeralSshAgent.start(plan.keyPem);
    } catch (err) {
      if (!(err instanceof VaultError)) throw err;
      return notSpawned(err);
    }
    try {
      identity = writeIdentityFile(agent.publicKeyOpenssh);
    } catch {
      return notSpawned(tempFileUnprepared());
    }
    if (control.signal.aborted) return notSpawned(VaultError.vaultLocked());

    const networkIsolation = policy.network_isolation === true;
    const fsIsolation = policy.fs_isolation === true;
    let child: DuplexChild;
    try {
      child = await spawnDuplex(
        plan.sshPath,
        [
          ...sshSftpSubsystemArgs(knownHosts, identity.file, RENDER_CONNECT_TIMEOUT_SEC),
          "-p",
          String(entry.port),
          "-s",
          "--",
          `${entry.user}@${host}`,
          "sftp",
        ],
        {
          env: buildSshEnv(agent.authSock, policy.env_allowlist),
          timeoutMs: plan.timeoutMs,
          redact: plan.redact,
          networkIsolation,
          fsIsolation,
          strictTreeExit: policy.strict_tree_exit === true,
        },
      );
    } catch (err) {
      if (!(err instanceof VaultError)) throw err;
      return {
        kind: "not_spawned",
        error: err,
        spawn: { network_isolation: networkIsolation, fs_isolation: fsIsolation },
      };
    }

    const cut = new AbortController();
    let consumerFailed = false;
    const channel: SftpChannel = {
      write: (chunk) => child.write(chunk),
      onData: (consumer) => {
        child.onData((chunk) => {
          if (consumerFailed) return;
          try {
            consumer(chunk);
          } catch {
            consumerFailed = true;
            cut.abort("ended");
            child.abort();
          }
        });
      },
    };
    const seal = (): void => {
      cut.abort("ended");
      child.abort();
    };
    if (control.signal.aborted) {
      seal();
    } else {
      control.signal.addEventListener("abort", seal, { once: true });
      detach = () => control.signal.removeEventListener("abort", seal);
    }
    const writing = writeRemoteFile(channel, entry.path, plan.content, cut.signal, (written) => {
      control.written = written;
    });
    void child.settled.then((seen) => {
      cut.abort(seen.timed_out ? "timeout" : "ended");
    });

    let wrote: SftpWriteOutcome;
    try {
      wrote = await writing;
    } catch (err) {
      child.abort();
      await child.settled;
      throw err;
    }
    if (wrote.reason === undefined) child.end();
    else if (!cut.signal.aborted) child.abort();
    const seen = await child.settled;
    const writer: SftpWriteOutcome = consumerFailed
      ? { written: wrote.written, reason: "protocol" }
      : wrote;
    return {
      kind: "ran",
      outcome: readRenderOutcome(writer, seen, (text) => redactCaptured(text, plan.redact)),
      spawn: renderSpawnFields(seen, networkIsolation, fsIsolation),
    };
  } finally {
    detach?.();
    agent?.dispose();
    knownHosts?.dispose();
    identity?.dispose();
    plan.content.fill(0);
    plan.redact.length = 0;
  }
}
