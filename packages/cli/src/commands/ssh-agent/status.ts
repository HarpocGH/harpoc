import { readdirSync, type Dirent } from "node:fs";
import { join } from "node:path";
import type { Command } from "commander";
import { VaultError } from "@harpoc/shared";
import { probeAgentSocket } from "../../utils/agent-probe.js";
import type { AgentProbe, AgentProbeFailure } from "../../utils/agent-probe.js";
import { handleError, printJson } from "../../utils/output.js";
import {
  agentSocketPipeName,
  assertConsumerName,
  consumerDir,
  resolveRuntimeDir,
} from "../../utils/runtime-dir.js";

interface SshAgentStatusOptions {
  consumer?: string;
  runtimeDir?: string;
  json?: boolean;
}

/** One consumer's socket and what one identities request found there. */
export type ConsumerSocketStatus = { consumer: string; socketPath: string } & AgentProbe;

/** How long one socket has to answer the identities request; the sockets are probed together. */
export const STATUS_PROBE_TIMEOUT_MS = 2_000;

const NOT_LISTENING: Readonly<Record<AgentProbeFailure, string>> = {
  no_socket: "no socket",
  not_a_socket: "not a socket",
  refused: "connection refused",
  permission_denied: "permission denied",
  timeout: `no answer within ${String(STATUS_PROBE_TIMEOUT_MS / 1_000)} s`,
  not_an_agent: "not an ssh-agent answer",
  unreachable: "unreachable",
};

/** The consumers to probe: the one named, or every directory under the runtime directory, by name. */
function consumersOf(runtimeDir: string, consumer: string | undefined): string[] {
  if (consumer !== undefined) {
    assertConsumerName(consumer);
    return [consumer];
  }
  let entries: Dirent[];
  try {
    entries = readdirSync(runtimeDir, { withFileTypes: true });
  } catch (err) {
    throw VaultError.invalidInput(
      `--runtime-dir: ${listingFailure((err as NodeJS.ErrnoException).code)}: ${runtimeDir}`,
    );
  }
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
}

/** Why the runtime directory cannot be listed, in `runtime-dir.ts`'s words: the errno's class. */
function listingFailure(code: string | undefined): string {
  switch (code) {
    case "ENOENT":
      return "no such directory";
    case "ENOTDIR":
      return "not a directory";
    case "EACCES":
    case "EPERM":
      return "permission denied";
    default:
      return "the consumer directories cannot be listed";
  }
}

/**
 * A peer's text on a terminal line: every C0 and C1 control character (`U+0000`–`U+001F`,
 * `U+007F`–`U+009F`) shown as `?` — a char-code scan, since `no-control-regex` flags the class.
 */
function printable(text: string): string {
  return Array.from(text, (char) => {
    const code = char.charCodeAt(0);
    return code <= 0x1f || (code >= 0x7f && code <= 0x9f) ? "?" : char;
  }).join("");
}

/**
 * Probe each consumer's `<runtime-dir>/<consumer>/ssh-agent.sock` (win32: its pipe
 * `agentSocketPipeName(consumer)`) with one identities request —
 * what `ssh-add -l` sends — under one deadline. Opens no vault and reads no ambient
 * `$RUNTIME_DIRECTORY`: the socket answers for the daemon, and the command runs as any user that
 * can reach the directory.
 */
export async function sshAgentStatus(
  runtimeDir: string,
  consumer: string | undefined,
  platform: NodeJS.Platform = process.platform,
): Promise<ConsumerSocketStatus[]> {
  const sockets = consumersOf(runtimeDir, consumer).map((name) => ({
    consumer: name,
    socketPath:
      platform === "win32"
        ? agentSocketPipeName(name)
        : join(consumerDir(runtimeDir, name), "ssh-agent.sock"),
  }));
  return Promise.all(
    sockets.map(async (socket) => ({
      ...socket,
      ...(await probeAgentSocket(socket.socketPath, STATUS_PROBE_TIMEOUT_MS)),
    })),
  );
}

/** The human report: one header line per consumer, then one `ssh-add -l`-like line per identity. */
export function statusLines(statuses: ConsumerSocketStatus[], runtimeDir: string): string[] {
  if (statuses.length === 0) return [`No consumer directory under ${runtimeDir}.`];
  return statuses.flatMap((status) => {
    const where = `(${status.socketPath})`;
    if (!status.listening) {
      return [
        `consumer ${status.consumer}: not listening — ${NOT_LISTENING[status.reason]} ${where}`,
      ];
    }
    if (status.identities === null) {
      return [
        `consumer ${status.consumer}: listening — the identities request was refused (a locked vault or a spent listing budget refuses it) ${where}`,
      ];
    }
    const count = status.identities.length;
    const counted =
      count === 0 ? "no identities" : `${String(count)} identit${count === 1 ? "y" : "ies"}`;
    return [
      `consumer ${status.consumer}: listening — ${counted} ${where}`,
      ...status.identities.map(
        (identity) =>
          `  ${printable(identity.keyType)} ${identity.fingerprint} ${printable(identity.comment)}`,
      ),
    ];
  });
}

export function registerSshAgentStatusCommand(sshAgent: Command): void {
  sshAgent
    .command("status")
    .description(
      "Report each consumer's ssh-agent socket (server start --ssh-agent): listening or not, and the identities it lists — key type, SHA256 fingerprint, the secret's handle; opens no vault",
    )
    .option(
      "--consumer <name>",
      "One consumer (an agent user's name); without it, every consumer directory under --runtime-dir",
    )
    .option(
      "--runtime-dir <path>",
      "The daemon's runtime directory, holding <consumer>/ssh-agent.sock (required; no $RUNTIME_DIRECTORY is read)",
    )
    .option("--json", "Output as JSON")
    .action(async (options: SshAgentStatusOptions) => {
      try {
        const runtimeDir = resolveRuntimeDir(options.runtimeDir, undefined);
        if (runtimeDir === undefined) {
          throw VaultError.invalidInput(
            "--runtime-dir <path> is required: the daemon's runtime directory (no $RUNTIME_DIRECTORY is read)",
          );
        }
        const statuses = await sshAgentStatus(runtimeDir.path, options.consumer);
        if (options.json) {
          printJson({ runtimeDir: runtimeDir.path, consumers: statuses });
          return;
        }
        for (const line of statusLines(statuses, runtimeDir.path)) console.log(line);
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
