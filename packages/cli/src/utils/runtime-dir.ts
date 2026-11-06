import { readdirSync, statSync, type Dirent, type Stats } from "node:fs";
import { join } from "node:path";
import { agentNameSchema, MAX_UNIX_SOCKET_PATH_BYTES, VaultError } from "@harpoc/shared";

/** Where the runtime directory came from — the label its refusals name. */
export type RuntimeDirSource = "--runtime-dir" | "$RUNTIME_DIRECTORY";

export interface RuntimeDir {
  path: string;
  source: RuntimeDirSource;
}

/** Group write (`0o020`) and every world bit (`0o007`): none may be set. */
const GROUP_WRITE_OR_WORLD = 0o027;

/**
 * A consumer directory's name: lowercase, so two agents differing in case
 * never share a directory on a case-insensitive filesystem, and never
 * dash-led, so no tool takes it for an option.
 */
const CONSUMER_SEGMENT = /^[a-z0-9_][a-z0-9_-]*$/;

/** A runtime or consumer directory's mode: `0750` or stricter. */
export function isPrivateDirMode(mode: number): boolean {
  return (mode & GROUP_WRITE_OR_WORLD) === 0;
}

/**
 * The runtime directory: `--runtime-dir` wins, else systemd's
 * `$RUNTIME_DIRECTORY`. An empty or flag-shaped option refuses as
 * `--vault-dir` does; a variable listing several directories (`:`-joined,
 * systemd.exec(5) `RuntimeDirectory=`) refuses, since none of them is marked
 * as the runtime directory.
 */
export function resolveRuntimeDir(
  option: string | undefined,
  env: { RUNTIME_DIRECTORY?: string },
): RuntimeDir | undefined {
  if (option !== undefined) {
    if (option.trim() === "") throw VaultError.invalidInput("--runtime-dir: empty path");
    if (option.startsWith("-")) {
      throw VaultError.invalidInput(
        "--runtime-dir: a flag, not a path (give a path that starts with a dash as ./-name)",
      );
    }
    return { path: option, source: "--runtime-dir" };
  }
  const fromEnv = env.RUNTIME_DIRECTORY;
  if (fromEnv === undefined || fromEnv === "") return undefined;
  if (fromEnv.includes(":")) {
    throw VaultError.invalidInput(
      `$RUNTIME_DIRECTORY: several directories (${fromEnv}); name one with --runtime-dir`,
    );
  }
  return { path: fromEnv, source: "$RUNTIME_DIRECTORY" };
}

/** Refuses `INVALID_INPUT` unless the runtime directory is this user's own, `0750` or stricter. */
export function assertRuntimeDir(dir: RuntimeDir): void {
  assertPrivateDir(dir.path, dir.source);
}

/** Refuses `INVALID_INPUT` unless the consumer is an agent's name that is also a safe path segment. */
export function assertConsumerName(consumer: string): void {
  if (!agentNameSchema.safeParse(consumer).success || !CONSUMER_SEGMENT.test(consumer)) {
    throw VaultError.invalidInput(
      `consumer ${JSON.stringify(consumer)}: not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)`,
    );
  }
}

/** `<runtime-dir>/<consumer>`, the consumer being an agent's name that is also a safe path segment. */
export function consumerDir(runtimeDir: string, consumer: string): string {
  assertConsumerName(consumer);
  return join(runtimeDir, consumer);
}

/**
 * `<runtime-dir>/<consumer>/<socketName>` for every consumer directory under the runtime
 * directory, by name. A directory entry is a consumer: its name must be a consumer name, the
 * socket path must fit a Unix socket address and the directory must pass `assertConsumerDir` — a
 * misconfigured consumer refuses the start instead of being skipped. Other entries are ignored.
 */
export function consumerSocketPaths(runtimeDir: RuntimeDir, socketName: string): string[] {
  let entries: Dirent[];
  try {
    entries = readdirSync(runtimeDir.path, { withFileTypes: true });
  } catch {
    throw VaultError.invalidInput(
      `${runtimeDir.source}: the consumer directories cannot be listed: ${runtimeDir.path}`,
    );
  }
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
    .map((consumer) => {
      const dir = consumerDir(runtimeDir.path, consumer);
      const path = join(dir, socketName);
      const bytes = Buffer.byteLength(path);
      if (bytes > MAX_UNIX_SOCKET_PATH_BYTES) {
        throw VaultError.invalidInput(
          `consumer ${JSON.stringify(consumer)}: the socket path is ${String(bytes)} bytes, over the ${String(MAX_UNIX_SOCKET_PATH_BYTES)} a Unix socket path holds: ${path}`,
        );
      }
      assertConsumerDir(dir);
      return path;
    });
}

/** Refuses `INVALID_INPUT` unless the consumer directory is this user's own, `0750` or stricter. */
export function assertConsumerDir(path: string): void {
  assertPrivateDir(path, "consumer directory");
}

function assertPrivateDir(path: string, label: string): void {
  let stat: Stats | undefined;
  try {
    stat = statSync(path, { throwIfNoEntry: false });
  } catch {
    stat = undefined;
  }
  if (stat === undefined) throw VaultError.invalidInput(`${label}: no such directory: ${path}`);
  if (!stat.isDirectory()) throw VaultError.invalidInput(`${label}: not a directory: ${path}`);
  if (process.geteuid === undefined) {
    throw VaultError.invalidInput(
      `${label}: not supported on this platform (the owner and mode cannot be checked): ${path}`,
    );
  }
  const uid = process.geteuid();
  if (stat.uid !== uid) {
    throw VaultError.invalidInput(
      `${label}: owned by uid ${String(stat.uid)}, not by this process's uid ${String(uid)}: ${path}`,
    );
  }
  if (!isPrivateDirMode(stat.mode)) {
    const mode = (stat.mode & 0o7777).toString(8).padStart(4, "0");
    throw VaultError.invalidInput(
      `${label}: mode ${mode} is not 0750 or stricter (group-writable or world-accessible): ${path}`,
    );
  }
}
