import { statSync, type Stats } from "node:fs";
import { join } from "node:path";
import { agentNameSchema, VaultError } from "@harpoc/shared";

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

/** `<runtime-dir>/<consumer>`, the consumer being an agent's name that is also a safe path segment. */
export function consumerDir(runtimeDir: string, consumer: string): string {
  if (!agentNameSchema.safeParse(consumer).success || !CONSUMER_SEGMENT.test(consumer)) {
    throw VaultError.invalidInput(
      `consumer ${JSON.stringify(consumer)}: not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)`,
    );
  }
  return join(runtimeDir, consumer);
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
