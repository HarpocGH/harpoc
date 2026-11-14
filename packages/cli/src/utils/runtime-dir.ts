import { lstatSync, readdirSync, statSync, type Dirent, type Stats } from "node:fs";
import { basename, join, posix, sep, win32 } from "node:path";
import { listWindowsAclSync } from "@harpoc/core";
import type { WindowsAclListing } from "@harpoc/core";
import { agentNameSchema, MAX_UNIX_SOCKET_PATH_BYTES, VaultError } from "@harpoc/shared";

/** Where the runtime directory came from — the label its refusals name. */
export type RuntimeDirSource = "--runtime-dir" | "$RUNTIME_DIRECTORY" | "%ProgramData%";

export interface RuntimeDir {
  path: string;
  source: RuntimeDirSource;
}

/** A checked consumer directory; on win32 with the consumer's account SID its pipe grants. */
export interface ConsumerDirEntry {
  consumer: string;
  dir: string;
  /** win32: the local account the directory's name names, by SID. */
  sid?: string;
}

/** Group write (`0o020`) and every world bit (`0o007`): none may be set. */
const GROUP_WRITE_OR_WORLD = 0o027;

/**
 * A consumer directory's name: lowercase, so two agents differing in case
 * never share a directory on a case-insensitive filesystem, and never
 * dash-led, so no tool takes it for an option.
 */
const CONSUMER_SEGMENT = /^[a-z0-9_][a-z0-9_-]*$/;

/** Windows' reserved device names a consumer name could spell (the grammar already excludes uppercase, `.` and `$`). */
const WINDOWS_RESERVED_NAME = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/;

const SYSTEM_SID = "S-1-5-18";
const ADMINISTRATORS_SID = "S-1-5-32-544";

/** A local or domain account's SID (`S-1-5-21-<three sub-authorities>-<RID>`), never a well-known group's. */
const ACCOUNT_SID = /^S-1-5-21-\d+-\d+-\d+-\d+$/;

/**
 * What a consumer may hold on its own directory: `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE`
 * (`icacls`' `(RX)`, measured 0x001200A9), plus `GENERIC_READ` and `GENERIC_EXECUTE` (an
 * inherit-only ACE keeps generic bits). Any write, delete, `WRITE_DAC` or `WRITE_OWNER` bit refuses.
 */
export const WINDOWS_CONSUMER_DIR_RIGHTS = (0x001200a9 | 0x80000000 | 0x20000000) >>> 0;

/** The Windows default runtime directory under `%ProgramData%` (the `--ssh-agent` default on win32). */
export const WINDOWS_RUNTIME_SUBDIR = win32.join("harpoc", "run");

/** A named pipe's whole name holds at most 256 characters (Microsoft Learn, "Pipe Names"). */
const MAX_PIPE_NAME_CHARS = 256;

interface DirReader {
  name: string;
  role: "consumer" | "agent";
}

/** A runtime or consumer directory's mode: `0750` or stricter. */
export function isPrivateDirMode(mode: number): boolean {
  return (mode & GROUP_WRITE_OR_WORLD) === 0;
}

/**
 * The runtime directory: `--runtime-dir` wins, else an ambient default from the
 * environment the caller hands — systemd's `$RUNTIME_DIRECTORY` (never set on
 * Windows), else on win32 `%ProgramData%\harpoc\run`; a caller that reads no
 * ambient default hands `undefined`. An empty or flag-shaped option refuses as
 * `--vault-dir` does; a variable listing several directories (`:`-joined,
 * systemd.exec(5) `RuntimeDirectory=`) refuses, since none of them is marked as
 * the runtime directory; an unset, empty or relative `ProgramData` in a handed
 * environment refuses on win32.
 */
export function resolveRuntimeDir(
  option: string | undefined,
  env: { RUNTIME_DIRECTORY?: string; ProgramData?: string } | undefined,
  platform: NodeJS.Platform = process.platform,
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
  if (env === undefined) return undefined;
  const fromEnv = env.RUNTIME_DIRECTORY;
  if (fromEnv !== undefined && fromEnv !== "") {
    if (fromEnv.includes(":")) {
      throw VaultError.invalidInput(
        `$RUNTIME_DIRECTORY: several directories (${fromEnv}); name one with --runtime-dir`,
      );
    }
    return { path: fromEnv, source: "$RUNTIME_DIRECTORY" };
  }
  if (platform === "win32") {
    const programData = env.ProgramData;
    if (programData === undefined || programData === "" || !win32.isAbsolute(programData)) {
      throw VaultError.invalidInput(
        "%ProgramData% is not set to an absolute path; name the runtime directory with --runtime-dir",
      );
    }
    return { path: win32.join(programData, WINDOWS_RUNTIME_SUBDIR), source: "%ProgramData%" };
  }
  return undefined;
}

/** Refuses `INVALID_INPUT` unless the runtime directory is this user's own, `0750` or stricter (win32: its access list), and not a symbolic link or junction. */
export function assertRuntimeDir(dir: RuntimeDir): void {
  assertPrivateDir(dir.path, dir.source, undefined);
}

/**
 * Refuses `INVALID_INPUT` unless the consumer is an agent's name that is also a safe path segment;
 * on win32 also a reserved device name (RD-B7-5: `mkdirSync("nul")` succeeds there, and the
 * access-list read of `<runtime-dir>\nul` lists the NUL device's rules, not the directory's).
 */
export function assertConsumerName(consumer: string): void {
  if (!agentNameSchema.safeParse(consumer).success || !CONSUMER_SEGMENT.test(consumer)) {
    throw VaultError.invalidInput(
      `consumer ${JSON.stringify(consumer)}: not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)`,
    );
  }
  if (process.platform === "win32" && WINDOWS_RESERVED_NAME.test(consumer)) {
    throw VaultError.invalidInput(
      `consumer ${JSON.stringify(consumer)}: not a directory name on Windows (a reserved device name: con, prn, aux, nul, com1-com9, lpt1-lpt9)`,
    );
  }
}

/** `<runtime-dir>/<consumer>`, the consumer being an agent's name that is also a safe path segment. */
export function consumerDir(runtimeDir: string, consumer: string): string {
  assertConsumerName(consumer);
  return join(runtimeDir, consumer);
}

/**
 * The consumer's agent pipe on Windows, derived from its name alone so `server start` and
 * `ssh-agent status` agree without a file: `\\.\pipe\harpoc-<consumer>-ssh-agent`. Refuses a
 * name that is not a consumer name or whose pipe name would pass 256 characters.
 */
export function agentSocketPipeName(consumer: string): string {
  assertConsumerName(consumer);
  const name = `\\\\.\\pipe\\harpoc-${consumer}-ssh-agent`;
  if (name.length > MAX_PIPE_NAME_CHARS) {
    throw VaultError.invalidInput(
      `consumer ${JSON.stringify(consumer)}: the pipe name is ${String(name.length)} characters, over the ${String(MAX_PIPE_NAME_CHARS)} a pipe name holds: ${name}`,
    );
  }
  return name;
}

/** The consumer directories under the runtime directory, by name: every subdirectory; a link refused, other entries ignored. */
function consumerNames(runtimeDir: RuntimeDir): string[] {
  let entries: Dirent[];
  try {
    entries = readdirSync(runtimeDir.path, { withFileTypes: true });
  } catch {
    throw VaultError.invalidInput(
      `${runtimeDir.source}: the consumer directories cannot be listed: ${runtimeDir.path}`,
    );
  }
  const [link] = entries
    .filter((entry) => entry.isSymbolicLink())
    .map((entry) => entry.name)
    .sort();
  if (link !== undefined) {
    throw VaultError.invalidInput(
      `${runtimeDir.source}: the entry is a symbolic link or junction, not a consumer directory: ${join(runtimeDir.path, link)}`,
    );
  }
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
}

/**
 * Every consumer directory under the runtime directory, by name, each checked as
 * `assertConsumerDir` checks it — a misconfigured consumer refuses the start instead of being
 * skipped. On win32 each entry carries the consumer's account SID (its pipe's grant).
 */
export function consumerDirs(runtimeDir: RuntimeDir): ConsumerDirEntry[] {
  return consumerNames(runtimeDir).map((consumer) => {
    const dir = consumerDir(runtimeDir.path, consumer);
    const sid = assertPrivateDir(dir, "consumer directory", { name: consumer, role: "consumer" });
    return sid === undefined ? { consumer, dir } : { consumer, dir, sid };
  });
}

/**
 * `<runtime-dir>/<consumer>/<socketName>` for every consumer directory under the runtime
 * directory, by name (POSIX: a Unix socket each). A directory entry is a consumer: its name must
 * be a consumer name, the socket path must fit a Unix socket address and the directory must pass
 * `assertConsumerDir` — a misconfigured consumer refuses the start instead of being skipped.
 * A link entry is refused; other entries are ignored.
 */
export function consumerSocketPaths(runtimeDir: RuntimeDir, socketName: string): string[] {
  return consumerNames(runtimeDir).map((consumer) => {
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

/**
 * Refuses `INVALID_INPUT` unless the consumer directory is this user's own, `0750` or stricter,
 * and not a symbolic link or junction; on win32, unless its access list grants nobody but this
 * account, SYSTEM, Administrators and the consumer its name names (read and execute at most).
 */
export function assertConsumerDir(path: string): void {
  assertPrivateDir(path, "consumer directory", { name: basename(path), role: "consumer" });
}

/** Refuses `INVALID_INPUT` under `label` unless a token file's directory passes `assertConsumerDir`'s ladder with the spec's agent as its one other reader (win32: `windowsTokenDirAclRefusal`). */
export function assertTokenDir(dir: string, label: string, agent: string): void {
  assertPrivateDir(dir, label, { name: agent, role: "agent" });
}

function hexMask(rights: number): string {
  return `0x${rights.toString(16).toUpperCase().padStart(8, "0")}`;
}

/**
 * The win32 counterpart of the owner and mode checks, on a listing by SID: the owner is this
 * account, SYSTEM or Administrators (an elevated administrator's directory is owned by
 * Administrators); every allow rule — inherited and inherit-only ones included — names one of
 * those three or, on a consumer directory, the consumer's local account with read and execute at
 * most. Deny rules are ignored. Returns the refusal's text, or undefined.
 */
export function windowsDirAclRefusal(
  acl: WindowsAclListing,
  consumer: string | undefined,
): string | undefined {
  const verdict = judgeWindowsDirAcl(
    acl,
    consumer === undefined ? undefined : { name: consumer, role: "consumer" },
  );
  return "refusal" in verdict ? verdict.refusal : undefined;
}

/** `windowsDirAclRefusal` for a token file's directory: the agent's local account, when its name names one, is the one other reader at read and execute at most, and an agent no local account is named for leaves the directory to this account, SYSTEM and Administrators. */
export function windowsTokenDirAclRefusal(
  acl: WindowsAclListing,
  agent: string,
): string | undefined {
  const verdict = judgeWindowsDirAcl(acl, { name: agent, role: "agent" });
  return "refusal" in verdict ? verdict.refusal : undefined;
}

/** `windowsDirAclRefusal`'s judgement, carrying the consumer's SID when the listing passes. */
function judgeWindowsDirAcl(
  acl: WindowsAclListing,
  reader: DirReader | undefined,
): { refusal: string } | { sid: string | undefined } {
  const trusted = new Set([acl.user, SYSTEM_SID, ADMINISTRATORS_SID]);
  if (!trusted.has(acl.owner)) {
    return {
      refusal: `owned by ${acl.owner}, not by this process's account ${acl.user}, SYSTEM or Administrators`,
    };
  }
  let grantee: { name: string; sid: string; role: DirReader["role"] } | undefined;
  if (reader !== undefined) {
    if (acl.account === undefined || acl.account === null) {
      if (reader.role === "consumer") {
        return {
          refusal: `no local account is named ${JSON.stringify(reader.name)} (a consumer directory is named for its agent user)`,
        };
      }
    } else if (!ACCOUNT_SID.test(acl.account) || acl.accountClass !== "User") {
      return { refusal: `${JSON.stringify(reader.name)} names ${acl.account}, not a user account` };
    } else {
      grantee = { name: reader.name, sid: acl.account, role: reader.role };
    }
  }
  for (const rule of acl.rules) {
    if (!rule.allow || trusted.has(rule.sid)) continue;
    if (grantee !== undefined && rule.sid === grantee.sid) {
      if ((rule.rights & ~WINDOWS_CONSUMER_DIR_RIGHTS) !== 0) {
        return {
          refusal: `the access list grants the ${grantee.role} ${grantee.name} (${rule.sid}) ${hexMask(rule.rights)}; read and execute (0x001200A9) at most`,
        };
      }
      continue;
    }
    const others = grantee === undefined ? "" : ` and the ${grantee.role}`;
    const unnamed =
      reader !== undefined && grantee === undefined
        ? ` (no local account is named ${JSON.stringify(reader.name)})`
        : "";
    return {
      refusal: `the access list grants ${rule.sid} ${hexMask(rule.rights)}${rule.inherited ? " (inherited)" : ""}; only this process's account, SYSTEM, Administrators${others} may hold a grant${unnamed}`,
    };
  }
  return { sid: grantee?.sid };
}

/** What `isLink` hands `lstat`: walking the path's segments from the end — separators and `.` skipped, each `..` consuming the next name to its left — the path exactly as given up to and including the first name no `..` consumes, else (no such name) the path with its trailing separators dropped, never below its root. */
export function linkProbePath(
  path: string,
  flavour: typeof posix = sep === "\\" ? win32 : posix,
): string {
  const separators = flavour.sep === "\\" ? "\\/" : "/";
  const { root } = flavour.parse(path);
  let end = path.length;
  let pending = 0;
  while (end > root.length) {
    if (separators.includes(path.charAt(end - 1))) {
      end -= 1;
      continue;
    }
    let start = end;
    while (start > root.length && !separators.includes(path.charAt(start - 1))) start -= 1;
    const segment = path.slice(start, end);
    if (segment === "..") {
      pending += 1;
    } else if (segment !== ".") {
      if (pending === 0) return path.slice(0, end);
      pending -= 1;
    }
    end = start;
  }
  const trimmed = path.replace(flavour.sep === "\\" ? /[\\/]+$/ : /\/+$/, "");
  return trimmed.length < root.length ? root : trimmed;
}

/** Whether the final component of the directory the path names is a symbolic link or a junction, read by `lstat` on `linkProbePath(path)` — the tail after the last name no `..` consumes canonicalised lexically, everything up to that name left to the kernel's own resolution; false where it cannot be read. */
export function isLink(path: string): boolean {
  try {
    return lstatSync(linkProbePath(path), { throwIfNoEntry: false })?.isSymbolicLink() === true;
  } catch {
    return false;
  }
}

/** The checks; on win32 returns the consumer's SID when a consumer was named. */
function assertPrivateDir(
  path: string,
  label: string,
  reader: DirReader | undefined,
): string | undefined {
  if (isLink(path)) {
    throw VaultError.invalidInput(
      `${label}: the path is a symbolic link or junction, not a directory: ${path}`,
    );
  }
  let stat: Stats | undefined;
  try {
    stat = statSync(path, { throwIfNoEntry: false });
  } catch {
    stat = undefined;
  }
  if (stat === undefined) throw VaultError.invalidInput(`${label}: no such directory: ${path}`);
  if (!stat.isDirectory()) throw VaultError.invalidInput(`${label}: not a directory: ${path}`);
  if (process.platform === "win32") return assertWindowsDirAcl(path, label, reader);
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
  return undefined;
}

/**
 * A junction would be judged by its own owner and entries, not by its target's —
 * `GetAccessControl` reads the reparse point itself (measured) — so `assertPrivateDir` refuses a
 * link before this read; the install recipe refuses a reparse point.
 */
function assertWindowsDirAcl(
  path: string,
  label: string,
  reader: DirReader | undefined,
): string | undefined {
  let acl: WindowsAclListing;
  try {
    acl = listWindowsAclSync(path, reader === undefined ? {} : { account: reader.name });
  } catch {
    throw VaultError.invalidInput(`${label}: the access list cannot be read: ${path}`);
  }
  const verdict = judgeWindowsDirAcl(acl, reader);
  if ("refusal" in verdict) {
    throw VaultError.invalidInput(`${label}: ${verdict.refusal}: ${path}`);
  }
  return verdict.sid;
}
