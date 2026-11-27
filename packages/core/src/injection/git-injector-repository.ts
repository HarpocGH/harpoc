import { isUtf8 } from "node:buffer";
import { constants } from "node:fs";
import type { Stats } from "node:fs";
import { lstat, open, realpath, stat } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname, isAbsolute, join, sep } from "node:path";
import { VaultError, vaultText } from "@harpoc/shared";
import { isHeldPath, othersMayWrite } from "../session/path-trust.js";
import { gitDirectoryShape, hasGitDirectoryShape } from "./local-path-git.js";
import { holdsNameNotWrittenAsStored, holdsNameWin32ReadsDifferently } from "./local-path.js";

/**
 * The repository the vault serves: `top` holds the `.git` entry `entry`, which
 * names the git directory `gitDir`; `commonDir` is the directory its
 * `commondir` file names, or null where it holds none. `top`, `gitDir` and
 * `commonDir` are resolved; `entry` is `top`'s `.git` itself, a link where it
 * is one.
 */
export interface ServedRepository {
  top: string;
  entry: string;
  gitDir: string;
  commonDir: string | null;
}

export const NOT_A_SERVED_REPOSITORY = vaultText`working_directory is not in a repository the vault serves`;

const REPOSITORY_OF_ANOTHER_ACCOUNT = vaultText`working_directory's repository belongs to another account`;
const REPOSITORY_CHANGEABLE = vaultText`working_directory's repository can be changed by another account`;

const MAX_GIT_FILE_BYTES = 1_048_576;
const GITFILE_PREFIX = "gitdir: ";

function isSeparator(char: string, platform: NodeJS.Platform): boolean {
  return char === "/" || (platform === "win32" && char === "\\");
}

function isGitSpace(char: string): boolean {
  return char === " " || char === "\t" || char === "\n" || char === "\r";
}

/**
 * The directory `git clone` derives from a repository address when it is handed
 * none, read as git reads the address the caller spelled (`guess_dir_name` in
 * `builtin/clone.c` at v2.32.0, `git_url_basename` in `dir.c` at v2.56.1, the
 * same algorithm); null where git derives no name, and where
 * it derives `.` or `..`, which would clone into the vault process's own
 * directory or the one above it.
 */
export function derivedCloneDirectory(
  repository: string,
  platform: NodeJS.Platform,
): string | null {
  const scheme = repository.indexOf("://");
  let start = scheme < 0 ? 0 : scheme + 3;
  let end = repository.length;
  for (let i = start; i < end && !isSeparator(repository.charAt(i), platform); i++) {
    if (repository.charAt(i) === "@") start = i + 1;
  }
  while (
    start < end &&
    (isSeparator(repository.charAt(end - 1), platform) || isGitSpace(repository.charAt(end - 1)))
  ) {
    end--;
  }
  if (
    end - start > 5 &&
    isSeparator(repository.charAt(end - 5), platform) &&
    repository.slice(end - 4, end) === ".git"
  ) {
    end -= 5;
    while (start < end && isSeparator(repository.charAt(end - 1), platform)) end--;
  }
  const remaining = repository.slice(start, end);
  if (!remaining.includes("/") && remaining.includes(":")) {
    let digits = end;
    while (start < digits && /[0-9]/.test(repository.charAt(digits - 1))) digits--;
    if (start < digits && repository.charAt(digits - 1) === ":") end = digits - 1;
  }
  let last = end;
  while (
    start < last &&
    !isSeparator(repository.charAt(last - 1), platform) &&
    repository.charAt(last - 1) !== ":"
  ) {
    last--;
  }
  let name = repository.slice(last, end);
  if (name.endsWith(".git")) name = name.slice(0, -4);
  if (name === "" || name === "/") return null;
  let collapsed = "";
  let afterSpace = true;
  for (let i = 0; i < name.length; i++) {
    const char = name.charCodeAt(i) < 0x20 ? " " : name.charAt(i);
    if (isGitSpace(char)) {
      if (afterSpace) continue;
      afterSpace = true;
    } else {
      afterSpace = false;
    }
    collapsed += char;
  }
  if (afterSpace) collapsed = collapsed.slice(0, -1);
  return collapsed === "" || collapsed === "." || collapsed === ".." ? null : collapsed;
}

function withoutTrailingLineBreaks(content: Buffer): Buffer {
  let end = content.length;
  while (end > 0 && (content[end - 1] === 0x0a || content[end - 1] === 0x0d)) end--;
  return content.subarray(0, end);
}

/**
 * The path a gitfile names, read as git reads it (`read_gitfile_gently` in
 * `setup.c`) or more strictly: the bytes `gitdir: `, then, every trailing line
 * feed and carriage return cut, a valid UTF-8 path without NUL, line feed or
 * carriage return that neither begins nor ends with a space or a tab and, on
 * win32, is not drive-relative; null for anything else.
 */
export function gitfilePath(content: Buffer, platform: NodeJS.Platform): string | null {
  const prefix = Buffer.from(GITFILE_PREFIX);
  if (!content.subarray(0, prefix.length).equals(prefix)) return null;
  const rest = withoutTrailingLineBreaks(content.subarray(prefix.length));
  if (rest.length === 0 || !isUtf8(rest)) return null;
  const path = rest.toString("utf8");
  if (path.includes("\0") || path.includes("\n") || path.includes("\r")) return null;
  if (/^[ \t]|[ \t]$/.test(path)) return null;
  if (platform === "win32" && /^[A-Za-z]:(?![\\/])/.test(path)) return null;
  return path;
}

function notServed(): VaultError {
  return VaultError.invalidGitConfig(NOT_A_SERVED_REPOSITORY);
}

async function entryThere(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code !== "ENOENT" && code !== "ENOTDIR";
  }
}

async function answersNoEntry(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return false;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "ENOENT";
  }
}

/**
 * The first directory from `resolvedDir` upwards that holds a `.git` entry;
 * none met before it may have a git directory's shape.
 */
async function topOf(resolvedDir: string): Promise<string> {
  for (let dir = resolvedDir; ; dir = dirname(dir)) {
    if (await entryThere(join(dir, ".git"))) return dir;
    if (await hasGitDirectoryShape(dir)) throw notServed();
    if (dirname(dir) === dir) throw notServed();
  }
}

/**
 * A regular file of at most `MAX_GIT_FILE_BYTES`, judged on `found` before it
 * is opened and again on the handle it is read through: an entry exchanged
 * since the `stat` is never waited on (`O_NONBLOCK`) nor read past its bound.
 */
async function smallRegularFile(path: string, found: Stats): Promise<Buffer> {
  if (!found.isFile() || found.size > MAX_GIT_FILE_BYTES) throw notServed();
  const handle = await open(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size > MAX_GIT_FILE_BYTES) throw notServed();
    const content = Buffer.alloc(opened.size + 1);
    let length = 0;
    while (length < content.length) {
      const { bytesRead } = await handle.read(content, length, content.length - length, null);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length > opened.size) throw notServed();
    return content.subarray(0, length);
  } finally {
    await handle.close();
  }
}

/**
 * A path a gitfile or a `commondir` file names, taken relative to `base` as
 * git takes it: off win32 joined by text, a `..` left to the system.
 */
function relativeTo(base: string, path: string): string {
  if (isAbsolute(path)) return path;
  if (process.platform === "win32") return join(base, path);
  return base.endsWith(sep) ? `${base}${path}` : `${base}${sep}${path}`;
}

function readsAsAnother(path: string): boolean {
  return (
    holdsNameWin32ReadsDifferently(path, process.platform) || holdsNameNotWrittenAsStored(path)
  );
}

async function commonDirectory(gitDir: string): Promise<string | null> {
  const file = join(gitDir, "commondir");
  try {
    await lstat(file);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  const rest = withoutTrailingLineBreaks(await smallRegularFile(file, await stat(file)));
  if (rest.length === 0 || !isUtf8(rest)) throw notServed();
  const path = rest.toString("utf8");
  if (path.includes("\0")) throw notServed();
  return realpath(relativeTo(gitDir, path));
}

async function servedRepository(resolvedDir: string): Promise<ServedRepository> {
  const top = await topOf(resolvedDir);
  const entry = join(top, ".git");
  const found = await stat(entry);
  let named = entry;
  if (!found.isDirectory()) {
    const path = gitfilePath(await smallRegularFile(entry, found), process.platform);
    if (path === null) throw notServed();
    named = relativeTo(top, path);
  }
  if (readsAsAnother(named)) throw notServed();
  const gitDir = await realpath(named);
  if (readsAsAnother(gitDir)) throw notServed();
  if ((await gitDirectoryShape(gitDir)) !== "shape") throw notServed();
  if (!(await answersNoEntry(join(gitDir, ".git")))) throw notServed();
  return { top, entry, gitDir, commonDir: await commonDirectory(gitDir) };
}

/**
 * The repository a resolved directory lies in, found by the vault and not by
 * git (A2, A3): the first directory upwards with a `.git` entry is its top, a
 * directory with a git directory's shape met before it refuses, and the git
 * directory the entry names must have that shape and hold no `.git` entry of
 * its own, so a work tree named `.git` is never served. Every failure is the
 * one refusal, which names no path.
 */
export async function findServedRepository(resolvedDir: string): Promise<ServedRepository> {
  try {
    return await servedRepository(resolvedDir);
  } catch {
    throw notServed();
  }
}

function ofAnotherAccount(): VaultError {
  return VaultError.invalidGitConfig(REPOSITORY_OF_ANOTHER_ACCOUNT);
}

function changeable(): VaultError {
  return VaultError.invalidGitConfig(REPOSITORY_CHANGEABLE);
}

/** `os.userInfo().gid`; undefined where it throws or is negative. */
function ownPrimaryGroup(): number | undefined {
  try {
    const { gid } = userInfo();
    return gid >= 0 ? gid : undefined;
  } catch {
    return undefined;
  }
}

/** The paths A5 judges, in their order; an optional one may be absent. */
function judgedPaths(repo: ServedRepository): { path: string; optional: boolean }[] {
  return [
    { path: repo.top, optional: false },
    { path: repo.entry, optional: false },
    { path: repo.gitDir, optional: false },
    { path: join(repo.gitDir, "config"), optional: true },
    { path: join(repo.gitDir, "config.worktree"), optional: true },
    { path: join(repo.gitDir, "commondir"), optional: true },
    ...(repo.commonDir === null
      ? []
      : [
          { path: repo.commonDir, optional: false },
          { path: join(repo.commonDir, "config"), optional: true },
        ]),
  ];
}

/**
 * The reading of `path` whose bits are judged, once its owner is `euid`: the
 * `lstat` one, or for a link the `stat` one, the link's own owner judged too.
 * Null for an optional path that is not there.
 */
async function ownReading(path: string, optional: boolean, euid: number): Promise<Stats | null> {
  let found: Stats;
  try {
    found = await lstat(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (optional && (code === "ENOENT" || code === "ENOTDIR")) return null;
    throw ofAnotherAccount();
  }
  if (found.uid !== euid) throw ofAnotherAccount();
  if (!found.isSymbolicLink()) return found;
  let target: Stats;
  try {
    target = await stat(path);
  } catch {
    throw ofAnotherAccount();
  }
  if (target.uid !== euid) throw ofAnotherAccount();
  return target;
}

/**
 * A5: off win32 the repository belongs to the effective user — `top`, its
 * `.git` entry, the git directory, its `config`, `config.worktree` and
 * `commondir`, and the common directory with its `config`, a link read itself
 * and where it leads. In a daemon no other account may write one of them (a
 * group's write bit passes for the account's own primary group alone), and
 * the directories above the entry, the git directory's `config` and the
 * common directory's `config` are held (`isHeldPath`). Every owner is judged
 * before any bit; the refusals name no path.
 */
export async function assertRepositoryOwned(
  repo: ServedRepository,
  daemon: boolean,
): Promise<void> {
  if (process.platform === "win32") return;
  const euid = process.geteuid?.();
  if (euid === undefined) throw ofAnotherAccount();
  const readings: Stats[] = [];
  for (const { path, optional } of judgedPaths(repo)) {
    const reading = await ownReading(path, optional, euid);
    if (reading !== null) readings.push(reading);
  }
  if (!daemon) return;
  const ownGroup = ownPrimaryGroup();
  if (readings.some((reading) => othersMayWrite(reading, ownGroup))) throw changeable();
  const walked = [
    repo.entry,
    join(repo.gitDir, "config"),
    ...(repo.commonDir === null ? [] : [join(repo.commonDir, "config")]),
  ];
  for (const path of walked) {
    if (!(await isHeldPath(path, ownGroup))) throw changeable();
  }
}
