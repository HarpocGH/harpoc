import { lstat, realpath, stat } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  parse,
  posix,
  relative,
  resolve,
  sep,
  win32,
} from "node:path";
import { VaultError, vaultText } from "@harpoc/shared";
import { isHeldPath } from "../session/path-trust.js";
import { hasGitDirectoryShape, holdsDotGitName } from "./local-path-git.js";

const GLOB_CHARACTERS = /[*?[]/;
const GLOB_CHARACTERS_AND_ESCAPE = /[*?[\\]/;
const WIN32_DEVICE_NAME = /^(?:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]|CONIN\$|CONOUT\$)$/i;
const WIN32_DEVICE_NAMESPACE_DRIVE = /^\\\\[?.]\\[A-Za-z]:(?:\\|$)/;
const NOT_WRITTEN_AS_STORED = /[\uFFFD\p{Cs}]/u;
const POSIX_DEVICE_ROOTS = ["/dev", "/proc", "/sys"];

/** The paths a daemon knows beside the vault's own files: under the floor whatever a policy lists. */
export interface DaemonPaths {
  protectedDirs: readonly string[];
  protectedFiles: readonly string[];
}

/**
 * Why a local path is refused: `not_absolute`, `device`, `network_share`,
 * `glob`, `win32_name`, `dot_segment`, `dot_git` and `is_directory` for a write
 * whose spelling ends in a separator before any file-system call; `protected`
 * inside the vault directory or a declared path, a path that does not resolve
 * judged through its nearest ancestor that resolves; `not_allowed` any other
 * path that does not resolve, a resolved name that is not handed on, one in no
 * listed directory, one with a `.git` name or inside a git directory, or one
 * not held; `is_directory` a write onto an existing directory inside a listed
 * directory.
 */
export type LocalPathRefusal =
  | "not_absolute"
  | "device"
  | "network_share"
  | "glob"
  | "win32_name"
  | "dot_segment"
  | "dot_git"
  | "protected"
  | "not_allowed"
  | "is_directory";

export interface LocalPathInput {
  localPath: unknown;
  access: "read" | "write";
  allowedDirs: readonly string[];
  vaultFiles: readonly string[];
  daemon?: DaemonPaths;
  refuseGlob: boolean;
  platform?: NodeJS.Platform;
  fs?: Partial<FileSystem>;
}

interface FileSystem {
  realpath: (path: string) => Promise<string>;
  lstat: (path: string) => Promise<unknown>;
  stat: (path: string) => Promise<{ isDirectory(): boolean }>;
}

interface ResolvedTarget {
  resolved: string;
  existing: boolean;
}

export function isWithin(dir: string, target: string): boolean {
  const rel = relative(dir, target);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * Whether an attachment path names a device rather than a file: on win32 the
 * `\\.\` and `\\?\` namespaces in either slash form (`\\?\UNC\` is a network
 * share); elsewhere anything under `/dev`, `/proc` or `/sys`.
 */
export function namesDevice(path: string, platform: NodeJS.Platform): boolean {
  if (platform === "win32") {
    const normalized = win32.normalize(path).toUpperCase();
    if (normalized.startsWith("\\\\?\\UNC\\")) return false;
    return normalized.startsWith("\\\\.\\") || normalized.startsWith("\\\\?\\");
  }
  const normalized = posix.normalize(path);
  return POSIX_DEVICE_ROOTS.some(
    (root) => normalized === root || normalized.startsWith(`${root}/`),
  );
}

/** Whether an attachment path names a win32 network share (`\\server\share`, `//server/share`, `\\?\UNC\`). */
export function namesNetworkShare(path: string, platform: NodeJS.Platform): boolean {
  return platform === "win32" && win32.normalize(path).startsWith("\\\\");
}

/**
 * Whether a win32 path is the device-namespace spelling of a drive letter:
 * `\\?\X:` or `\\.\X:` as `win32.normalize` spells it, at its end or before a
 * separator. Nothing else under the two namespaces is one.
 */
export function namesDeviceNamespaceDrive(path: string, platform: NodeJS.Platform): boolean {
  return platform === "win32" && WIN32_DEVICE_NAMESPACE_DRIVE.test(win32.normalize(path));
}

/**
 * On win32 the normalized spelling must lead with a drive and a separator, or
 * with two separators (a device or a network share, refused next): `C:x`, `/x`
 * and `//server`, which `win32.normalize` reads as `\server`, are not absolute.
 */
function isAbsoluteFor(path: string, platform: NodeJS.Platform): boolean {
  if (platform === "win32") return /^(?:[A-Za-z]:\\|\\\\)/.test(win32.normalize(path));
  return posix.isAbsolute(path);
}

/**
 * `sftp` globs an upload's source and unescapes a download's target, and both
 * read a backslash as the escape character. On win32 the backslash is the
 * separator, which `sftp.exe` rewrites to a forward slash before it parses.
 */
function holdsGlobCharacter(path: string, platform: NodeJS.Platform): boolean {
  return (platform === "win32" ? GLOB_CHARACTERS : GLOB_CHARACTERS_AND_ESCAPE).test(path);
}

/**
 * The Win32 file API, which `sftp.exe` calls, does not read every name as it
 * is spelled, while Node's own calls do: it drops trailing dots and spaces and
 * reads a colon as a stream. Microsoft documents a reserved name as a device
 * with or without an extension; Windows 11 build 26200 was measured to read
 * only `NUL` so, and the judgement cannot know which build reads the path.
 */
function win32Names(path: string): string[] {
  const normalized = win32.normalize(path);
  return normalized.slice(win32.parse(normalized).root.length).split("\\");
}

function namesReservedDevice(path: string, platform: NodeJS.Platform): boolean {
  return (
    platform === "win32" &&
    win32Names(path).some((name) =>
      WIN32_DEVICE_NAME.test((name.split(".")[0] as string).replace(/ +$/, "")),
    )
  );
}

export function holdsNameWin32ReadsDifferently(path: string, platform: NodeJS.Platform): boolean {
  return (
    platform === "win32" &&
    win32Names(path).some((name) => /[. ]$/.test(name) || name.includes(":"))
  );
}

export function holdsDotSegment(path: string, platform: NodeJS.Platform): boolean {
  return path.split(platform === "win32" ? /[\\/]/ : "/").includes("..");
}

function endsInSeparator(path: string, platform: NodeJS.Platform): boolean {
  return path.endsWith("/") || (platform === "win32" && path.endsWith("\\"));
}

/**
 * A name with a byte that is not UTF-8 resolves with U+FFFD in its place, and
 * an unpaired surrogate is written to the batch file as U+FFFD: either way
 * `sftp` would be handed another name than the one judged.
 */
export function holdsNameNotWrittenAsStored(path: string): boolean {
  return NOT_WRITTEN_AS_STORED.test(path);
}

function lexicalRefusal(
  path: unknown,
  platform: NodeJS.Platform,
  refuseGlob: boolean,
): LocalPathRefusal | null {
  if (typeof path !== "string" || !isAbsoluteFor(path, platform)) return "not_absolute";
  if (namesDevice(path, platform) || namesReservedDevice(path, platform)) return "device";
  if (namesNetworkShare(path, platform)) return "network_share";
  if (refuseGlob && holdsGlobCharacter(path, platform)) return "glob";
  if (holdsNameWin32ReadsDifferently(path, platform)) return "win32_name";
  return null;
}

async function realpathOrNull(path: string, fs: FileSystem): Promise<string | null> {
  try {
    return await fs.realpath(path);
  } catch {
    return null;
  }
}

function errnoCode(err: unknown): unknown {
  return (err as NodeJS.ErrnoException | null)?.code;
}

async function resolveReadSource(path: string, fs: FileSystem): Promise<ResolvedTarget | null> {
  const resolved = await realpathOrNull(path, fs);
  return resolved === null ? null : { resolved, existing: true };
}

/**
 * An entry that exists but does not resolve (a dangling or looping link) is
 * refused: `sftp` would write through it.
 */
async function resolveWriteTarget(path: string, fs: FileSystem): Promise<ResolvedTarget | null> {
  const existing = await realpathOrNull(path, fs);
  if (existing !== null) return { resolved: existing, existing: true };
  try {
    await fs.lstat(path);
    return null;
  } catch (err) {
    if (errnoCode(err) !== "ENOENT") return null;
  }
  const parent = await realpathOrNull(dirname(path), fs);
  return parent === null ? null : { resolved: join(parent, basename(path)), existing: false };
}

/**
 * The path resolved; where it does not resolve, its nearest ancestor that
 * does, resolved and joined with the rest. `missing` climbs only past a step
 * that does not exist: null where a step cannot be read, as spelled where no
 * ancestor exists. `any` climbs past every error: null where no ancestor
 * resolves.
 */
async function nearestResolvedPath(
  path: string,
  realpathOf: FileSystem["realpath"],
  climb: "missing" | "any",
): Promise<string | null> {
  const missing: string[] = [];
  for (let current = path; ; current = dirname(current)) {
    try {
      const real = await realpathOf(current);
      return missing.length === 0 ? real : join(real, ...missing);
    } catch (err) {
      if (climb === "missing" && errnoCode(err) !== "ENOENT") return null;
    }
    if (dirname(current) === current) return climb === "missing" ? path : null;
    missing.unshift(basename(current));
  }
}

function saysNotThere(err: unknown): boolean {
  const code = errnoCode(err);
  return code === "ENOENT" || code === "ENOTDIR";
}

type SpelledFileSystem = Pick<FileSystem, "realpath" | "lstat">;

async function resolveSpelledOnce(path: string, fs: SpelledFileSystem): Promise<string | null> {
  const { root } = parse(path);
  if (root === "") return null;
  const steps = path
    .slice(root.length)
    .split(sep)
    .filter((step) => step !== "");
  for (let held = steps.length; held >= 0; held--) {
    const prefix = root + steps.slice(0, held).join(sep);
    try {
      const real = await fs.realpath(prefix);
      const rest = steps.slice(held);
      return rest.includes("..") ? null : join(real, ...rest);
    } catch (err) {
      if (!saysNotThere(err)) return null;
    }
    try {
      await fs.lstat(prefix);
      return null;
    } catch (err) {
      if (!saysNotThere(err)) return null;
    }
  }
  return null;
}

/**
 * A directory that may not exist yet, resolved as the system resolves the
 * absolute spelling it is handed: links followed, every `..` up to the nearest
 * step that resolves climbing from where the path really is, the steps behind
 * that one joined on. A step is climbed past only where the system says it is
 * not there. Null where the spelling names no one directory: no step resolves;
 * a step fails to resolve for another reason — it exists all the same, a link
 * that leads nowhere, or the system refuses to read it, as it refuses a
 * spelling at its length limit, link and all —; or a `..` stands among the
 * steps behind, with no directory to climb from. The answer is resolved once
 * more and must be itself: a system's `realpath` and its kernel can read a
 * spelling differently — Darwin's takes a `..` off the name of a file, for
 * which its kernel answers that it is no directory — and the path handed on is
 * the one that both read as it stands.
 */
export async function resolveSpelledDirectory(
  path: string,
  fs: SpelledFileSystem = { realpath, lstat },
): Promise<string | null> {
  const resolved = await resolveSpelledOnce(path, fs);
  if (resolved === null) return null;
  return (await resolveSpelledOnce(resolved, fs)) === resolved ? resolved : null;
}

/** Each path through `nearestResolvedPath` past missing steps; null where one cannot be read. */
async function resolvedFloorPaths(
  paths: readonly string[],
  realpathOf: FileSystem["realpath"],
): Promise<string[] | null> {
  const resolved: string[] = [];
  for (const path of paths) {
    const real = await nearestResolvedPath(path, realpathOf, "missing");
    if (real === null) return null;
    resolved.push(real);
  }
  return resolved;
}

/**
 * The floor's paths, resolved: the directories of `vaultFiles` and the declared
 * directories, and the declared files. Null where one cannot be read.
 */
async function resolvedFloor(
  vaultFiles: readonly string[],
  daemon: DaemonPaths | undefined,
  realpathOf: FileSystem["realpath"],
): Promise<{ dirs: string[]; files: string[] } | null> {
  const dirs = await resolvedFloorPaths(
    [
      ...new Set(vaultFiles.map((file) => dirname(resolve(file)))),
      ...(daemon?.protectedDirs ?? []).map((dir) => resolve(dir)),
    ],
    realpathOf,
  );
  const files = await resolvedFloorPaths(
    (daemon?.protectedFiles ?? []).map((file) => resolve(file)),
    realpathOf,
  );
  return dirs === null || files === null ? null : { dirs, files };
}

async function isUnderFloor(
  resolved: string,
  vaultFiles: readonly string[],
  daemon: DaemonPaths | undefined,
  realpathOf: FileSystem["realpath"],
): Promise<boolean> {
  const floor = await resolvedFloor(vaultFiles, daemon, realpathOf);
  return (
    floor === null ||
    floor.dirs.some((dir) => isWithin(dir, resolved)) ||
    floor.files.some((file) => relative(file, resolved) === "")
  );
}

/**
 * Whether a resolved path is under the vault-directory floor: inside a
 * directory of `vaultFiles` or of `daemon.protectedDirs`, or one of
 * `daemon.protectedFiles`. A floor path that cannot be read holds every path.
 */
export async function isProtectedPath(
  resolved: string,
  vaultFiles: readonly string[],
  daemon?: DaemonPaths,
): Promise<boolean> {
  return isUnderFloor(resolved, vaultFiles, daemon, realpath);
}

/**
 * Whether a floor directory or a declared file, each resolved as the floor
 * resolves it, lies inside a resolved directory. A floor path that cannot be
 * read answers true.
 */
export async function holdsProtectedPath(
  resolvedDir: string,
  vaultFiles: readonly string[],
  daemon?: DaemonPaths,
): Promise<boolean> {
  const floor = await resolvedFloor(vaultFiles, daemon, realpath);
  return (
    floor === null || [...floor.dirs, ...floor.files].some((path) => isWithin(resolvedDir, path))
  );
}

async function resolvedListedDirs(
  allowedDirs: readonly string[],
  platform: NodeJS.Platform,
  refuseGlob: boolean,
  fs: FileSystem,
): Promise<string[]> {
  const resolved = await Promise.all(
    allowedDirs.map((dir) =>
      lexicalRefusal(dir, platform, refuseGlob) === null && !holdsDotGitName(dir)
        ? realpathOrNull(dir, fs)
        : Promise.resolve(null),
    ),
  );
  return resolved.filter((dir): dir is string => dir !== null);
}

export async function liesInGitDirectory(dir: string): Promise<boolean> {
  for (let current = dir; ; current = dirname(current)) {
    try {
      if (await hasGitDirectoryShape(current)) return true;
    } catch {
      return true;
    }
    if (dirname(current) === current) return false;
  }
}

async function isDirectory(path: string, fs: FileSystem): Promise<boolean | null> {
  try {
    return (await fs.stat(path)).isDirectory();
  } catch {
    return null;
  }
}

/**
 * Judges a local file the vault reads or writes for an agent against the
 * directories a policy lists, and answers the resolved path or the reason it
 * is refused. With `daemon` the floor also covers its paths and every
 * directory of the resolved path must be held (`isHeldPath`).
 */
export async function judgeLocalPath(
  input: LocalPathInput,
): Promise<{ resolved: string } | { refusal: LocalPathRefusal }> {
  const platform = input.platform ?? process.platform;
  const fs: FileSystem = {
    realpath: input.fs?.realpath ?? realpath,
    lstat: input.fs?.lstat ?? lstat,
    stat: input.fs?.stat ?? stat,
  };
  const lexical = lexicalRefusal(input.localPath, platform, input.refuseGlob);
  if (lexical !== null) return { refusal: lexical };
  const localPath = input.localPath as string;
  if (holdsDotSegment(localPath, platform)) return { refusal: "dot_segment" };
  if (holdsDotGitName(localPath)) return { refusal: "dot_git" };
  if (input.access === "write" && endsInSeparator(localPath, platform)) {
    return { refusal: "is_directory" };
  }

  const target =
    input.access === "read"
      ? await resolveReadSource(localPath, fs)
      : await resolveWriteTarget(localPath, fs);
  if (target === null) {
    const nearest = await nearestResolvedPath(localPath, fs.realpath, "any");
    return nearest !== null &&
      (await isUnderFloor(nearest, input.vaultFiles, input.daemon, fs.realpath))
      ? { refusal: "protected" }
      : { refusal: "not_allowed" };
  }
  const { resolved, existing } = target;

  if (
    namesDevice(resolved, platform) ||
    namesReservedDevice(resolved, platform) ||
    (input.refuseGlob && holdsGlobCharacter(resolved, platform)) ||
    holdsNameWin32ReadsDifferently(resolved, platform) ||
    holdsNameNotWrittenAsStored(resolved)
  ) {
    return { refusal: "not_allowed" };
  }
  if (await isUnderFloor(resolved, input.vaultFiles, input.daemon, fs.realpath)) {
    return { refusal: "protected" };
  }
  const listedDirs = await resolvedListedDirs(input.allowedDirs, platform, input.refuseGlob, fs);
  if (!listedDirs.some((dir) => relative(dir, resolved) !== "" && isWithin(dir, resolved))) {
    return { refusal: "not_allowed" };
  }
  if (holdsDotGitName(resolved) || (await liesInGitDirectory(dirname(resolved)))) {
    return { refusal: "not_allowed" };
  }

  if (input.access === "write" && existing) {
    const directory = await isDirectory(resolved, fs);
    if (directory === null) return { refusal: "not_allowed" };
    if (directory) return { refusal: "is_directory" };
  }
  if (input.daemon !== undefined && !(await isHeldPath(resolved))) {
    return { refusal: "not_allowed" };
  }
  return { resolved };
}

const SFTP_REFUSALS: Record<LocalPathRefusal, () => VaultError> = {
  not_absolute: () => VaultError.invalidInput(vaultText`sftp local path must be absolute`),
  device: () => VaultError.invalidInput(vaultText`sftp local path names a device`),
  network_share: () => VaultError.invalidInput(vaultText`sftp local path names a network share`),
  glob: () => VaultError.invalidInput(vaultText`sftp local path must not contain glob characters`),
  win32_name: () =>
    VaultError.invalidInput(vaultText`sftp local path holds a name Windows reads differently`),
  dot_segment: () => VaultError.invalidInput(vaultText`sftp local path must not hold a .. segment`),
  dot_git: () => VaultError.invalidInput(vaultText`sftp local path must not hold a .git segment`),
  protected: () => VaultError.localPathNotAllowed(),
  not_allowed: () => VaultError.localPathNotAllowed(),
  is_directory: () => VaultError.invalidInput(vaultText`sftp download path must name a file`),
};

/**
 * Judges the local file of an sftp `upload` or `download` (`judgeLocalPath`)
 * and returns the resolved path the batch command names. Past the checks of
 * the spelling every refusal carries one code and one message, so a refusal
 * never tells whether a file exists — but for one: where no earlier judgement
 * refuses it, a download onto an existing directory inside a listed directory
 * is told it names no file, as one whose spelling ends in a separator is.
 */
export async function resolveSftpLocalPath(input: {
  localPath: unknown;
  operation: "upload" | "download";
  allowedDirs: readonly string[];
  vaultFiles: readonly string[];
  daemon?: DaemonPaths;
  platform?: NodeJS.Platform;
}): Promise<string> {
  const verdict = await judgeLocalPath({
    localPath: input.localPath,
    access: input.operation === "upload" ? "read" : "write",
    allowedDirs: input.allowedDirs,
    vaultFiles: input.vaultFiles,
    daemon: input.daemon,
    refuseGlob: true,
    platform: input.platform,
  });
  if ("refusal" in verdict) throw SFTP_REFUSALS[verdict.refusal]();
  return verdict.resolved;
}
