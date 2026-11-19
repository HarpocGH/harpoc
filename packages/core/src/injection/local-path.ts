import { lstat, realpath, stat } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  posix,
  relative,
  resolve,
  sep,
  win32,
} from "node:path";
import { VaultError } from "@harpoc/shared";
import { namesDevice, namesNetworkShare } from "./smtp-injector.js";

const GLOB_CHARACTERS = /[*?[]/;
const GLOB_CHARACTERS_AND_ESCAPE = /[*?[\\]/;
const WIN32_DEVICE_NAME = /^(?:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]|CONIN\$|CONOUT\$)$/i;
const NOT_WRITTEN_AS_STORED = /[\uFFFD\p{Cs}]/u;

interface ResolvedTarget {
  resolved: string;
  existing: boolean;
}

export function isWithin(dir: string, target: string): boolean {
  const rel = relative(dir, target);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
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

function holdsNameWin32ReadsDifferently(path: string, platform: NodeJS.Platform): boolean {
  return (
    platform === "win32" &&
    win32Names(path).some((name) => /[. ]$/.test(name) || name.includes(":"))
  );
}

/**
 * A name with a byte that is not UTF-8 resolves with U+FFFD in its place, and
 * an unpaired surrogate is written to the batch file as U+FFFD: either way
 * `sftp` would be handed another name than the one judged.
 */
function holdsNameNotWrittenAsStored(path: string): boolean {
  return NOT_WRITTEN_AS_STORED.test(path);
}

function lexicalRefusal(path: unknown, platform: NodeJS.Platform): VaultError | null {
  if (typeof path !== "string" || !isAbsoluteFor(path, platform)) {
    return VaultError.invalidInput("sftp local path must be absolute");
  }
  if (namesDevice(path, platform) || namesReservedDevice(path, platform)) {
    return VaultError.invalidInput("sftp local path names a device");
  }
  if (namesNetworkShare(path, platform)) {
    return VaultError.invalidInput("sftp local path names a network share");
  }
  if (holdsGlobCharacter(path, platform)) {
    return VaultError.invalidInput("sftp local path must not contain glob characters");
  }
  if (holdsNameWin32ReadsDifferently(path, platform)) {
    return VaultError.invalidInput("sftp local path holds a name Windows reads differently");
  }
  return null;
}

async function realpathOrNull(path: string): Promise<string | null> {
  try {
    return await realpath(path);
  } catch {
    return null;
  }
}

function errnoCode(err: unknown): unknown {
  return (err as NodeJS.ErrnoException | null)?.code;
}

async function resolveUploadSource(path: string): Promise<ResolvedTarget | null> {
  const resolved = await realpathOrNull(path);
  return resolved === null ? null : { resolved, existing: true };
}

/**
 * An entry that exists but does not resolve (a dangling or looping link) is
 * refused: `sftp` would write through it.
 */
async function resolveDownloadTarget(path: string): Promise<ResolvedTarget | null> {
  const existing = await realpathOrNull(path);
  if (existing !== null) return { resolved: existing, existing: true };
  try {
    await lstat(path);
    return null;
  } catch (err) {
    if (errnoCode(err) !== "ENOENT") return null;
  }
  const parent = await realpathOrNull(dirname(path));
  return parent === null ? null : { resolved: join(parent, basename(path)), existing: false };
}

async function resolvedVaultDirs(vaultFiles: readonly string[]): Promise<string[] | null> {
  const resolved: string[] = [];
  for (const dir of new Set(vaultFiles.map((file) => dirname(resolve(file))))) {
    try {
      resolved.push(await realpath(dir));
    } catch (err) {
      if (errnoCode(err) !== "ENOENT") return null;
      resolved.push(dir);
    }
  }
  return resolved;
}

async function resolvedListedDirs(
  allowedDirs: readonly string[],
  platform: NodeJS.Platform,
): Promise<string[]> {
  const resolved = await Promise.all(
    allowedDirs.map((dir) =>
      lexicalRefusal(dir, platform) === null ? realpathOrNull(dir) : Promise.resolve(null),
    ),
  );
  return resolved.filter((dir): dir is string => dir !== null);
}

async function isDirectory(path: string): Promise<boolean | null> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return null;
  }
}

/**
 * Judges the local file of an sftp `upload` or `download` against the
 * directories the secret's policy lists and returns the resolved path the
 * batch command names. Past the lexical checks every refusal carries one code
 * and one message, so a refusal never tells whether a file exists; a download
 * onto a directory is told so only inside a listed directory.
 */
export async function resolveSftpLocalPath(input: {
  localPath: unknown;
  operation: "upload" | "download";
  allowedDirs: readonly string[];
  vaultFiles: readonly string[];
  platform?: NodeJS.Platform;
}): Promise<string> {
  const platform = input.platform ?? process.platform;
  const refusal = lexicalRefusal(input.localPath, platform);
  if (refusal !== null) throw refusal;
  const localPath = input.localPath as string;

  const target =
    input.operation === "upload"
      ? await resolveUploadSource(localPath)
      : await resolveDownloadTarget(localPath);
  if (target === null) throw VaultError.localPathNotAllowed();
  const { resolved, existing } = target;

  if (
    namesDevice(resolved, platform) ||
    namesReservedDevice(resolved, platform) ||
    holdsGlobCharacter(resolved, platform) ||
    holdsNameWin32ReadsDifferently(resolved, platform) ||
    holdsNameNotWrittenAsStored(resolved)
  ) {
    throw VaultError.localPathNotAllowed();
  }
  const vaultDirs = await resolvedVaultDirs(input.vaultFiles);
  if (vaultDirs === null || vaultDirs.some((dir) => isWithin(dir, resolved))) {
    throw VaultError.localPathNotAllowed();
  }
  const listedDirs = await resolvedListedDirs(input.allowedDirs, platform);
  if (!listedDirs.some((dir) => relative(dir, resolved) !== "" && isWithin(dir, resolved))) {
    throw VaultError.localPathNotAllowed();
  }

  if (input.operation === "download" && existing) {
    const directory = await isDirectory(resolved);
    if (directory === null) throw VaultError.localPathNotAllowed();
    if (directory) throw VaultError.invalidInput("sftp download path must name a file");
  }
  return resolved;
}
