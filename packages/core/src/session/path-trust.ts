import { lstatSync, realpathSync, statSync, type Stats } from "node:fs";
import { lstat } from "node:fs/promises";
import { dirname, isAbsolute, join, posix, sep, win32 } from "node:path";
import { VaultError } from "@harpoc/shared";
import {
  ADMINISTRATORS_SID,
  SYSTEM_SID,
  TRUSTED_INSTALLER_SID,
  foreignToVaultAccounts,
  listWindowsAclChain,
  listWindowsAclSync,
} from "./owner-only.js";
import type { WindowsAclListing } from "./owner-only.js";

/** Who besides this process's account may own a held win32 directory or hold any grant on it. */
export const WIN32_TRUSTED_SIDS: readonly string[] = [
  SYSTEM_SID,
  ADMINISTRATORS_SID,
  TRUSTED_INSTALLER_SID,
];

/** Generic all, write owner, write DAC, delete, delete child: a grant that can replace a directory's entry. */
export const WIN32_REPLACE_RIGHTS = 0x100d0040;

/** `WIN32_REPLACE_RIGHTS`, generic write, write attributes (it turns an empty directory into a junction), add file and add subdirectory: what the file's own parent grants nobody else. */
export const WIN32_PARENT_RIGHTS = 0x500d0146;

const OWNER_ONLY_MASK = 0o077;
const GROUP_WRITE = 0o020;
const WORLD_WRITE = 0o002;
const STICKY = 0o1000;
const INHERIT_ONLY = 2;
const WIN32_TRIMMED_NAME = /[. ][\\/]*$/;

/** The path up to its last name that no `..` consumes, separators and `.` skipped; else the path without trailing separators, never below its root. */
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

/** Whether the directory the path names is a symbolic link or junction (`lstat` on `linkProbePath`); false where it cannot be read. */
export function isLinkPath(path: string): boolean {
  try {
    return lstatSync(linkProbePath(path), { throwIfNoEntry: false })?.isSymbolicLink() === true;
  } catch {
    return false;
  }
}

function hexMask(rights: number): string {
  return `0x${(rights >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}

/**
 * Refuses `INVALID_INPUT` unless the path is a directory and no symbolic link
 * or junction; answers its `stat`. It reads no owner, mode or access list.
 */
export function assertUnlinkedDir(path: string, label: string): Stats {
  if (isLinkPath(path)) {
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
  return stat;
}

/**
 * Refuses `INVALID_INPUT` unless the path is a directory, no symbolic link or
 * junction (`assertUnlinkedDir`), that is this process's own and closed to
 * everyone else: off win32 owned by the effective uid with
 * `(mode & 0o077) === 0`; on win32 owned by this account, SYSTEM or
 * Administrators with no allow entry, inherited and inherit-only ones
 * included, for anyone else.
 */
export function assertOwnerOnlyDir(path: string, label: string): void {
  const stat = assertUnlinkedDir(path, label);
  if (process.platform === "win32") {
    assertOwnerOnlyAcl(path, label);
    return;
  }
  const euid = process.geteuid?.();
  if (euid === undefined) {
    throw VaultError.invalidInput(
      `${label}: not supported on this platform (the owner and mode cannot be checked): ${path}`,
    );
  }
  if (stat.uid !== euid) {
    throw VaultError.invalidInput(
      `${label}: owned by uid ${String(stat.uid)}, not by this process's uid ${String(euid)}: ${path}`,
    );
  }
  if ((stat.mode & OWNER_ONLY_MASK) !== 0) {
    const mode = (stat.mode & 0o7777).toString(8).padStart(4, "0");
    throw VaultError.invalidInput(
      `${label}: mode ${mode} is not 0700 (group- or world-accessible): ${path}`,
    );
  }
}

function assertOwnerOnlyAcl(path: string, label: string): void {
  let acl: WindowsAclListing;
  try {
    acl = listWindowsAclSync(path);
  } catch {
    throw VaultError.invalidInput(`${label}: the access list cannot be read: ${path}`);
  }
  const foreign = foreignToVaultAccounts(acl);
  if (foreign === undefined) return;
  if ("owner" in foreign) {
    throw VaultError.invalidInput(
      `${label}: owned by ${foreign.owner}, not by this process's account ${acl.user}, SYSTEM or Administrators: ${path}`,
    );
  }
  throw VaultError.invalidInput(
    `${label}: the access list grants ${foreign.grant.sid} ${hexMask(foreign.grant.rights)}; only this process's account, SYSTEM and Administrators may hold a grant: ${path}`,
  );
}

/**
 * Whether an account other than the owner may write the entry: a write bit for
 * others, or one for the group unless the entry is of `ownGroup`, the group for
 * which the group's write bit passes. Without `ownGroup` any write bit but the
 * owner's counts; no caller but the git context passes one.
 */
export function othersMayWrite(entry: { mode: number; gid?: number }, ownGroup?: number): boolean {
  if ((entry.mode & WORLD_WRITE) !== 0) return true;
  return (entry.mode & GROUP_WRITE) !== 0 && (ownGroup === undefined || entry.gid !== ownGroup);
}

/**
 * Every directory of the chain, root first and the file's parent last, is
 * owned by `euid` or root and no other account may write it (`othersMayWrite`;
 * `ownGroup` is the group for which the group's write bit passes, and no
 * caller but the git context passes one), or is root's sticky directory that
 * is not the parent and whose next entry is `euid`'s or root's.
 */
export function posixHeld(
  chain: readonly { uid: number; mode: number; gid?: number }[],
  euid: number,
  ownGroup?: number,
): boolean {
  const trusted = (uid: number): boolean => uid === euid || uid === 0;
  return (
    chain.length > 0 &&
    chain.every((dir, index) => {
      if (trusted(dir.uid) && !othersMayWrite(dir, ownGroup)) return true;
      const next = chain[index + 1];
      return dir.uid === 0 && (dir.mode & STICKY) !== 0 && next !== undefined && trusted(next.uid);
    })
  );
}

/**
 * Every directory of the chain, root first and the file's parent last, is
 * owned by this process's account or a `WIN32_TRUSTED_SIDS` member, and no
 * other principal's allow entry, inherit-only ones aside, holds a bit of
 * `WIN32_REPLACE_RIGHTS`, or on the parent of `WIN32_PARENT_RIGHTS`.
 */
export function win32Held(chain: readonly WindowsAclListing[]): boolean {
  return (
    chain.length > 0 &&
    chain.every((acl, index) => {
      const trusted = new Set([acl.user, ...WIN32_TRUSTED_SIDS]);
      if (!trusted.has(acl.owner)) return false;
      const rights = index === chain.length - 1 ? WIN32_PARENT_RIGHTS : WIN32_REPLACE_RIGHTS;
      return acl.rules.every(
        (rule) =>
          !rule.allow ||
          rule.propagation === INHERIT_ONLY ||
          trusted.has(rule.sid) ||
          (rule.rights & rights) === 0,
      );
    })
  );
}

function directoryChain(dir: string): string[] {
  const chain = [dir];
  for (let parent = dirname(dir); parent !== chain[0]; parent = dirname(parent)) {
    chain.unshift(parent);
  }
  return chain;
}

/**
 * Whether every directory of `dirname(resolvedFile)`, from the root down, is
 * held (`posixHeld`, `win32Held`); the file itself need not exist. False for a
 * relative path, a link or non-directory on the chain, a chain that cannot be
 * read, and on win32 a directory name that ends in a dot or a space: the
 * access listing reads such a name without it, another directory than `lstat`.
 * Off win32 `ownGroup` is the group for which the group's write bit passes; no
 * caller but the git context passes one, and the win32 walk ignores it.
 */
export async function isHeldPath(resolvedFile: string, ownGroup?: number): Promise<boolean> {
  if (!isAbsolute(resolvedFile)) return false;
  const dirs = directoryChain(dirname(resolvedFile));
  if (process.platform === "win32" && dirs.some((dir) => WIN32_TRIMMED_NAME.test(dir))) {
    return false;
  }
  try {
    const stats = await Promise.all(dirs.map((dir) => lstat(dir)));
    if (stats.some((stat) => stat.isSymbolicLink() || !stat.isDirectory())) return false;
    if (process.platform === "win32") return win32Held(await listWindowsAclChain(dirs));
    const euid = process.geteuid?.();
    return euid !== undefined && posixHeld(stats, euid, ownGroup);
  } catch {
    return false;
  }
}

/**
 * Refuses `INVALID_INPUT` naming the path unless the directory it names,
 * resolved through links, is held from the root down (`isHeldPath` on a name
 * inside it); a path that does not resolve is refused the same way. Answers
 * the resolved directory, the one to write into.
 */
export async function assertHeldDir(path: string, label: string): Promise<string> {
  let real: string | undefined;
  try {
    real = realpathSync(path);
  } catch {
    real = undefined;
  }
  if (real === undefined || !(await isHeldPath(join(real, "harpoc-held-probe")))) {
    throw VaultError.invalidInput(
      `${label}: a directory on its path can be changed by another account: ${path}`,
    );
  }
  return real;
}
