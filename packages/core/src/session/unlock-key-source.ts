import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import type { Stats } from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";
import { AES_KEY_LENGTH, ErrorCode, VaultError } from "@harpoc/shared";
import type { UnlockKeySourceUnsafeReason } from "@harpoc/shared";
import { wipeBuffer } from "../crypto/random.js";
import { listWindowsAcl, restrictWindowsAclToOwner } from "./owner-only.js";
import type { WindowsAcl } from "./owner-only.js";

/** Why a source is refused before a byte of it is read, and what was seen (never the key). */
export type UnlockKeySourceVerdict =
  { reason: UnlockKeySourceUnsafeReason; observed?: string } | undefined;

export interface ReadUnlockKeyFileOptions {
  /**
   * Advice that is not a refusal — on Linux, a key file on a filesystem whose
   * modes come from its mount options (B4-U1). Default: silent — core never
   * logs; the CLI prints it.
   */
  onWarning?: (warning: string) => void;
}

/** Group or world bits (`0o077`): `--unlock-key-file` allows neither. */
const GROUP_OR_WORLD = 0o077;
/** Group write and every world bit (`0o027`): a credential file allows neither. */
const GROUP_WRITE_OR_WORLD = 0o027;
const SYSTEM_SID = "S-1-5-18";
const ADMINISTRATORS_SID = "S-1-5-32-544";

/**
 * A credential name the reader accepts: a subset of systemd's
 * `credential_name_valid` (printable ASCII without `/` or `:`, not `.` or `..`,
 * at most 255) that is also a Windows file name and never dash-led.
 */
const CREDENTIAL_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$/;

/**
 * Filesystems whose modes are synthesized from mount options or a server's
 * policy rather than stored per file: FAT, exFAT, NTFS (ntfs3, ntfs-3g through
 * fuseblk), SMB, 9p (WSL 2's drvfs), WSL 1's drvfs, VirtualBox shared folders,
 * optical media.
 */
const MODE_SYNTHESIZING_FILESYSTEMS: ReadonlySet<string> = new Set([
  "vfat",
  "msdos",
  "exfat",
  "ntfs3",
  "fuseblk",
  "cifs",
  "smb3",
  "9p",
  "drvfs",
  "vboxsf",
  "iso9660",
  "udf",
]);

function octalMode(mode: number): string {
  return (mode & 0o7777).toString(8).padStart(4, "0");
}

/** `--unlock-key-file` on POSIX: this user's own file, nothing for group or others (`0600` or stricter). */
export function keyFileModeVerdict(
  stat: { uid: number; mode: number },
  euid: number,
): UnlockKeySourceVerdict {
  if (stat.uid !== euid) {
    return { reason: "owner", observed: `uid ${stat.uid}; this process runs as uid ${euid}` };
  }
  if ((stat.mode & GROUP_OR_WORLD) !== 0) {
    return { reason: "mode", observed: `mode ${octalMode(stat.mode)}` };
  }
  return undefined;
}

/**
 * A systemd credential on POSIX: owned by this user or root, no group write and
 * nothing for others. systemd writes a credential `0400` and grants a unit
 * running under another user a read ACL entry, which `stat` shows as `0440`
 * (the ACL mask in the group bits) on root's file; on a filesystem without ACLs
 * it gives the file to the unit's user instead (`exec-credential.c`
 * `write_credential`).
 */
export function credentialModeVerdict(
  stat: { uid: number; mode: number },
  euid: number,
): UnlockKeySourceVerdict {
  if (stat.uid !== euid && stat.uid !== 0) {
    return { reason: "owner", observed: `uid ${stat.uid}; this process runs as uid ${euid}` };
  }
  if ((stat.mode & GROUP_WRITE_OR_WORLD) !== 0) {
    return { reason: "mode", observed: `mode ${octalMode(stat.mode)}` };
  }
  return undefined;
}

/**
 * The win32 counterpart of the owner and mode checks: owned by this user,
 * SYSTEM or Administrators, and no allow rule for any other account — what
 * `restrictWindowsAclToOwner` leaves, and what a file under the user's profile
 * inherits.
 */
export function windowsAclVerdict(acl: WindowsAcl): UnlockKeySourceVerdict {
  const trusted = new Set([acl.user, SYSTEM_SID, ADMINISTRATORS_SID]);
  if (!trusted.has(acl.owner)) return { reason: "owner", observed: `owner ${acl.owner}` };
  const foreign = acl.rules.find((rule) => rule.allow && !trusted.has(rule.sid));
  if (foreign) return { reason: "acl", observed: foreign.sid };
  return undefined;
}

function unescapeMountField(field: string): string {
  return field.replace(/\\([0-7]{3})/g, (_, octal: string) =>
    String.fromCharCode(Number.parseInt(octal, 8)),
  );
}

function isUnderMountPoint(path: string, point: string): boolean {
  if (point === "/" || path === point) return true;
  return path.startsWith(point.endsWith("/") ? point : `${point}/`);
}

/**
 * The filesystem type of the mount holding `path` (absolute, its directory's
 * symlinks resolved), from `/proc/self/mountinfo` text (proc_pid_mountinfo(5)):
 * the entry whose mount point is the longest prefix of the path — the last one
 * listed when several share it, a later mount covering an earlier.
 */
export function mountFilesystemType(mountinfo: string, path: string): string | undefined {
  let best: { point: string; type: string } | undefined;
  for (const line of mountinfo.split("\n")) {
    const fields = line.split(" ");
    const separator = fields.indexOf("-", 6);
    const rawPoint = fields[4];
    const rawType = fields[separator + 1];
    if (separator < 0 || rawPoint === undefined || rawType === undefined) continue;
    const point = unescapeMountField(rawPoint);
    if (!isUnderMountPoint(path, point)) continue;
    if (best === undefined || point.length >= best.point.length) {
      best = { point, type: unescapeMountField(rawType) };
    }
  }
  return best?.type;
}

/**
 * B4-U1's warning for `path` (resolved) against `mountinfo`, naming `shown` — the path as
 * the operator gave it — or undefined where the filesystem stores modes per file.
 */
export function mountWarningFor(
  mountinfo: string,
  path: string,
  shown: string = path,
): string | undefined {
  const type = mountFilesystemType(mountinfo, path);
  if (type === undefined) return undefined;
  const dot = type.indexOf(".");
  if (!MODE_SYNTHESIZING_FILESYSTEMS.has(dot < 0 ? type : type.slice(0, dot))) return undefined;
  return `${shown} is on a ${type} filesystem — its modes are the mount's options, not the file's`;
}

function linuxMountWarning(path: string): string | undefined {
  if (process.platform !== "linux") return undefined;
  try {
    const resolved = join(realpathSync(dirname(path)), basename(path));
    return mountWarningFor(readFileSync("/proc/self/mountinfo", "utf8"), resolved, path);
  } catch {
    return undefined;
  }
}

async function win32Verdict(path: string): Promise<UnlockKeySourceVerdict> {
  let acl: WindowsAcl;
  try {
    acl = await listWindowsAcl(path);
  } catch {
    return { reason: "acl_unverified" };
  }
  return windowsAclVerdict(acl);
}

function posixVerdict(stat: Stats, kind: "key-file" | "credential"): UnlockKeySourceVerdict {
  const euid = (process.geteuid as () => number)();
  return kind === "key-file" ? keyFileModeVerdict(stat, euid) : credentialModeVerdict(stat, euid);
}

/**
 * The ladder both readers share: `lstat` (a symlink refused, anything but a
 * regular file refused), one descriptor opened without following a symlink
 * and without blocking on a FIFO, the owner and mode (POSIX) or the access
 * list (win32) checked, a key file's mount warning issued, then exactly
 * `AES_KEY_LENGTH` bytes read. Nothing is read before every check has passed;
 * the returned buffer is fresh, never a view of a pooled one, and the caller
 * wipes it.
 */
async function readKeySource(
  path: string,
  label: string,
  kind: "key-file" | "credential",
  onWarning?: (warning: string) => void,
): Promise<Uint8Array> {
  let link: Stats;
  try {
    link = lstatSync(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") {
      throw VaultError.invalidInput(`${label}: no such file: ${path}`);
    }
    throw VaultError.invalidInput(`${label}: not a readable file: ${path}`);
  }
  if (link.isSymbolicLink()) throw VaultError.unlockKeySourceUnsafe(path, "symlink");
  if (!link.isFile()) throw VaultError.invalidInput(`${label}: not a readable file: ${path}`);

  let fd: number;
  try {
    fd = openSync(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ELOOP") {
      throw VaultError.unlockKeySourceUnsafe(path, "symlink");
    }
    throw VaultError.invalidInput(`${label}: not a readable file: ${path}`);
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw VaultError.invalidInput(`${label}: not a readable file: ${path}`);
    const verdict =
      process.platform === "win32" ? await win32Verdict(path) : posixVerdict(stat, kind);
    if (verdict) throw VaultError.unlockKeySourceUnsafe(path, verdict.reason, verdict.observed);
    if (kind === "key-file" && onWarning !== undefined) {
      const warning = linuxMountWarning(path);
      if (warning !== undefined) onWarning(warning);
    }
    if (stat.size !== AES_KEY_LENGTH) {
      throw VaultError.invalidUnlockKey(
        `${path} holds ${stat.size} bytes; an unlock key file holds exactly ${AES_KEY_LENGTH} raw bytes`,
      );
    }
    const scratch = Buffer.alloc(AES_KEY_LENGTH + 1);
    try {
      let total = 0;
      while (total < scratch.length) {
        const n = readSync(fd, scratch, total, scratch.length - total, null);
        if (n === 0) break;
        total += n;
      }
      if (total !== AES_KEY_LENGTH) {
        throw VaultError.invalidUnlockKey(`${path} changed size while it was read`);
      }
      const key = new Uint8Array(AES_KEY_LENGTH);
      key.set(scratch.subarray(0, AES_KEY_LENGTH));
      return key;
    } finally {
      wipeBuffer(scratch);
    }
  } finally {
    closeSync(fd);
  }
}

/**
 * `server start --unlock-key-file <path>`: the raw 32-byte unlock key from a
 * file that is this user's own and readable by nobody else — on POSIX `0600`
 * or stricter (`UNLOCK_KEY_SOURCE_UNSAFE` naming the octal mode otherwise), on
 * win32 an access list naming no account beyond this user, SYSTEM and
 * Administrators. A missing path or a non-file is `INVALID_INPUT`, a wrong
 * length `INVALID_UNLOCK_KEY`. Read before the vault opens; the caller hands
 * the buffer to `unlockWithKey`, which wipes it.
 */
export async function readUnlockKeyFile(
  path: string,
  options: ReadUnlockKeyFileOptions = {},
): Promise<Uint8Array> {
  return readKeySource(path, "--unlock-key-file", "key-file", options.onWarning);
}

/**
 * `server start --unlock-credential <name>`: the unlock key systemd decrypted
 * into `$CREDENTIALS_DIRECTORY/<name>` (`LoadCredential=` /
 * `LoadCredentialEncrypted=`, systemd.exec(5)). An unset, empty or relative
 * variable and a name outside the credential-name rule are `INVALID_INPUT`
 * before anything is read; the file then takes the key file's ladder with the
 * acceptance systemd's own layout needs (`credentialModeVerdict`). No mount
 * warning: the directory is systemd's own read-only tmpfs or ramfs.
 */
export async function readUnlockCredential(
  name: string,
  env: { CREDENTIALS_DIRECTORY?: string },
): Promise<Uint8Array> {
  const dir = env.CREDENTIALS_DIRECTORY;
  if (dir === undefined || dir === "") {
    throw VaultError.invalidInput(
      "--unlock-credential: $CREDENTIALS_DIRECTORY is not set (systemd sets it for a unit with LoadCredential= or LoadCredentialEncrypted=)",
    );
  }
  if (!isAbsolute(dir)) {
    throw VaultError.invalidInput(
      `--unlock-credential: $CREDENTIALS_DIRECTORY is not an absolute path: ${dir}`,
    );
  }
  if (!CREDENTIAL_NAME.test(name)) {
    throw VaultError.invalidInput(
      `--unlock-credential: ${JSON.stringify(name)} is not a credential name (letters, digits, _, . and -, not starting with . or -; at most 255)`,
    );
  }
  return readKeySource(join(dir, name), `--unlock-credential ${name}`, "credential");
}

/**
 * `unlock-key enroll --out <path>`: write the key to a new file only the owner
 * can read — created exclusively (`EEXIST` refused naming the path; the parent
 * must exist), on POSIX mode `0400` set on the descriptor whatever the umask,
 * on win32 the access list reduced to the owner before a byte is written. No
 * temp file and rename: a leftover temp would be a second copy of the key. A
 * failure after the create removes the file and throws; the caller keeps and
 * wipes the key.
 */
export async function writeUnlockKeyFile(path: string, key: Uint8Array): Promise<void> {
  if (key.length !== AES_KEY_LENGTH) {
    throw VaultError.invalidInput(
      `--out: an unlock key is ${AES_KEY_LENGTH} bytes; got ${key.length}`,
    );
  }
  let fd: number;
  try {
    fd = openSync(path, "wx", 0o400);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EEXIST") {
      throw VaultError.invalidInput(
        `--out: ${path} exists; the unlock key is written to a new file only`,
      );
    }
    if (code === "ENOENT" || code === "ENOTDIR") {
      throw VaultError.invalidInput(`--out: no such directory: ${dirname(path)}`);
    }
    throw VaultError.invalidInput(`--out: cannot create ${path}`);
  }
  let written = false;
  try {
    if (process.platform === "win32") {
      restrictWindowsAclToOwner(path);
    } else {
      fchmodSync(fd, 0o400);
    }
    let offset = 0;
    while (offset < key.length) {
      offset += writeSync(fd, key, offset, key.length - offset);
    }
    fsyncSync(fd);
    written = true;
  } catch (err) {
    throw new VaultError(
      ErrorCode.FILE_IO_ERROR,
      `could not write the unlock key file ${path} (${err instanceof Error ? err.message : String(err)})`,
    );
  } finally {
    closeSync(fd);
    if (!written) {
      try {
        unlinkSync(path);
      } catch {
        // Best effort: the thrown error names the path.
      }
    }
  }
}
