import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { listWindowsAcl, restrictWindowsAclToOwner } from "./owner-only.js";
import type { WindowsAcl } from "./owner-only.js";
import {
  credentialModeVerdict,
  keyFileModeVerdict,
  mountFilesystemType,
  mountWarningFor,
  readUnlockCredential,
  readUnlockKeyFile,
  windowsAclVerdict,
  writeUnlockKeyFile,
} from "./unlock-key-source.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, readFileSync: vi.fn(actual.readFileSync) };
});

vi.mock("./owner-only.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./owner-only.js")>();
  return {
    ...actual,
    listWindowsAcl: vi.fn(actual.listWindowsAcl),
    restrictWindowsAclToOwner: vi.fn(actual.restrictWindowsAclToOwner),
  };
});

const KEY = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);
const KEY_FORMS = [
  Buffer.from(KEY).toString("hex"),
  Buffer.from(KEY).toString("base64"),
  Buffer.from(KEY).toString("base64url"),
];
const USER_SID = "S-1-5-21-1000-2000-3000-1001";

let dir: string;

function withPlatform<T>(platform: NodeJS.Platform, fn: () => Promise<T>): Promise<T> {
  const original = process.platform;
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
  return fn().finally(() => {
    Object.defineProperty(process, "platform", { value: original, configurable: true });
  });
}

function expectNoKeyIn(message: string): void {
  for (const form of KEY_FORMS) expect(message.includes(form)).toBe(false);
}

beforeEach(() => {
  vi.clearAllMocks();
  dir = mkdtempSync(join(tmpdir(), "harpoc-unlock-key-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("readUnlockKeyFile", () => {
  it("reads the 32 bytes writeUnlockKeyFile wrote, into a fresh buffer on every read", async () => {
    const path = join(dir, "unlock.key");
    await writeUnlockKeyFile(path, KEY);

    const first = await readUnlockKeyFile(path);
    const second = await readUnlockKeyFile(path);
    expect(Buffer.from(first).equals(KEY)).toBe(true);
    expect(first.byteOffset).toBe(0);
    expect(first.buffer.byteLength).toBe(32);
    first.fill(0);
    expect(Buffer.from(second).equals(KEY)).toBe(true);
  });

  it("refuses a missing path INVALID_INPUT naming it", async () => {
    const path = join(dir, "absent.key");
    const error = await expectVaultError(() => readUnlockKeyFile(path), ErrorCode.INVALID_INPUT);
    expect(error.message).toBe(`--unlock-key-file: no such file: ${path}`);
  });

  it("refuses a directory INVALID_INPUT as not a readable file", async () => {
    const error = await expectVaultError(() => readUnlockKeyFile(dir), ErrorCode.INVALID_INPUT);
    expect(error.message).toBe(`--unlock-key-file: not a readable file: ${dir}`);
  });

  it.each([
    ["31 bytes", KEY.subarray(0, 31)],
    ["33 bytes", Buffer.concat([KEY, Buffer.from([0])])],
    ["the key in hex (64 bytes)", Buffer.from(Buffer.from(KEY).toString("hex"), "ascii")],
  ])(
    "refuses a file of %s INVALID_UNLOCK_KEY naming the length, not the bytes",
    async (_, bytes) => {
      const path = join(dir, "wrong-length.key");
      writeFileSync(path, bytes, { mode: 0o600 });
      const error = await expectVaultError(
        () => readUnlockKeyFile(path),
        ErrorCode.INVALID_UNLOCK_KEY,
      );
      expectNoKeyIn(error.message);
      expect(error.message).toBe(
        `Invalid unlock key: ${path} holds ${bytes.length} bytes; an unlock key file holds exactly 32 raw bytes`,
      );
    },
  );

  it("refuses UNLOCK_KEY_SOURCE_UNSAFE acl_unverified when the win32 access list cannot be read, and the key is not in the message", async () => {
    const path = join(dir, "unlock.key");
    writeFileSync(path, KEY, { mode: 0o600 });
    vi.mocked(listWindowsAcl).mockRejectedValueOnce(new Error("ACL listing failed (exit 1)"));

    const error = await withPlatform("win32", () =>
      expectVaultError(() => readUnlockKeyFile(path), ErrorCode.UNLOCK_KEY_SOURCE_UNSAFE),
    );
    expect(error.details).toEqual({ reason: "acl_unverified" });
    expectNoKeyIn(error.message);
    expect(error.message).toBe(
      `Unlock key source refused: ${path} has an access list that could not be read`,
    );
  });

  it.skipIf(process.platform === "linux")(
    "never warns off Linux: the mount table is a Linux file (macOS and win32 would need an addon)",
    async () => {
      const path = join(dir, "unlock.key");
      await writeUnlockKeyFile(path, KEY);
      const warnings: string[] = [];
      await readUnlockKeyFile(path, { onWarning: (w) => warnings.push(w) });
      expect(warnings).toEqual([]);
    },
  );

  // Faked as Linux on macOS too; win32 has no geteuid for the POSIX owner check the ladder runs.
  it.skipIf(process.platform === "win32")(
    "hands the mount warning for a key file on a vfat mount to onWarning, the key still read (B4-U1)",
    async () => {
      const path = join(dir, "unlock.key");
      await writeUnlockKeyFile(path, KEY);
      const point = realpathSync(dir).replaceAll("\\", "\\134").replaceAll(" ", "\\040");
      vi.mocked(readFileSync).mockImplementationOnce(
        () => `1 0 0:1 / ${point} rw - vfat /dev/sdz1 rw,fmask=0077\n`,
      );
      const warnings: string[] = [];
      const key = await withPlatform("linux", () =>
        readUnlockKeyFile(path, { onWarning: (w) => warnings.push(w) }),
      );
      expect(vi.mocked(readFileSync)).toHaveBeenCalledWith("/proc/self/mountinfo", "utf8");
      expect(warnings).toEqual([
        `${path} is on a vfat filesystem — its modes are the mount's options, not the file's`,
      ]);
      expect(Buffer.from(key).equals(KEY)).toBe(true);
    },
  );

  it.runIf(process.platform === "linux")(
    "draws no mount warning for a key file on the temporary directory's filesystem",
    async () => {
      const path = join(dir, "unlock.key");
      await writeUnlockKeyFile(path, KEY);
      const warnings: string[] = [];
      await readUnlockKeyFile(path, { onWarning: (w) => warnings.push(w) });
      expect(warnings).toEqual([]);
    },
  );
});

// win32's fs.stat reports 0o666 (or 0o444 with the read-only attribute) for every file whatever
// its access list, so the POSIX owner and mode rows run on Linux and macOS only; win32 checks the
// access list instead (the win32 describe below).
describe.skipIf(process.platform === "win32")("readUnlockKeyFile on POSIX — owner and mode", () => {
  it.each([
    ["0400", 0o400],
    ["0600", 0o600],
  ])("accepts mode %s", async (_, mode) => {
    const path = join(dir, "unlock.key");
    writeFileSync(path, KEY, { mode: 0o600 });
    chmodSync(path, mode);
    expect(Buffer.from(await readUnlockKeyFile(path)).equals(KEY)).toBe(true);
  });

  it.each([
    ["0640", 0o640],
    ["0644", 0o644],
    ["0444", 0o444],
    ["0604", 0o604],
    ["0620", 0o620],
  ])("refuses mode %s UNLOCK_KEY_SOURCE_UNSAFE naming the octal mode", async (octal, mode) => {
    const path = join(dir, "unlock.key");
    writeFileSync(path, KEY, { mode: 0o600 });
    chmodSync(path, mode);
    const error = await expectVaultError(
      () => readUnlockKeyFile(path),
      ErrorCode.UNLOCK_KEY_SOURCE_UNSAFE,
    );
    expect(error.details).toEqual({ reason: "mode" });
    expectNoKeyIn(error.message);
    expect(error.message).toBe(
      `Unlock key source refused: ${path} has permission bits that grant access beyond its owner (mode ${octal})`,
    );
  });

  it("refuses a symbolic link to a good key file UNLOCK_KEY_SOURCE_UNSAFE symlink", async () => {
    const target = join(dir, "unlock.key");
    await writeUnlockKeyFile(target, KEY);
    const link = join(dir, "link.key");
    symlinkSync(target, link);
    const error = await expectVaultError(
      () => readUnlockKeyFile(link),
      ErrorCode.UNLOCK_KEY_SOURCE_UNSAFE,
    );
    expect(error.details).toEqual({ reason: "symlink" });
    expect(error.message).toBe(
      `Unlock key source refused: ${link} is a symbolic link; name the file itself`,
    );
  });
});

describe.runIf(process.platform === "win32")("readUnlockKeyFile on win32 — the access list", () => {
  it("accepts a file that inherits the temporary directory's SYSTEM, Administrators and user rules", async () => {
    const path = join(dir, "unlock.key");
    writeFileSync(path, KEY);
    expect(Buffer.from(await readUnlockKeyFile(path)).equals(KEY)).toBe(true);
  });

  it("refuses a file that also grants Everyone read UNLOCK_KEY_SOURCE_UNSAFE acl naming S-1-1-0", async () => {
    const path = join(dir, "unlock.key");
    writeFileSync(path, KEY);
    const grant = spawnSync(
      join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "icacls.exe"),
      [path, "/grant", "*S-1-1-0:(R)"],
      { shell: false, windowsHide: true },
    );
    expect(grant.status).toBe(0);
    const error = await expectVaultError(
      () => readUnlockKeyFile(path),
      ErrorCode.UNLOCK_KEY_SOURCE_UNSAFE,
    );
    expect(error.details).toEqual({ reason: "acl" });
    expect(error.message).toBe(
      `Unlock key source refused: ${path} grants access to an account other than this process's account, SYSTEM and Administrators (S-1-1-0)`,
    );
  });
});

// The predicates run on every platform: a file owned by another uid cannot be created without
// privilege, so the foreign-owner case is pinned here and not through a real file.
describe("the POSIX owner and mode predicates", () => {
  it("keyFileModeVerdict: this user's 0400 and 0600 pass; another owner is `owner`; any group or world bit is `mode`", () => {
    expect(keyFileModeVerdict({ uid: 1000, mode: 0o100400 }, 1000)).toBeUndefined();
    expect(keyFileModeVerdict({ uid: 1000, mode: 0o100600 }, 1000)).toBeUndefined();
    expect(keyFileModeVerdict({ uid: 0, mode: 0o100400 }, 1000)).toEqual({
      reason: "owner",
      observed: "uid 0; this process runs as uid 1000",
    });
    expect(keyFileModeVerdict({ uid: 1000, mode: 0o100440 }, 1000)).toEqual({
      reason: "mode",
      observed: "mode 0440",
    });
    expect(keyFileModeVerdict({ uid: 1000, mode: 0o100401 }, 1000)).toEqual({
      reason: "mode",
      observed: "mode 0401",
    });
  });

  it("credentialModeVerdict: systemd's root 0440 (the ACL mask) and the unit user's 0400 pass; group write, world bits and a third owner are refused", () => {
    expect(credentialModeVerdict({ uid: 0, mode: 0o100440 }, 1000)).toBeUndefined();
    expect(credentialModeVerdict({ uid: 1000, mode: 0o100400 }, 1000)).toBeUndefined();
    expect(credentialModeVerdict({ uid: 1000, mode: 0o100600 }, 1000)).toBeUndefined();
    expect(credentialModeVerdict({ uid: 0, mode: 0o100460 }, 1000)).toEqual({
      reason: "mode",
      observed: "mode 0460",
    });
    expect(credentialModeVerdict({ uid: 0, mode: 0o100444 }, 1000)).toEqual({
      reason: "mode",
      observed: "mode 0444",
    });
    expect(credentialModeVerdict({ uid: 1001, mode: 0o100400 }, 1000)).toEqual({
      reason: "owner",
      observed: "uid 1001; this process runs as uid 1000",
    });
  });
});

describe("windowsAclVerdict", () => {
  const acl = (owner: string, rules: WindowsAcl["rules"]): WindowsAcl => ({
    user: USER_SID,
    owner,
    rules,
  });

  it("passes the owner-only list and the inherited SYSTEM, Administrators and user list", () => {
    expect(windowsAclVerdict(acl(USER_SID, [{ allow: true, sid: USER_SID }]))).toBeUndefined();
    expect(
      windowsAclVerdict(
        acl("S-1-5-32-544", [
          { allow: true, sid: "S-1-5-18" },
          { allow: true, sid: "S-1-5-32-544" },
          { allow: true, sid: USER_SID },
        ]),
      ),
    ).toBeUndefined();
  });

  it("refuses an allow rule for any other account `acl`, ignores a deny rule, refuses a foreign owner `owner`", () => {
    expect(
      windowsAclVerdict(
        acl(USER_SID, [
          { allow: true, sid: USER_SID },
          { allow: true, sid: "S-1-5-32-545" },
        ]),
      ),
    ).toEqual({ reason: "acl", observed: "S-1-5-32-545" });
    expect(
      windowsAclVerdict(
        acl(USER_SID, [
          { allow: false, sid: "S-1-1-0" },
          { allow: true, sid: USER_SID },
        ]),
      ),
    ).toBeUndefined();
    expect(windowsAclVerdict(acl("S-1-5-21-9-9-9-500", [{ allow: true, sid: USER_SID }]))).toEqual({
      reason: "owner",
      observed: "owner S-1-5-21-9-9-9-500",
    });
  });
});

// proc_pid_mountinfo(5): mount ID, parent ID, major:minor, root, mount point, options, optional
// fields, "-", type, source, super options; the kernel escapes a space in the mount point as \040.
const MOUNTINFO = [
  "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw",
  "95 22 8:1 / /boot/efi rw,relatime shared:50 master:3 - vfat /dev/sda1 rw,fmask=0077,dmask=0077",
  "120 22 0:52 / /mnt/c rw,noatime - 9p drvfs rw,aname=drvfs;path=C:\\;uid=1000;gid=1000",
  "130 22 0:60 / /mnt/my\\040share rw - cifs //srv/share rw,file_mode=0600",
  "140 22 0:61 / /media/stick rw shared:9 - fuseblk /dev/sdb1 rw,user_id=0,group_id=0",
  "150 22 0:62 / /srv/data rw - vfat /dev/sdc1 rw",
  "151 150 0:63 / /srv/data rw - ext4 /dev/sdd1 rw",
  "",
].join("\n");

describe("mountFilesystemType and mountWarningFor", () => {
  it.each([
    ["/home/u/unlock.key", "ext4"],
    ["/boot/efi/unlock.key", "vfat"],
    ["/boot/efikey/unlock.key", "ext4"],
    ["/mnt/c/Users/u/unlock.key", "9p"],
    ["/mnt/my share/unlock.key", "cifs"],
    ["/media/stick/unlock.key", "fuseblk"],
    ["/srv/data/unlock.key", "ext4"],
  ])("%s is on %s (the longest mount-point prefix, the last of equal ones)", (path, type) => {
    expect(mountFilesystemType(MOUNTINFO, path)).toBe(type);
  });

  it("warns for a filesystem whose modes are its mount's options, and not for ext4", () => {
    expect(mountWarningFor(MOUNTINFO, "/home/u/unlock.key")).toBeUndefined();
    expect(mountWarningFor(MOUNTINFO, "/mnt/c/Users/u/unlock.key")).toBe(
      "/mnt/c/Users/u/unlock.key is on a 9p filesystem — its modes are the mount's options, not the file's",
    );
    expect(mountWarningFor(MOUNTINFO, "/boot/efi/unlock.key")).toBe(
      "/boot/efi/unlock.key is on a vfat filesystem — its modes are the mount's options, not the file's",
    );
    expect(mountWarningFor("", "/home/u/unlock.key")).toBeUndefined();
  });
});

describe("readUnlockCredential", () => {
  it.each([
    ["unset", {}],
    ["empty", { CREDENTIALS_DIRECTORY: "" }],
  ])(
    "refuses INVALID_INPUT naming the variable when $CREDENTIALS_DIRECTORY is %s",
    async (_, env) => {
      const error = await expectVaultError(
        () => readUnlockCredential("harpoc-unlock", env),
        ErrorCode.INVALID_INPUT,
      );
      expect(error.message).toBe(
        "--unlock-credential: $CREDENTIALS_DIRECTORY is not set (systemd sets it for a unit with LoadCredential= or LoadCredentialEncrypted=)",
      );
    },
  );

  it("refuses a relative $CREDENTIALS_DIRECTORY INVALID_INPUT", async () => {
    const error = await expectVaultError(
      () => readUnlockCredential("harpoc-unlock", { CREDENTIALS_DIRECTORY: "creds" }),
      ErrorCode.INVALID_INPUT,
    );
    expect(error.message).toBe(
      "--unlock-credential: $CREDENTIALS_DIRECTORY is not an absolute path: creds",
    );
  });

  it.each([
    "",
    ".",
    "..",
    "a/b",
    "a\\b",
    "../unlock",
    "-x",
    ".hidden",
    "a:b",
    "a b",
    "x".repeat(256),
  ])("refuses the name %j INVALID_INPUT before anything is read", async (name) => {
    const error = await expectVaultError(
      () => readUnlockCredential(name, { CREDENTIALS_DIRECTORY: dir }),
      ErrorCode.INVALID_INPUT,
    );
    expect(error.message).toBe(
      `--unlock-credential: ${JSON.stringify(name)} is not a credential name (letters, digits, _, . and -, not starting with . or -; at most 255)`,
    );
  });

  it("refuses a missing credential INVALID_INPUT naming the name and the path", async () => {
    const error = await expectVaultError(
      () => readUnlockCredential("harpoc-unlock", { CREDENTIALS_DIRECTORY: dir }),
      ErrorCode.INVALID_INPUT,
    );
    expect(error.message).toBe(
      `--unlock-credential harpoc-unlock: no such file: ${join(dir, "harpoc-unlock")}`,
    );
  });

  it("reads the key from $CREDENTIALS_DIRECTORY/<name> — the fake credential directory of every leg", async () => {
    await writeUnlockKeyFile(join(dir, "harpoc-unlock"), KEY);
    expect(
      Buffer.from(
        await readUnlockCredential("harpoc-unlock", { CREDENTIALS_DIRECTORY: dir }),
      ).equals(KEY),
    ).toBe(true);
  });

  it.skipIf(process.platform === "win32")(
    "accepts systemd's shapes 0440 and 0400; refuses 0444 and group-writable 0460 `mode` and a symlink (POSIX modes; win32 checks the access list)",
    async () => {
      const path = join(dir, "harpoc-unlock");
      writeFileSync(path, KEY, { mode: 0o600 });
      const env = { CREDENTIALS_DIRECTORY: dir };
      for (const mode of [0o440, 0o400]) {
        chmodSync(path, mode);
        expect(Buffer.from(await readUnlockCredential("harpoc-unlock", env)).equals(KEY)).toBe(
          true,
        );
      }
      for (const [mode, octal] of [
        [0o444, "0444"],
        [0o460, "0460"],
      ] as const) {
        chmodSync(path, mode);
        const error = await expectVaultError(
          () => readUnlockCredential("harpoc-unlock", env),
          ErrorCode.UNLOCK_KEY_SOURCE_UNSAFE,
        );
        expect(error.message).toBe(
          `Unlock key source refused: ${path} has permission bits that grant access beyond its owner (mode ${octal})`,
        );
      }
      chmodSync(path, 0o400);
      symlinkSync(path, join(dir, "linked"));
      const error = await expectVaultError(
        () => readUnlockCredential("linked", env),
        ErrorCode.UNLOCK_KEY_SOURCE_UNSAFE,
      );
      expect(error.details).toEqual({ reason: "symlink" });
    },
  );
});

describe("writeUnlockKeyFile", () => {
  it("refuses an existing file INVALID_INPUT naming it and leaves it as it was", async () => {
    const path = join(dir, "unlock.key");
    writeFileSync(path, "operator's file");
    const error = await expectVaultError(
      () => writeUnlockKeyFile(path, KEY),
      ErrorCode.INVALID_INPUT,
    );
    expectNoKeyIn(error.message);
    expect(error.message).toBe(
      `--out: ${path} exists; the unlock key is written to a new file only`,
    );
    expect(readFileSync(path, "utf8")).toBe("operator's file");
  });

  it("refuses a missing parent directory INVALID_INPUT naming it — no directory is created", async () => {
    const parent = join(dir, "absent");
    const error = await expectVaultError(
      () => writeUnlockKeyFile(join(parent, "unlock.key"), KEY),
      ErrorCode.INVALID_INPUT,
    );
    expect(error.message).toBe(`--out: no such directory: ${parent}`);
    expect(existsSync(parent)).toBe(false);
  });

  it.skipIf(process.platform === "win32")(
    "writes mode 0400 whatever the umask — 0o477 here, which alone would create 0000 (POSIX modes)",
    async () => {
      const path = join(dir, "unlock.key");
      const previous = process.umask(0o477);
      try {
        await writeUnlockKeyFile(path, KEY);
      } finally {
        process.umask(previous);
      }
      expect(statSync(path).mode & 0o777).toBe(0o400);
      expect(Buffer.from(await readUnlockKeyFile(path)).equals(KEY)).toBe(true);
    },
  );

  it("on win32 reduces the access list to the owner before a byte of the key is written", async () => {
    const path = join(dir, "unlock.key");
    let sizeAtRestriction = -1;
    vi.mocked(restrictWindowsAclToOwner).mockImplementationOnce((target) => {
      sizeAtRestriction = statSync(target).size;
    });
    await withPlatform("win32", () => writeUnlockKeyFile(path, KEY));
    expect(vi.mocked(restrictWindowsAclToOwner)).toHaveBeenCalledWith(path);
    expect(sizeAtRestriction).toBe(0);
    expect(readFileSync(path).equals(KEY)).toBe(true);
  });

  it("a failed access-list reduction removes the file and refuses FILE_IO_ERROR — nothing of the key reaches the disk", async () => {
    const path = join(dir, "unlock.key");
    vi.mocked(restrictWindowsAclToOwner).mockImplementationOnce(() => {
      throw new Error("icacls exited 5: Access is denied.");
    });
    const error = await withPlatform("win32", () =>
      expectVaultError(() => writeUnlockKeyFile(path, KEY), ErrorCode.FILE_IO_ERROR),
    );
    expectNoKeyIn(error.message);
    expect(error.message).toBe(
      `could not write the unlock key file ${path} (icacls exited 5: Access is denied.)`,
    );
    expect(existsSync(path)).toBe(false);
  });

  it.runIf(process.platform === "win32")(
    "real path: the access list names the current user alone",
    async () => {
      const path = join(dir, "unlock.key");
      await writeUnlockKeyFile(path, KEY);
      const acl = await listWindowsAcl(path);
      expect(acl.rules).toEqual([{ allow: true, sid: acl.user }]);
      expect(windowsAclVerdict(acl)).toBeUndefined();
    },
  );

  it("refuses a key that is not 32 bytes before creating the file (the writer fails closed like the reader)", async () => {
    const path = join(dir, "unlock.key");
    await expectVaultError(
      () => writeUnlockKeyFile(path, KEY.subarray(0, 31)),
      ErrorCode.INVALID_INPUT,
    );
    expect(existsSync(path)).toBe(false);
  });
});
