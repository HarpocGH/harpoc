import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, posix, sep, win32 } from "node:path";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { system32Path } from "../win32-paths.js";
import type { WindowsAclEntry, WindowsAclListing } from "./owner-only.js";
import { foreignToVaultAccounts } from "./owner-only.js";
import {
  WIN32_PARENT_RIGHTS,
  WIN32_REPLACE_RIGHTS,
  WIN32_TRUSTED_SIDS,
  assertHeldDir,
  assertOwnerOnlyDir,
  assertUnlinkedDir,
  isHeldPath,
  isLinkPath,
  linkProbePath,
  posixHeld,
  win32Held,
} from "./path-trust.js";

const WIN32 = process.platform === "win32";
const LABEL = "--backup-dir";

const EUID = 1001;
const NEIGHBOUR_UID = 1002;
const ROOT_0755 = { uid: 0, mode: 0o755 };
const ROOT_STICKY_1777 = { uid: 0, mode: 0o1777 };
const OWN_0700 = { uid: EUID, mode: 0o700 };

const ME = "S-1-5-21-1000-2000-3000-1001";
const NEIGHBOUR = "S-1-5-21-1000-2000-3000-1002";
const SYSTEM = "S-1-5-18";
const ADMINISTRATORS = "S-1-5-32-544";
const USERS = "S-1-5-32-545";
const AUTHENTICATED_USERS = "S-1-5-11";
const EVERYONE = "S-1-1-0";
const CREATOR_OWNER = "S-1-3-0";
const TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const FULL = 0x001f01ff;

function allow(
  sid: string,
  rights: number,
  inheritance: number,
  propagation: number,
  inherited = false,
): WindowsAclEntry {
  return { allow: true, sid, rights, inherited, inheritance, propagation };
}

// Measured on Windows 11 build 26200, this account's SID replaced by ME.
const C_ROOT: WindowsAclListing = {
  user: ME,
  owner: TRUSTED_INSTALLER,
  rules: [
    allow(AUTHENTICATED_USERS, 0x00000004, 0, 0),
    allow(AUTHENTICATED_USERS, 0xe0010000, 3, 2),
    allow(SYSTEM, FULL, 3, 0),
    allow(ADMINISTRATORS, FULL, 3, 0),
    allow(USERS, 0x001200a9, 3, 0),
    allow(
      "S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176",
      0x001000a1,
      0,
      0,
    ),
  ],
};
const C_USERS: WindowsAclListing = {
  user: ME,
  owner: SYSTEM,
  rules: [
    allow(EVERYONE, 0xa0000000, 3, 2),
    allow(EVERYONE, 0x001200a9, 0, 0),
    allow(SYSTEM, FULL, 3, 0),
    allow(ADMINISTRATORS, FULL, 3, 0),
    allow(USERS, 0x001200a9, 0, 0),
    allow(USERS, 0xa0000000, 3, 2),
    allow(
      "S-1-15-3-65536-4045685566-1323397456-4055816110-285687253-194181-4019357623-1925838800-191844675",
      0x00100021,
      0,
      0,
    ),
  ],
};
const PROFILE: WindowsAclListing = {
  user: ME,
  owner: SYSTEM,
  rules: [
    allow(SYSTEM, FULL, 3, 0),
    allow(ADMINISTRATORS, FULL, 3, 0),
    allow(ME, FULL, 3, 0),
    allow(
      "S-1-15-3-65536-599108337-2355189375-1353122160-3480128286-3345335107-485756383-4087318168-230526575",
      0x00100020,
      0,
      0,
    ),
  ],
};
const PROGRAM_DATA: WindowsAclListing = {
  user: ME,
  owner: SYSTEM,
  rules: [
    allow(CREATOR_OWNER, 0x10000000, 3, 2),
    allow(SYSTEM, FULL, 3, 0),
    allow(ADMINISTRATORS, FULL, 3, 0),
    allow(USERS, 0x001200a9, 3, 0),
    allow(USERS, 0x00000116, 1, 0),
  ],
};
// The deployment layout's %ProgramData%\harpoc: /inheritance:r, the vault account as owner.
const PROGRAM_DATA_HARPOC: WindowsAclListing = {
  user: ME,
  owner: ME,
  rules: [allow(ME, FULL, 3, 0), allow(SYSTEM, FULL, 3, 0), allow(ADMINISTRATORS, FULL, 3, 0)],
};
// The layout's %ProgramData%\harpoc\backups, set as %ProgramData%\harpoc is.
const PROGRAM_DATA_HARPOC_BACKUPS: WindowsAclListing = PROGRAM_DATA_HARPOC;
// A folder made in a volume's root takes C_ROOT's inheritable entries: Authenticated Users modify, delete included.
const ROOT_FOLDER: WindowsAclListing = {
  user: ME,
  owner: ME,
  rules: [
    allow(ADMINISTRATORS, FULL, 3, 0, true),
    allow(SYSTEM, FULL, 3, 0, true),
    allow(USERS, 0x001200a9, 3, 0, true),
    allow(AUTHENTICATED_USERS, 0x001301bf, 0, 0, true),
    allow(AUTHENTICATED_USERS, 0xe0010000, 3, 2, true),
  ],
};
// An operator's own backup directory in that folder, its inherited entries removed.
const CLOSED_BACKUPS: WindowsAclListing = PROGRAM_DATA_HARPOC;

function withRule(acl: WindowsAclListing, rule: WindowsAclEntry): WindowsAclListing {
  return { ...acl, rules: [...acl.rules, rule] };
}

describe("the win32 constants", () => {
  it("are SYSTEM, Administrators and TrustedInstaller, the replace mask, and the parent mask with write attributes", () => {
    expect(WIN32_TRUSTED_SIDS).toEqual([SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER]);
    expect(WIN32_REPLACE_RIGHTS).toBe(0x100d0040);
    expect(WIN32_PARENT_RIGHTS).toBe(0x500d0146);
  });
});

describe("posixHeld", () => {
  it("holds a chain that is root-owned 0755 all the way", () => {
    expect(posixHeld([ROOT_0755, ROOT_0755, ROOT_0755], EUID)).toBe(true);
  });

  it("refuses a chain with one 0775 directory", () => {
    expect(posixHeld([ROOT_0755, { uid: 0, mode: 0o775 }, ROOT_0755], EUID)).toBe(false);
  });

  it("refuses a chain with one directory of a third uid", () => {
    expect(posixHeld([ROOT_0755, { uid: NEIGHBOUR_UID, mode: 0o755 }, OWN_0700], EUID)).toBe(false);
  });

  it("holds a root-owned 1777 directory above the parent when the next entry is the euid's", () => {
    expect(posixHeld([ROOT_0755, ROOT_STICKY_1777, OWN_0700], EUID)).toBe(true);
  });

  it("refuses a root-owned 1777 directory as the file's own parent", () => {
    expect(posixHeld([ROOT_0755, ROOT_STICKY_1777], EUID)).toBe(false);
  });

  it("refuses a sticky directory owned by the euid's neighbour", () => {
    expect(posixHeld([ROOT_0755, { uid: NEIGHBOUR_UID, mode: 0o1777 }, OWN_0700], EUID)).toBe(
      false,
    );
  });

  it("refuses a sticky directory whose next entry belongs to a third uid", () => {
    expect(
      posixHeld([ROOT_0755, ROOT_STICKY_1777, { uid: NEIGHBOUR_UID, mode: 0o700 }], EUID),
    ).toBe(false);
  });

  it("holds nothing on an empty chain", () => {
    expect(posixHeld([], EUID)).toBe(false);
  });
});

describe("win32Held", () => {
  it("holds C:\\ with C:\\Users and a profile directory", () => {
    expect(win32Held([C_ROOT, C_USERS, PROFILE])).toBe(true);
  });

  it("refuses a chain that ends in C:\\ProgramData (Users hold 0x116 on it)", () => {
    expect(win32Held([C_ROOT, PROGRAM_DATA])).toBe(false);
  });

  it("holds C:\\ProgramData above the parent", () => {
    expect(win32Held([C_ROOT, PROGRAM_DATA, PROGRAM_DATA_HARPOC])).toBe(true);
  });

  it("refuses an entry of another SID with 0x00010000 (delete)", () => {
    const users = withRule(C_USERS, allow(NEIGHBOUR, 0x00010000, 0, 0));
    expect(win32Held([C_ROOT, users, PROFILE])).toBe(false);
  });

  it("does not judge that entry inherit-only", () => {
    const users = withRule(C_USERS, allow(NEIGHBOUR, 0x00010000, 3, 2));
    expect(win32Held([C_ROOT, users, PROFILE])).toBe(true);
  });

  it("refuses an owner outside this account, SYSTEM, Administrators and TrustedInstaller", () => {
    expect(win32Held([C_ROOT, C_USERS, { ...PROFILE, owner: NEIGHBOUR }])).toBe(false);
  });

  it("holds TrustedInstaller as owner", () => {
    expect(win32Held([C_ROOT, C_USERS, { ...PROFILE, owner: TRUSTED_INSTALLER }])).toBe(true);
  });

  it("refuses an entry of another SID with 0x00000100 (write attributes: it turns an empty directory into a junction) on the file's own parent", () => {
    const parent = withRule(PROFILE, allow(NEIGHBOUR, 0x00000100, 0, 0));
    expect(win32Held([C_ROOT, C_USERS, parent])).toBe(false);
  });

  it("holds that entry on a directory above the parent", () => {
    const users = withRule(C_USERS, allow(NEIGHBOUR, 0x00000100, 0, 0));
    expect(win32Held([C_ROOT, users, PROFILE])).toBe(true);
  });

  it("does not read a deny entry of another SID as a grant", () => {
    const parent = withRule(PROFILE, { ...allow(NEIGHBOUR, FULL, 3, 0), allow: false });
    expect(win32Held([C_ROOT, C_USERS, parent])).toBe(true);
  });

  it("holds nothing on an empty chain", () => {
    expect(win32Held([])).toBe(false);
  });

  it("holds the layout's backup directory below C:\\ProgramData and %ProgramData%\\harpoc", () => {
    expect(
      win32Held([C_ROOT, PROGRAM_DATA, PROGRAM_DATA_HARPOC, PROGRAM_DATA_HARPOC_BACKUPS]),
    ).toBe(true);
  });

  it("refuses a closed backup directory under a folder in which Authenticated Users hold delete, though the directory alone passes its own judgement", () => {
    expect(foreignToVaultAccounts(CLOSED_BACKUPS)).toBeUndefined();
    expect(win32Held([C_ROOT, ROOT_FOLDER, CLOSED_BACKUPS])).toBe(false);
  });
});

describe("linkProbePath (the tail walk on the text alone, every platform)", () => {
  it.each([
    ["/srv/link", "/srv/link"],
    ["/srv/link/", "/srv/link"],
    ["/srv/link//", "/srv/link"],
    ["/srv/link/.", "/srv/link"],
    ["/srv/link/./", "/srv/link"],
    ["/srv/link/sub/..", "/srv/link"],
    ["/srv/link/sub/../.", "/srv/link"],
    ["/srv/link/a/b/../..", "/srv/link"],
    ["/srv/a/../run", "/srv/a/../run"],
    ["/srv/a/../x/sub/..", "/srv/a/../x"],
    ["/var/run/../x", "/var/run/../x"],
    ["./run", "./run"],
    ["run/", "run"],
    ["/", "/"],
    ["//", "/"],
    ["/.", "/."],
    ["", ""],
    ["/x/..", "/x/.."],
    ["..", ".."],
    ["../..", "../.."],
    ["../../", "../.."],
    ["a/../..", "a/../.."],
  ])("POSIX: %j is read at %j", (path, probe) => {
    expect(linkProbePath(path, posix)).toBe(probe);
  });

  it.each([
    ["C:\\srv\\link\\", "C:\\srv\\link"],
    ["C:\\srv\\link\\/", "C:\\srv\\link"],
    ["C:\\srv\\link\\.", "C:\\srv\\link"],
    ["C:\\srv/link/.", "C:\\srv/link"],
    ["C:/srv/link/./", "C:/srv/link"],
    ["C:\\srv\\link\\sub\\..", "C:\\srv\\link"],
    ["C:\\srv\\link\\a\\b\\..\\..", "C:\\srv\\link"],
    ["C:\\srv\\a\\..\\run", "C:\\srv\\a\\..\\run"],
    ["C:\\", "C:\\"],
    ["C:/", "C:/"],
    ["C:\\x\\..", "C:\\x\\.."],
    ["C:", "C:"],
    ["C:..", "C:.."],
    ["C:rel\\.", "C:rel"],
    ["\\\\server\\share", "\\\\server\\share"],
    ["\\\\server\\share\\", "\\\\server\\share\\"],
    ["\\\\server\\share\\x\\.", "\\\\server\\share\\x"],
    ["//server/share/x/./", "//server/share/x"],
    ["..\\..", "..\\.."],
    ["..\\..\\", "..\\.."],
  ])("win32: %j is read at %j", (path, probe) => {
    expect(linkProbePath(path, win32)).toBe(probe);
  });

  it("defaults to this platform's path flavour", () => {
    expect(linkProbePath(`${join("srv", "link")}${sep}.`)).toBe(join("srv", "link"));
  });
});

function grantUsers(dir: string, rights: string): void {
  const res = spawnSync(
    system32Path("icacls.exe"),
    [dir, "/grant", `*${USERS}:(OI)(CI)${rights}`],
    { shell: false, windowsHide: true, timeout: 15_000 },
  );
  expect(res.status).toBe(0);
}

function grantUsersDelete(dir: string): void {
  const res = spawnSync(system32Path("icacls.exe"), [dir, "/grant", `*${USERS}:(D)`], {
    shell: false,
    windowsHide: true,
    timeout: 15_000,
  });
  expect(res.status).toBe(0);
}

describe("on real directories", () => {
  let base: string;

  beforeEach(() => {
    base = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-path-trust-")));
  });

  afterEach(() => {
    rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  describe("assertOwnerOnlyDir", () => {
    it.skipIf(WIN32)("passes a 0700 directory of this process's uid (POSIX modes)", () => {
      chmodSync(base, 0o700);
      expect(() => assertOwnerOnlyDir(base, LABEL)).not.toThrow();
    });

    it.skipIf(WIN32)("refuses a 0750 directory with the mode line (POSIX modes)", async () => {
      chmodSync(base, 0o750);
      const error = await expectVaultError(
        () => assertOwnerOnlyDir(base, LABEL),
        ErrorCode.INVALID_INPUT,
      );
      expect(error.message).toBe(
        `${LABEL}: mode 0750 is not 0700 (group- or world-accessible): ${base}`,
      );
    });

    it.skipIf(WIN32 || process.geteuid?.() === 0)(
      "refuses a directory of another uid, the root directory, with the owner line (POSIX owners; not as root)",
      async () => {
        const error = await expectVaultError(
          () => assertOwnerOnlyDir("/", LABEL),
          ErrorCode.INVALID_INPUT,
        );
        expect(error.message).toBe(
          `${LABEL}: owned by uid 0, not by this process's uid ${String(process.geteuid?.())}: /`,
        );
      },
    );

    // The host may not grant a symbolic link on win32.
    it.skipIf(WIN32)("refuses a symbolic link to a 0700 directory with the link line", async () => {
      const target = join(base, "target");
      mkdirSync(target, { mode: 0o700 });
      const link = join(base, "link");
      symlinkSync(target, link);
      const error = await expectVaultError(
        () => assertOwnerOnlyDir(link, LABEL),
        ErrorCode.INVALID_INPUT,
      );
      expect(error.message).toBe(
        `${LABEL}: the path is a symbolic link or junction, not a directory: ${link}`,
      );
    });

    it("refuses a file with the not-a-directory line", async () => {
      const file = join(base, "file");
      writeFileSync(file, "");
      const error = await expectVaultError(
        () => assertOwnerOnlyDir(file, LABEL),
        ErrorCode.INVALID_INPUT,
      );
      expect(error.message).toBe(`${LABEL}: not a directory: ${file}`);
    });

    it("refuses a missing path with the no-such-directory line", async () => {
      const missing = join(base, "missing");
      const error = await expectVaultError(
        () => assertOwnerOnlyDir(missing, LABEL),
        ErrorCode.INVALID_INPUT,
      );
      expect(error.message).toBe(`${LABEL}: no such directory: ${missing}`);
    });

    it.runIf(WIN32)("passes a fresh directory under the temporary directory (win32)", () => {
      expect(() => assertOwnerOnlyDir(base, LABEL)).not.toThrow();
    });

    it.runIf(WIN32)(
      "refuses a directory icacls gave Users a grant, with the grant line (win32)",
      async () => {
        grantUsers(base, "(RX)");
        const error = await expectVaultError(
          () => assertOwnerOnlyDir(base, LABEL),
          ErrorCode.INVALID_INPUT,
        );
        expect(error.message).toBe(
          `${LABEL}: the access list grants ${USERS} 0x001200A9; only this process's account, SYSTEM and Administrators may hold a grant: ${base}`,
        );
      },
    );

    it.runIf(WIN32)(
      "refuses a directory icacls gave Users an inherit-only grant, with the grant line (win32)",
      async () => {
        grantUsers(base, "(IO)R");
        const error = await expectVaultError(
          () => assertOwnerOnlyDir(base, LABEL),
          ErrorCode.INVALID_INPUT,
        );
        expect(error.message).toBe(
          `${LABEL}: the access list grants ${USERS} 0x00120089; only this process's account, SYSTEM and Administrators may hold a grant: ${base}`,
        );
      },
    );

    it.runIf(WIN32)("refuses a junction to a directory with the link line (win32)", async () => {
      const target = join(base, "target");
      mkdirSync(target);
      const link = join(base, "link");
      symlinkSync(target, link, "junction");
      const error = await expectVaultError(
        () => assertOwnerOnlyDir(link, LABEL),
        ErrorCode.INVALID_INPUT,
      );
      expect(error.message).toBe(
        `${LABEL}: the path is a symbolic link or junction, not a directory: ${link}`,
      );
    });
  });

  describe("assertUnlinkedDir", () => {
    it.skipIf(WIN32)(
      "answers the stat of a directory whatever its mode: a 0777 directory passes (POSIX modes)",
      () => {
        chmodSync(base, 0o777);
        expect(assertUnlinkedDir(base, LABEL).isDirectory()).toBe(true);
        expect(assertUnlinkedDir(base, LABEL).mode & 0o777).toBe(0o777);
      },
    );

    it.runIf(WIN32)(
      "answers the stat of a directory whatever its access list: one icacls gave Users a grant passes (win32)",
      () => {
        grantUsers(base, "(RX)");
        expect(assertUnlinkedDir(base, LABEL).isDirectory()).toBe(true);
      },
    );

    it("refuses a file with the not-a-directory line", async () => {
      const file = join(base, "file");
      writeFileSync(file, "");
      const error = await expectVaultError(
        () => assertUnlinkedDir(file, LABEL),
        ErrorCode.INVALID_INPUT,
      );
      expect(error.message).toBe(`${LABEL}: not a directory: ${file}`);
    });

    it("refuses a missing path with the no-such-directory line", async () => {
      const missing = join(base, "missing");
      const error = await expectVaultError(
        () => assertUnlinkedDir(missing, LABEL),
        ErrorCode.INVALID_INPUT,
      );
      expect(error.message).toBe(`${LABEL}: no such directory: ${missing}`);
    });

    // The host may not grant a symbolic link on win32.
    it.skipIf(WIN32)("refuses a symbolic link to a directory with the link line", async () => {
      const target = join(base, "target");
      mkdirSync(target, { mode: 0o700 });
      const link = join(base, "link");
      symlinkSync(target, link);
      const error = await expectVaultError(
        () => assertUnlinkedDir(link, LABEL),
        ErrorCode.INVALID_INPUT,
      );
      expect(error.message).toBe(
        `${LABEL}: the path is a symbolic link or junction, not a directory: ${link}`,
      );
    });

    it.runIf(WIN32)("refuses a junction to a directory with the link line (win32)", async () => {
      const target = join(base, "target");
      mkdirSync(target);
      const link = join(base, "link");
      symlinkSync(target, link, "junction");
      const error = await expectVaultError(
        () => assertUnlinkedDir(link, LABEL),
        ErrorCode.INVALID_INPUT,
      );
      expect(error.message).toBe(
        `${LABEL}: the path is a symbolic link or junction, not a directory: ${link}`,
      );
    });
  });

  describe("isLinkPath", () => {
    it("reads a directory, with a trailing separator too, as no link", () => {
      expect(isLinkPath(base)).toBe(false);
      expect(isLinkPath(`${base}${sep}`)).toBe(false);
    });

    it.runIf(WIN32)("reads a junction to a directory as one, a trailing separator too", () => {
      const target = join(base, "target");
      mkdirSync(target);
      const link = join(base, "link");
      symlinkSync(target, link, "junction");
      expect(isLinkPath(link)).toBe(true);
      expect(isLinkPath(`${link}${sep}`)).toBe(true);
      expect(isLinkPath(target)).toBe(false);
    });

    // The host may not grant a symbolic link on win32.
    it.skipIf(WIN32)(
      "reads a symbolic link to a directory as one, a trailing separator too",
      () => {
        const target = join(base, "target");
        mkdirSync(target);
        const link = join(base, "link");
        symlinkSync(target, link);
        expect(isLinkPath(link)).toBe(true);
        expect(isLinkPath(`${link}${sep}`)).toBe(true);
      },
    );
  });

  describe("isHeldPath", () => {
    it.skipIf(WIN32)(
      "holds a file in a 0700 directory under the temporary directory, and a name not yet written there (POSIX modes)",
      async () => {
        chmodSync(base, 0o700);
        const file = join(base, "transfer.bin");
        writeFileSync(file, "");
        expect(await isHeldPath(file)).toBe(true);
        expect(await isHeldPath(join(base, "not-yet-written.bin"))).toBe(true);
      },
    );

    it.skipIf(WIN32)("does not hold it after chmod 0777 (POSIX modes)", async () => {
      const file = join(base, "transfer.bin");
      writeFileSync(file, "");
      chmodSync(base, 0o777);
      expect(await isHeldPath(file)).toBe(false);
    });

    it.runIf(WIN32)(
      "holds a file in a fresh directory under the temporary directory (win32)",
      async () => {
        const file = join(base, "transfer.bin");
        writeFileSync(file, "");
        expect(await isHeldPath(file)).toBe(true);
      },
    );

    it.runIf(WIN32)(
      "does not hold it after icacls gave Users modify on the directory (win32)",
      async () => {
        const file = join(base, "transfer.bin");
        writeFileSync(file, "");
        expect(await isHeldPath(file)).toBe(true);
        grantUsers(base, "M");
        expect(await isHeldPath(file)).toBe(false);
      },
    );

    it.runIf(WIN32)(
      "does not hold a path through a junction on the chain, though it holds the junction's target (win32)",
      async () => {
        const target = join(base, "target");
        mkdirSync(join(target, "sub"), { recursive: true });
        const link = join(base, "link");
        symlinkSync(target, link, "junction");
        expect(await isHeldPath(join(target, "sub", "transfer.bin"))).toBe(true);
        expect(await isHeldPath(join(link, "sub", "transfer.bin"))).toBe(false);
      },
    );

    it.runIf(WIN32)(
      "does not hold a chain with a name that ends in a dot or a space, which the access listing reads without it (win32)",
      async () => {
        const held = join(base, "held");
        mkdirSync(join(held, "sub"), { recursive: true });
        expect(await isHeldPath(join(held, "sub", "transfer.bin"))).toBe(true);
        const answers: boolean[] = [];
        for (const suffix of [".", " "]) {
          mkdirSync(`${held}${suffix}${sep}sub`, { recursive: true });
          answers.push(
            await isHeldPath(`${held}${suffix}${sep}transfer.bin`),
            await isHeldPath(`${held}${suffix}${sep}sub${sep}transfer.bin`),
          );
        }
        expect(answers).toEqual([false, false, false, false]);
      },
    );
  });

  describe("assertHeldDir", () => {
    const CHANGEABLE = `${LABEL}: a directory on its path can be changed by another account`;

    it.skipIf(WIN32)(
      "answers a 0700 directory under the temporary directory as itself (POSIX modes)",
      async () => {
        const closed = join(base, "backups");
        mkdirSync(closed, { mode: 0o700 });
        expect(await assertHeldDir(closed, LABEL)).toBe(closed);
      },
    );

    it.skipIf(WIN32)(
      "refuses a 0700 directory under a 0777 directory that is not sticky, naming the path (POSIX modes)",
      async () => {
        const open = join(base, "open");
        mkdirSync(open);
        chmodSync(open, 0o777);
        const closed = join(open, "backups");
        mkdirSync(closed, { mode: 0o700 });
        expect(() => assertOwnerOnlyDir(closed, LABEL)).not.toThrow();
        const error = await expectVaultError(
          () => assertHeldDir(closed, LABEL),
          ErrorCode.INVALID_INPUT,
        );
        expect(error.message).toBe(`${CHANGEABLE}: ${closed}`);
      },
    );

    // The host may not grant a symbolic link on win32.
    it.skipIf(WIN32)(
      "judges a directory reached through a link at its real path and answers that path (POSIX links)",
      async () => {
        const real = join(base, "real");
        mkdirSync(join(real, "backups"), { recursive: true, mode: 0o700 });
        const link = join(base, "link");
        symlinkSync(real, link);
        expect(await assertHeldDir(join(link, "backups"), LABEL)).toBe(join(real, "backups"));

        const open = join(base, "open");
        mkdirSync(join(open, "backups"), { recursive: true, mode: 0o700 });
        chmodSync(open, 0o777);
        const openLink = join(base, "open-link");
        symlinkSync(open, openLink);
        const error = await expectVaultError(
          () => assertHeldDir(join(openLink, "backups"), LABEL),
          ErrorCode.INVALID_INPUT,
        );
        expect(error.message).toBe(`${CHANGEABLE}: ${join(openLink, "backups")}`);
      },
    );

    it("refuses a path that does not resolve, naming it", async () => {
      const missing = join(base, "missing");
      const error = await expectVaultError(
        () => assertHeldDir(missing, LABEL),
        ErrorCode.INVALID_INPUT,
      );
      expect(error.message).toBe(`${CHANGEABLE}: ${missing}`);
    });

    it.runIf(WIN32)(
      "answers a fresh directory under the temporary directory as itself (win32)",
      async () => {
        const closed = join(base, "backups");
        mkdirSync(closed);
        expect(await assertHeldDir(closed, LABEL)).toBe(closed);
      },
    );

    it.runIf(WIN32)(
      "refuses a closed directory under a directory icacls gave Users delete, naming the path (win32)",
      async () => {
        const open = join(base, "open");
        mkdirSync(open);
        grantUsersDelete(open);
        const closed = join(open, "backups");
        mkdirSync(closed);
        expect(() => assertOwnerOnlyDir(closed, LABEL)).not.toThrow();
        const error = await expectVaultError(
          () => assertHeldDir(closed, LABEL),
          ErrorCode.INVALID_INPUT,
        );
        expect(error.message).toBe(`${CHANGEABLE}: ${closed}`);
      },
    );
  });
});
