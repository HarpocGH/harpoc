import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { lstat, realpath, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { system32Path } from "../win32-paths.js";
import type { DaemonPaths, LocalPathInput } from "./local-path.js";
import { judgeLocalPath, resolveSftpLocalPath } from "./local-path.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    realpath: vi.fn(actual.realpath),
    lstat: vi.fn(actual.lstat),
    stat: vi.fn(actual.stat),
  };
});

const B = "\\";
const MUST_BE_ABSOLUTE = "sftp local path must be absolute";
const NAMES_A_DEVICE = "sftp local path names a device";
const NAMES_A_SHARE = "sftp local path names a network share";
const NO_GLOB = "sftp local path must not contain glob characters";
const MUST_NAME_A_FILE = "sftp download path must name a file";
const READ_DIFFERENTLY = "sftp local path holds a name Windows reads differently";
const WIN32 = process.platform === "win32";
const NO_PATHS: DaemonPaths = { protectedDirs: [], protectedFiles: [] };
const USERS = "S-1-5-32-545";
const STICKY_DIR = "/tmp";

type Input = Parameters<typeof resolveSftpLocalPath>[0];

interface Fixture {
  root: string;
  listed: string;
  link: string;
  outside: string;
  vault: string;
  caseParent: string;
  caseInsensitive: boolean;
}

let fx: Fixture;

beforeAll(() => {
  // `.native` like the product's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  const root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-local-path-")));
  fx = {
    root,
    listed: join(root, "listed"),
    link: join(root, "listed-link"),
    outside: join(root, "outside"),
    vault: join(root, "vault"),
    caseParent: join(root, "case"),
    caseInsensitive: false,
  };
  for (const dir of [fx.listed, join(fx.listed, "sub"), fx.outside, fx.vault]) mkdirSync(dir);
  writeFileSync(join(fx.listed, "report.pdf"), "report");
  for (const name of ["key", "other", join("sub", "held.pdf")]) {
    writeFileSync(join(fx.listed, name), name);
  }
  // The daemon's walk refuses a group-writable directory, which a umask of 0002 makes.
  if (process.platform !== "win32") {
    for (const dir of [fx.listed, join(fx.listed, "sub")]) chmodSync(dir, 0o755);
  }
  writeFileSync(join(fx.outside, "secret.txt"), "outside");
  writeFileSync(join(fx.vault, "vault.db"), "");
  writeFileSync(join(fx.vault, "session.json"), "");
  mkdirSync(join(fx.caseParent, "Vault"), { recursive: true });
  writeFileSync(join(fx.caseParent, "Vault", "vault.db"), "");
  fx.caseInsensitive = existsSync(join(fx.caseParent, "VAULT", "vault.db"));
  // Node creates these names as they are spelled; the Win32 file API reads them differently.
  if (process.platform === "win32") {
    symlinkSync(fx.outside, join(fx.listed, "junc"), "junction");
    for (const [name, junction] of [
      ["dotted.", "to-dotted"],
      ["con", "to-con"],
    ] as const) {
      mkdirSync(join(fx.listed, name));
      writeFileSync(join(fx.listed, name, "report.pdf"), "report");
      symlinkSync(join(fx.listed, name), join(fx.listed, junction), "junction");
    }
    symlinkSync(fx.listed, join(root, "listed-junction."), "junction");
  }
  // A symbolic link needs a privilege a win32 host may not grant; the rows that need one skip there.
  if (process.platform !== "win32") {
    symlinkSync(fx.listed, fx.link);
    symlinkSync(fx.listed, join(root, "listed[link]"));
    symlinkSync(fx.listed, join(root, `listed${B}link`));
    symlinkSync(join(fx.outside, "secret.txt"), join(fx.listed, "escape"));
    symlinkSync(join(fx.outside, "new.txt"), join(fx.listed, "dangling"));
    writeFileSync(join(fx.listed, `back${B}slash.pdf`), "report");
    symlinkSync(join(fx.listed, `back${B}slash.pdf`), join(fx.listed, "backslash-link"));
    mkdirSync(join(fx.listed, "real", "sub2"), { recursive: true });
    for (const dir of [join(fx.listed, "real"), join(fx.listed, "real", "sub2")]) {
      chmodSync(dir, 0o755);
    }
    symlinkSync(join(fx.listed, "real"), join(fx.listed, "link"));
  }
});

afterAll(() => {
  rmSync(fx.root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function input(overrides: Partial<Input> = {}): Input {
  return {
    localPath: join(fx.listed, "report.pdf"),
    operation: "upload",
    allowedDirs: [fx.listed],
    vaultFiles: [join(fx.vault, "vault.db"), join(fx.vault, "session.json")],
    ...overrides,
  };
}

/** A spelling the caller may send: `<dir>/sub/../<name>`, which `path.join` would normalize away. */
function viaSub(dir: string, name: string): string {
  return `${dir}${sep}sub${sep}..${sep}${name}`;
}

type Case = readonly [string, () => Partial<Input>];

/** A row for a spelling under `C:\d`, judged by win32's rules on every host. */
function onWin32(
  name: string,
  message: string,
  label = name,
): readonly [string, () => Partial<Input>, string] {
  return [
    `C:${B}d${B}${label} on win32`,
    () => ({ localPath: `C:${B}d${B}${name}`, platform: "win32" }),
    message,
  ];
}

const NOT_ALLOWED: readonly Case[] = [
  ["a file outside every listed directory", () => ({ localPath: join(fx.outside, "secret.txt") })],
  ["a file that does not exist", () => ({ localPath: join(fx.listed, "missing.pdf") })],
  [
    "a .. path that leaves the directory",
    () => ({ localPath: `${fx.listed}${sep}..${sep}outside${sep}secret.txt` }),
  ],
  ["the listed directory itself", () => ({ localPath: fx.listed })],
  ["an empty list", () => ({ allowedDirs: [] })],
  ["a listed directory that does not exist", () => ({ allowedDirs: [join(fx.root, "nowhere")] })],
  [
    "a download whose parent does not exist",
    () => ({ operation: "download", localPath: join(fx.listed, "nowhere", "new.pdf") }),
  ],
  [
    "a file inside the vault directory although the list names that directory",
    () => ({ localPath: join(fx.vault, "vault.db"), allowedDirs: [fx.vault] }),
  ],
  [
    "a download onto an existing directory outside every listed directory",
    () => ({ operation: "download", localPath: fx.outside }),
  ],
  [
    "a download to a new file whose name holds an unpaired surrogate",
    () => ({ operation: "download", localPath: join(fx.listed, "new\uD83D.pdf") }),
  ],
  ...["console.txt", "a.b.txt", ".hidden", "nullable"].map((name): Case => [
    `C:${B}d${B}${name} on win32, an ordinary name,`,
    () => ({ localPath: `C:${B}d${B}${name}`, platform: "win32" }),
  ]),
  ...["name.", "a:b", "nul"].map((name): Case => [
    `/srv/${name} on linux, an ordinary name,`,
    () => ({ localPath: `/srv/${name}`, platform: "linux" }),
  ]),
];

const NOT_ALLOWED_THROUGH_A_LINK: readonly Case[] = [
  [
    "a link inside the directory that points outside",
    () => ({ localPath: join(fx.listed, "escape") }),
  ],
  [
    "a download onto a link that points outside",
    () => ({ operation: "download", localPath: join(fx.listed, "escape") }),
  ],
  [
    "a download onto a dangling link that points outside",
    () => ({ operation: "download", localPath: join(fx.listed, "dangling") }),
  ],
  [
    "a link whose resolved target holds a backslash",
    () => ({ localPath: join(fx.listed, "backslash-link") }),
  ],
];

const RESOLVED_NAMES_NOT_WRITTEN_AS_STORED: ReadonlyArray<readonly [string, string]> = [
  ["U+FFFD", "rep\uFFFDrt.pdf"],
  ["an unpaired high surrogate", "rep\uD83Drt.pdf"],
  ["an unpaired low surrogate", "rep\uDCC4rt.pdf"],
];

const RESOLVED_NAMES_WRITTEN_AS_STORED: ReadonlyArray<readonly [string, string]> = [
  ["a letter outside ASCII", "résumé.pdf"],
  ["a surrogate pair", "report-\uD83D\uDCC4.pdf"],
];

/** Runs `run` while `realpath` answers `<listed>/<name>` for the fixture's report. */
async function withResolvedName<T>(name: string, run: () => Promise<T>): Promise<T> {
  const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
  const given = join(fx.listed, "report.pdf");
  vi.mocked(realpath).mockImplementation(async (path, options) => {
    if (path === given) return join(fx.listed, name);
    return actual.realpath(path, options);
  });
  try {
    return await run();
  } finally {
    vi.mocked(realpath).mockImplementation(actual.realpath);
  }
}

function grantUsers(dir: string, rights: string): void {
  const res = spawnSync(
    system32Path("icacls.exe"),
    [dir, "/grant", `*${USERS}:(OI)(CI)${rights}`],
    { shell: false, windowsHide: true, timeout: 15_000 },
  );
  expect(res.status).toBe(0);
}

const LISTED_BY_A_REFUSED_SPELLING: ReadonlyArray<readonly [string, string]> = [
  ["a glob character", "listed[link]"],
  ["a backslash", `listed${B}link`],
];

const INVALID: ReadonlyArray<readonly [string, () => Partial<Input>, string]> = [
  ["a relative path", () => ({ localPath: "report.pdf" }), MUST_BE_ABSOLUTE],
  ["a number", () => ({ localPath: 5 }), MUST_BE_ABSOLUTE],
  ["a glob character", () => ({ localPath: join(fx.listed, "*.pdf") }), NO_GLOB],
  [
    "a download onto an existing directory",
    () => ({ operation: "download", localPath: join(fx.listed, "sub") }),
    MUST_NAME_A_FILE,
  ],
  ["C:x on win32", () => ({ localPath: "C:x", platform: "win32" }), MUST_BE_ABSOLUTE],
  ["/x on win32", () => ({ localPath: "/x", platform: "win32" }), MUST_BE_ABSOLUTE],
  ["//server on win32", () => ({ localPath: "//server", platform: "win32" }), MUST_BE_ABSOLUTE],
  ["///x on win32", () => ({ localPath: "///x", platform: "win32" }), MUST_BE_ABSOLUTE],
  [`${B}${B}. on win32`, () => ({ localPath: `${B}${B}.`, platform: "win32" }), MUST_BE_ABSOLUTE],
  [
    `${B}${B}server${B}share${B}f on win32`,
    () => ({ localPath: `${B}${B}server${B}share${B}f`, platform: "win32" }),
    NAMES_A_SHARE,
  ],
  [
    `${B}${B}.${B}C:${B}f on win32`,
    () => ({ localPath: `${B}${B}.${B}C:${B}f`, platform: "win32" }),
    NAMES_A_DEVICE,
  ],
  [
    "/proc/self/environ on linux",
    () => ({ localPath: "/proc/self/environ", platform: "linux" }),
    NAMES_A_DEVICE,
  ],
  [
    "a backslash on linux",
    () => ({ localPath: `/srv/reports/escap${B}e`, platform: "linux" }),
    NO_GLOB,
  ],
  onWin32("name.", READ_DIFFERENTLY),
  onWin32("name ", READ_DIFFERENTLY, "name and a trailing space"),
  onWin32(`sub.${B}f`, READ_DIFFERENTLY),
  onWin32("f.txt:stream", READ_DIFFERENTLY),
  onWin32("NUL", NAMES_A_DEVICE),
  onWin32("nul.txt", NAMES_A_DEVICE),
  onWin32("nul.tar.gz", NAMES_A_DEVICE),
  onWin32("NUL .txt", NAMES_A_DEVICE),
  onWin32("COM1", NAMES_A_DEVICE),
  onWin32(`con${B}f`, NAMES_A_DEVICE),
  onWin32("CONOUT$", NAMES_A_DEVICE),
  onWin32("COM¹", NAMES_A_DEVICE),
  ...[
    "PRN",
    "AUX",
    "COM0",
    "COM2",
    "COM9",
    "LPT0",
    "LPT1",
    "LPT9",
    "CONIN$",
    "COM²",
    "COM³",
    "LPT¹",
    "LPT²",
    "LPT³",
  ].map((name) => onWin32(name, NAMES_A_DEVICE)),
];

const WIN32_DOWNLOADS_WITH_A_TRAILING_DOT: readonly Case[] = [
  [
    "the vault directory, whose parent is listed,",
    () => ({ localPath: `${fx.vault}.`, allowedDirs: [fx.root] }),
  ],
  ["a junction to the outside", () => ({ localPath: `${join(fx.listed, "junc")}.` })],
  ["an existing file", () => ({ localPath: `${join(fx.listed, "report.pdf")}.` })],
];

describe("resolveSftpLocalPath", () => {
  it("an upload inside a listed directory returns its resolved path", async () => {
    await expect(
      resolveSftpLocalPath(input({ localPath: viaSub(fx.listed, "report.pdf") })),
    ).resolves.toBe(join(fx.listed, "report.pdf"));
  });

  it.skipIf(process.platform === "win32")("a listed directory given by a link", async () => {
    await expect(
      resolveSftpLocalPath(
        input({ localPath: join(fx.link, "report.pdf"), allowedDirs: [fx.link] }),
      ),
    ).resolves.toBe(join(fx.listed, "report.pdf"));
  });

  it("a download to a new file returns the resolved directory joined with the name", async () => {
    await expect(
      resolveSftpLocalPath(
        input({ operation: "download", localPath: viaSub(fx.listed, "new.pdf") }),
      ),
    ).resolves.toBe(join(fx.listed, "new.pdf"));
  });

  it("a download onto an existing file inside a listed directory is allowed", async () => {
    await expect(resolveSftpLocalPath(input({ operation: "download" }))).resolves.toBe(
      join(fx.listed, "report.pdf"),
    );
  });

  it.each(NOT_ALLOWED)("refuses %s as not allowed", async (_label, overrides) => {
    await expectVaultError(
      () => resolveSftpLocalPath(input(overrides())),
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    );
  });

  it.skipIf(process.platform === "win32").each(NOT_ALLOWED_THROUGH_A_LINK)(
    "refuses %s as not allowed",
    async (_label, overrides) => {
      await expectVaultError(
        () => resolveSftpLocalPath(input(overrides())),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
    },
  );

  it.skipIf(process.platform === "win32").each(LISTED_BY_A_REFUSED_SPELLING)(
    "a listed directory given by a link whose name holds %s matches nothing",
    async (_label, name) => {
      await expectVaultError(
        () => resolveSftpLocalPath(input({ allowedDirs: [join(fx.root, name)] })),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
    },
  );

  it.runIf(process.platform === "win32")(
    "a listed directory given through the win32 device namespace matches nothing",
    async () => {
      await expectVaultError(
        () => resolveSftpLocalPath(input({ allowedDirs: [`${B}${B}?${B}${fx.listed}`] })),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
    },
  );

  it("an unreadable vault directory refuses the use", async () => {
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    const denied = Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
    vi.mocked(realpath).mockImplementation(async (path, options) => {
      if (path === fx.vault) throw denied;
      return actual.realpath(path, options);
    });
    try {
      await expectVaultError(() => resolveSftpLocalPath(input()), ErrorCode.LOCAL_PATH_NOT_ALLOWED);
    } finally {
      vi.mocked(realpath).mockImplementation(actual.realpath);
    }
  });

  it.each(RESOLVED_NAMES_NOT_WRITTEN_AS_STORED)(
    "refuses a file whose resolved name holds %s as not allowed",
    async (_label, name) => {
      await withResolvedName(name, () =>
        expectVaultError(() => resolveSftpLocalPath(input()), ErrorCode.LOCAL_PATH_NOT_ALLOWED),
      );
    },
  );

  it.each(RESOLVED_NAMES_WRITTEN_AS_STORED)(
    "returns a resolved name that holds %s",
    async (_label, name) => {
      await withResolvedName(name, () =>
        expect(resolveSftpLocalPath(input())).resolves.toBe(join(fx.listed, name)),
      );
    },
  );

  // Linux alone: APFS refuses to create a name that is not UTF-8, and a win32 name is UTF-16.
  it.runIf(process.platform === "linux")(
    "linux: refuses an upload through a link to a file whose name is not UTF-8",
    async () => {
      const stored = Buffer.concat([Buffer.from(join(fx.listed, "stored-")), Buffer.from([0xff])]);
      writeFileSync(stored, "report");
      symlinkSync(stored, join(fx.listed, "to-stored"));
      try {
        await expectVaultError(
          () => resolveSftpLocalPath(input({ localPath: join(fx.listed, "to-stored") })),
          ErrorCode.LOCAL_PATH_NOT_ALLOWED,
        );
      } finally {
        unlinkSync(stored);
      }
    },
  );

  it("a path that does not exist and a path outside the list are refused with the same message", async () => {
    const a = await expectVaultError(
      () => resolveSftpLocalPath(input({ localPath: join(fx.listed, "missing.pdf") })),
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    );
    const b = await expectVaultError(
      () => resolveSftpLocalPath(input({ localPath: join(fx.outside, "secret.txt") })),
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    );
    expect(a.message).toBe(b.message);
  });

  it.each(INVALID)(
    "refuses %s as invalid input, with its message",
    async (_label, overrides, message) => {
      const err = await expectVaultError(
        () => resolveSftpLocalPath(input(overrides())),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(message);
    },
  );

  it("judges a network share before any file-system call", async () => {
    vi.mocked(realpath).mockClear();
    vi.mocked(lstat).mockClear();
    vi.mocked(stat).mockClear();
    const err = await expectVaultError(
      () =>
        resolveSftpLocalPath(
          input({ localPath: `${B}${B}server${B}share${B}f`, platform: "win32" }),
        ),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(NAMES_A_SHARE);
    expect(realpath).not.toHaveBeenCalled();
    expect(lstat).not.toHaveBeenCalled();
    expect(stat).not.toHaveBeenCalled();
  });

  it("judges a name Windows reads differently before any file-system call", async () => {
    vi.mocked(realpath).mockClear();
    vi.mocked(lstat).mockClear();
    vi.mocked(stat).mockClear();
    for (const name of ["name.", "name ", "f.txt:stream", "NUL"]) {
      await expectVaultError(
        () => resolveSftpLocalPath(input({ localPath: `C:${B}d${B}${name}`, platform: "win32" })),
        ErrorCode.INVALID_INPUT,
      );
    }
    expect(realpath).not.toHaveBeenCalled();
    expect(lstat).not.toHaveBeenCalled();
    expect(stat).not.toHaveBeenCalled();
  });

  it.runIf(process.platform === "win32").each(WIN32_DOWNLOADS_WITH_A_TRAILING_DOT)(
    "win32: refuses a download onto %s spelled with a trailing dot",
    async (_label, overrides) => {
      const err = await expectVaultError(
        () => resolveSftpLocalPath(input({ operation: "download", ...overrides() })),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(READ_DIFFERENTLY);
    },
  );

  it.runIf(process.platform === "win32").each([
    ["whose name ends in a dot", "to-dotted"],
    ["with a device's name", "to-con"],
  ])("win32: refuses an upload through a junction to a directory %s", async (_label, junction) => {
    await expectVaultError(
      () => resolveSftpLocalPath(input({ localPath: join(fx.listed, junction, "report.pdf") })),
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    );
  });

  it.runIf(process.platform === "win32")(
    "win32: a listed directory given by a junction whose name ends in a dot matches nothing",
    async () => {
      await expectVaultError(
        () => resolveSftpLocalPath(input({ allowedDirs: [join(fx.root, "listed-junction.")] })),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
    },
  );

  it("refuses a file in the vault directory spelled in another case", async (ctx) => {
    // A case-sensitive file system has no second spelling of the directory.
    if (!fx.caseInsensitive) return ctx.skip();
    await expectVaultError(
      () =>
        resolveSftpLocalPath(
          input({
            localPath: join(fx.caseParent, "VAULT", "vault.db"),
            allowedDirs: [fx.caseParent],
            vaultFiles: [join(fx.caseParent, "Vault", "vault.db")],
          }),
        ),
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    );
  });

  it("a declared directory is under the floor whatever is listed", async () => {
    const localPath = join(fx.listed, "sub", "held.pdf");
    await expect(resolveSftpLocalPath(input({ localPath }))).resolves.toBe(localPath);
    await expectVaultError(
      () =>
        resolveSftpLocalPath(
          input({
            localPath,
            daemon: { protectedDirs: [join(fx.listed, "sub")], protectedFiles: [] },
          }),
        ),
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    );
  });

  it("a declared file is under the floor, its neighbours are not", async () => {
    const daemon: DaemonPaths = { protectedDirs: [], protectedFiles: [join(fx.listed, "key")] };
    await expectVaultError(
      () => resolveSftpLocalPath(input({ localPath: join(fx.listed, "key"), daemon })),
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    );
    await expect(
      resolveSftpLocalPath(input({ localPath: join(fx.listed, "other"), daemon })),
    ).resolves.toBe(join(fx.listed, "other"));
  });

  it("a declared path that does not exist yet refuses nothing else", async () => {
    const daemon: DaemonPaths = {
      protectedDirs: [join(fx.listed, "not-yet")],
      protectedFiles: [join(fx.listed, "not-yet.key")],
    };
    await expect(resolveSftpLocalPath(input({ daemon }))).resolves.toBe(
      join(fx.listed, "report.pdf"),
    );
    await expect(
      resolveSftpLocalPath(
        input({ operation: "download", localPath: join(fx.listed, "new.pdf"), daemon }),
      ),
    ).resolves.toBe(join(fx.listed, "new.pdf"));
    await expectVaultError(
      () =>
        resolveSftpLocalPath(
          input({ operation: "download", localPath: join(fx.listed, "not-yet.key"), daemon }),
        ),
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    );
  });

  // A symbolic link needs a privilege a win32 host may not grant.
  it.skipIf(WIN32)(
    "a declared file that does not exist yet is under the floor through a link in its path",
    async () => {
      const daemon: DaemonPaths = {
        protectedDirs: [],
        protectedFiles: [join(fx.listed, "link", "key")],
      };
      await expectVaultError(
        () =>
          resolveSftpLocalPath(
            input({ operation: "download", localPath: join(fx.listed, "real", "key"), daemon }),
          ),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
      await expect(
        resolveSftpLocalPath(
          input({ operation: "download", localPath: join(fx.listed, "real", "other"), daemon }),
        ),
      ).resolves.toBe(join(fx.listed, "real", "other"));
    },
  );

  // A symbolic link needs a privilege a win32 host may not grant.
  it.skipIf(WIN32)(
    "a declared directory that does not exist yet is under the floor through a link in its path",
    async () => {
      const daemon: DaemonPaths = {
        protectedDirs: [join(fx.listed, "link", "sub", "deep")],
        protectedFiles: [],
      };
      const download = (...names: string[]): Promise<string> =>
        resolveSftpLocalPath(
          input({ operation: "download", localPath: join(fx.listed, "real", ...names), daemon }),
        );
      await expect(download("sub2", "x")).resolves.toBe(join(fx.listed, "real", "sub2", "x"));
      mkdirSync(join(fx.listed, "real", "sub"), { mode: 0o755 });
      await expectVaultError(() => download("sub", "deep"), ErrorCode.LOCAL_PATH_NOT_ALLOWED);
      mkdirSync(join(fx.listed, "real", "sub", "deep"), { recursive: true, mode: 0o755 });
      await expectVaultError(() => download("sub", "deep", "x"), ErrorCode.LOCAL_PATH_NOT_ALLOWED);
    },
  );

  it.skipIf(WIN32)(
    "with a daemon a file in a 0775 listed directory refuses, without one it resolves (POSIX modes)",
    async () => {
      const dir = join(fx.root, "group-writable");
      mkdirSync(dir);
      chmodSync(dir, 0o775);
      const localPath = join(dir, "report.pdf");
      writeFileSync(localPath, "report");
      await expect(resolveSftpLocalPath(input({ localPath, allowedDirs: [dir] }))).resolves.toBe(
        localPath,
      );
      await expectVaultError(
        () => resolveSftpLocalPath(input({ localPath, allowedDirs: [dir], daemon: NO_PATHS })),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
    },
  );

  it.skipIf(WIN32)(
    "with a daemon a file in a 0777 subdirectory of a 0755 listed directory refuses (POSIX modes)",
    async () => {
      const dir = join(fx.root, "held");
      const open = join(dir, "open");
      mkdirSync(open, { recursive: true });
      chmodSync(dir, 0o755);
      chmodSync(open, 0o777);
      const localPath = join(open, "report.pdf");
      writeFileSync(localPath, "report");
      await expectVaultError(
        () => resolveSftpLocalPath(input({ localPath, allowedDirs: [dir], daemon: NO_PATHS })),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
    },
  );

  it.skipIf(WIN32)(
    "with a daemon a download of a new name straight into a listed sticky world-writable directory refuses (POSIX modes)",
    async () => {
      const sticky = realpathSync(STICKY_DIR);
      expect(statSync(sticky).mode & 0o1002).toBe(0o1002);
      await expectVaultError(
        () =>
          resolveSftpLocalPath(
            input({
              operation: "download",
              localPath: join(sticky, `harpoc-local-path-${randomUUID()}.pdf`),
              allowedDirs: [sticky],
              daemon: NO_PATHS,
            }),
          ),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
    },
  );

  it.skipIf(WIN32)(
    "with a daemon a file in a 0700 directory under a listed sticky directory resolves (POSIX modes)",
    async () => {
      const sticky = realpathSync(STICKY_DIR);
      const dir = mkdtempSync(join(sticky, "harpoc-local-path-sticky-"));
      try {
        chmodSync(dir, 0o700);
        const localPath = join(dir, "report.pdf");
        writeFileSync(localPath, "report");
        await expect(
          resolveSftpLocalPath(input({ localPath, allowedDirs: [sticky], daemon: NO_PATHS })),
        ).resolves.toBe(localPath);
      } finally {
        rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    },
  );

  it.runIf(WIN32)(
    "win32: with a daemon a file in a fresh directory under the temporary directory resolves, and refuses once icacls gave Users modify",
    async () => {
      const dir = join(fx.root, "granted");
      mkdirSync(dir);
      const localPath = join(dir, "report.pdf");
      writeFileSync(localPath, "report");
      const judged = input({ localPath, allowedDirs: [dir], daemon: NO_PATHS });
      await expect(resolveSftpLocalPath(judged)).resolves.toBe(localPath);
      grantUsers(dir, "M");
      await expectVaultError(() => resolveSftpLocalPath(judged), ErrorCode.LOCAL_PATH_NOT_ALLOWED);
    },
  );
});

function judgement(overrides: Partial<LocalPathInput>): LocalPathInput {
  return {
    localPath: join(fx.listed, "report.pdf"),
    access: "read",
    allowedDirs: [fx.listed],
    vaultFiles: [join(fx.vault, "vault.db"), join(fx.vault, "session.json")],
    refuseGlob: true,
    ...overrides,
  };
}

describe("judgeLocalPath: a path that does not resolve", () => {
  it("a read of a missing file inside the vault's directory is protected", async () => {
    await expect(
      judgeLocalPath(judgement({ localPath: join(fx.vault, "missing.db") })),
    ).resolves.toEqual({ refusal: "protected" });
  });

  it("a read of a missing file inside a declared directory is protected", async () => {
    await expect(
      judgeLocalPath(
        judgement({
          localPath: join(fx.listed, "sub", "missing.pdf"),
          daemon: { protectedDirs: [join(fx.listed, "sub")], protectedFiles: [] },
        }),
      ),
    ).resolves.toEqual({ refusal: "protected" });
  });

  it("a read of a missing file outside the floor is not allowed", async () => {
    await expect(
      judgeLocalPath(judgement({ localPath: join(fx.outside, "missing.txt") })),
    ).resolves.toEqual({ refusal: "not_allowed" });
  });

  // On win32 a path through a regular file fails ENOENT as a missing name does; off win32 it fails ENOTDIR.
  it.skipIf(WIN32)(
    "a read through a regular file inside the vault's directory is protected",
    async () => {
      await expect(
        judgeLocalPath(judgement({ localPath: join(fx.vault, "vault.db", "x") })),
      ).resolves.toEqual({ refusal: "protected" });
    },
  );

  // On win32 a path through a regular file fails ENOENT as a missing name does; off win32 it fails ENOTDIR.
  it.skipIf(WIN32)("a read through a regular file outside the floor is not allowed", async () => {
    await expect(
      judgeLocalPath(judgement({ localPath: join(fx.outside, "secret.txt", "x") })),
    ).resolves.toEqual({ refusal: "not_allowed" });
  });

  it("a write whose parent directory does not exist, under the floor, is protected", async () => {
    await expect(
      judgeLocalPath(
        judgement({ access: "write", localPath: join(fx.vault, "nowhere", "new.db") }),
      ),
    ).resolves.toEqual({ refusal: "protected" });
  });
});

describe("judgeLocalPath: a path that names a device", () => {
  it("on win32 a reserved name on a share is a device, any other name there a network share", async () => {
    await expect(
      judgeLocalPath(judgement({ localPath: "//server/share/NUL", platform: "win32" })),
    ).resolves.toEqual({ refusal: "device" });
    await expect(
      judgeLocalPath(judgement({ localPath: "//server/share/f", platform: "win32" })),
    ).resolves.toEqual({ refusal: "network_share" });
  });

  // win32 has no /dev, and a symbolic link needs a privilege a win32 host may not grant.
  it.skipIf(WIN32)(
    "a read through a listed directory that is a link to /dev is not allowed",
    async () => {
      const link = join(fx.root, "to-dev");
      symlinkSync("/dev", link);
      await expect(
        judgeLocalPath(judgement({ localPath: join(link, "zero"), allowedDirs: [link] })),
      ).resolves.toEqual({ refusal: "not_allowed" });
    },
  );
});
