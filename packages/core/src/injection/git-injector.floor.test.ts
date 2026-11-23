import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { lstat, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join, sep } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs } from "./allowlist.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import type { readGitVersion } from "./git-injector-version.js";
import { GitInjector } from "./git-injector.js";
import type { DaemonPaths } from "./local-path.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { system32Path } from "../win32-paths.js";
import { expectVaultError } from "@harpoc/test-utils";

const readVersion = vi.hoisted(() => vi.fn<typeof readGitVersion>());

vi.mock("./git-injector-version.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./git-injector-version.js")>();
  return { ...actual, readGitVersion: readVersion };
});
vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, statSync: vi.fn(actual.statSync) };
});
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, realpath: vi.fn(actual.realpath), lstat: vi.fn(actual.lstat) };
});

// On win32 the git context accepts only the native Win32-OpenSSH client, so its
// directory leads the PATH (as in git-injector.audit.test.ts).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const GIT = resolveSupportedGit();
const SSH = resolveNativeSshClient("ssh");

const HTTPS_REPOSITORY = "https://8.8.8.8/org/repo.git";
const SSH_HOST = "allowed.invalid";
const SSH_REPOSITORY = `git@${SSH_HOST}:org/repo.git`;
const PINNED: ConnectionConfig = {
  ssh: { known_hosts: [`${SSH_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`] },
};
const SECRET = new Uint8Array(Buffer.from("git-user:floor-token-value"));
const PROTECTED = "git working directory is inside a directory the vault protects";
const DAEMON_CLONE = "working_directory is required for clone in a daemon";
const NAMES_A_SHARE = "working_directory names a network share";
const DOT_SEGMENT = "working_directory must not hold a .. segment";
const NO_PATHS: DaemonPaths = { protectedDirs: [], protectedFiles: [] };

const FAILED_STEP: SpawnCapturedResult = {
  exit_code: 1,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

const OK_STEP: SpawnCapturedResult = { ...FAILED_STEP, exit_code: 0 };

const TREE_OPERATIONS = ["pull", "push", "fetch"] as const;
const NAMED_OPERATIONS = ["clone", ...TREE_OPERATIONS] as const;
const WIN32 = process.platform === "win32";
const PATH_LIMITS = [1024, 4096];

const SHARE_SPELLINGS = [
  "\\\\server\\share\\repo",
  "//server/share/repo",
  "\\\\?\\UNC\\server\\share\\repo",
  "\\\\wsl$\\Ubuntu\\home\\repo",
  "\\\\.\\UNC\\server\\share\\repo",
  "//./UNC/server/share/repo",
  "\\\\?\\GLOBALROOT\\Device\\Mup\\server\\share\\repo",
  "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\repo",
  "\\\\.\\C:\\..\\UNC\\server\\share\\repo",
];
const SHARE_CASES = NAMED_OPERATIONS.flatMap((operation) =>
  SHARE_SPELLINGS.map((spelled) => [operation, spelled] as const),
);

const DOT_SEGMENT_CASES: ReadonlyArray<
  readonly [string, (typeof NAMED_OPERATIONS)[number], (root: string) => string]
> = [
  ...NAMED_OPERATIONS.flatMap((operation) => [
    [
      `${operation}, absolute`,
      operation,
      (r: string) => `${r}${sep}agent${sep}..${sep}tree`,
    ] as const,
    ...(WIN32
      ? [
          [
            `${operation}, absolute, spelled with /`,
            operation,
            (r: string) => `${r}/agent/../tree`,
          ] as const,
        ]
      : []),
  ]),
  ["clone, relative", "clone", () => `..${sep}tree`],
  ...(WIN32 ? [["clone, relative, spelled with /", "clone", () => "../tree"] as const] : []),
];

const UNDER_THE_FLOOR = [
  ["a file", "file"],
  ["a missing name", "missing"],
] as const;
const UNDER_THE_FLOOR_CASES = TREE_OPERATIONS.flatMap((operation) =>
  UNDER_THE_FLOOR.map(([label, name]) => [operation, label, name] as const),
);

const OUTSIDE_THE_FLOOR = [
  ["a missing name", "absent", "working_directory does not exist"],
  ["a file", "file", "working_directory is not a directory"],
] as const;
const OUTSIDE_THE_FLOOR_CASES = TREE_OPERATIONS.flatMap((operation) =>
  OUTSIDE_THE_FLOOR.map(([label, name, message]) => [operation, label, name, message] as const),
);

function leadsWithTwoSeparators(path: unknown): boolean {
  return /^[\\/]{2}/.test(String(path));
}

function notThere(): NodeJS.ErrnoException {
  return Object.assign(new Error("ENOENT: no such file or directory"), { code: "ENOENT" });
}

function shareSpellingsTouched(): string[] {
  return [
    ...vi.mocked(statSync).mock.calls,
    ...vi.mocked(realpath).mock.calls,
    ...vi.mocked(lstat).mock.calls,
  ]
    .map(([path]) => String(path))
    .filter(leadsWithTwoSeparators);
}

/** `<dir>/<name><behind>` with `.` steps in front of the name, `length` characters long: the name is "link", or "links" where that takes the odd character. */
function padded(length: number, dir: string, behind = ""): { name: string; spelled: string } {
  const room = length - dir.length - 1 - "link".length - behind.length;
  const name = room % 2 === 0 ? "link" : "links";
  return { name, spelled: `${dir}/${"./".repeat(Math.floor(room / 2))}${name}${behind}` };
}

function gitSubcommand(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === "-c") i++;
    else if (!a.startsWith("-")) return a;
  }
  return undefined;
}

function policy(): InjectionPolicy {
  return {
    url_allowlist: ["https://8.8.8.8/*"],
    command_allowlist: [GIT as string],
    env_allowlist: [],
    host_allowlist: [SSH_HOST],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    proxy: false,
    ssh_agent_socket: false,
    local_dirs: [],
  };
}

const spawnMock = vi.mocked(spawnCaptured);
let root: string;
let vaultDir: string;
let log: Mock;

beforeEach(() => {
  // `.native` like the judgement's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-floor-")));
  vaultDir = join(root, "vault");
  mkdirSync(join(vaultDir, "tree"), { recursive: true });
  log = vi.fn();
  readVersion.mockReset();
  readVersion.mockResolvedValue({ major: 2, minor: 51, patch: 0 });
  spawnMock.mockReset();
  spawnMock.mockResolvedValue(FAILED_STEP);
});

afterEach(() => {
  spawnMock.mockReset();
  readVersion.mockReset();
  rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function use(action: GitAction, daemon?: DaemonPaths) {
  return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
    action,
    SECRET,
    policy(),
    PINNED,
    "secret-1",
    undefined,
    {
      vaultFiles: [join(vaultDir, "vault.db"), join(vaultDir, "session.json")],
      ...(daemon !== undefined ? { daemon } : {}),
    },
  );
}

async function expectProtected(
  action: GitAction,
  row: Record<string, unknown> = {},
  daemon?: DaemonPaths,
): Promise<void> {
  const err = await expectVaultError(() => use(action, daemon), ErrorCode.LOCAL_PATH_NOT_ALLOWED);
  expect(err.message).toBe(PROTECTED);
  expect(log.mock.calls).toEqual([
    [
      {
        eventType: "secret.use",
        secretId: "secret-1",
        detail: {
          context: "git",
          operation: action.operation,
          ...row,
          error: "LOCAL_PATH_NOT_ALLOWED",
        },
        success: false,
      },
    ],
  ]);
  expect(readVersion).toHaveBeenCalledTimes(1);
  expect(spawnMock).not.toHaveBeenCalled();
}

async function expectInvalid(
  action: GitAction,
  message: string,
  row: Record<string, unknown> = {},
  daemon?: DaemonPaths,
): Promise<void> {
  const err = await expectVaultError(() => use(action, daemon), ErrorCode.INVALID_GIT_CONFIG);
  expect(err.message).toBe(message);
  expect(log.mock.calls).toEqual([
    [
      {
        eventType: "secret.use",
        secretId: "secret-1",
        detail: {
          context: "git",
          operation: action.operation,
          ...row,
          error: "INVALID_GIT_CONFIG",
        },
        success: false,
      },
    ],
  ]);
  expect(readVersion).toHaveBeenCalledTimes(1);
  expect(spawnMock).not.toHaveBeenCalled();
}

async function expectRefusedInDaemon(
  repository: string,
  row: Record<string, unknown> = {},
  daemon: DaemonPaths = NO_PATHS,
): Promise<void> {
  const err = await expectVaultError(
    () => use({ type: "git", operation: "clone", repository }, daemon),
    ErrorCode.INVALID_GIT_CONFIG,
  );
  expect(err.message).toBe(DAEMON_CLONE);
  expect(log.mock.calls).toEqual([
    [
      {
        eventType: "secret.use",
        secretId: "secret-1",
        detail: { context: "git", operation: "clone", ...row, error: "INVALID_GIT_CONFIG" },
        success: false,
      },
    ],
  ]);
  expect(readVersion).toHaveBeenCalledTimes(1);
  expect(spawnMock).not.toHaveBeenCalled();
}

async function cloneDestination(
  workingDirectory: string,
  daemon?: DaemonPaths,
): Promise<string | undefined> {
  spawnMock.mockResolvedValue(OK_STEP);
  const result = await use(
    {
      type: "git",
      operation: "clone",
      repository: HTTPS_REPOSITORY,
      working_directory: workingDirectory,
    },
    daemon,
  );
  expect(result.exit_code).toBe(0);
  const calls = spawnMock.mock.calls as Parameters<typeof spawnCaptured>[];
  expect(calls.map(([, args]) => gitSubcommand(args))).toEqual(["ls-remote", "fetch", "clone"]);
  const [, args, opts] = calls[2] as Parameters<typeof spawnCaptured>;
  expect(opts.cwd).toBeUndefined();
  const tail = args.slice(args.indexOf("clone"));
  expect(tail.slice(0, 3)).toEqual(["clone", "--", HTTPS_REPOSITORY]);
  expect(tail).toHaveLength(4);
  return tail[3];
}

/** `dir` holding a `.git` with a git directory's shape: `HEAD`, `objects`, `refs`. */
function repository(dir: string): string {
  mkdirSync(join(dir, ".git", "objects"), { recursive: true });
  mkdirSync(join(dir, ".git", "refs"));
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  return dir;
}

async function treeDirectory(
  operation: (typeof TREE_OPERATIONS)[number],
  workingDirectory: string,
): Promise<string | undefined> {
  await expectVaultError(
    () =>
      use({
        type: "git",
        operation,
        repository: HTTPS_REPOSITORY,
        working_directory: workingDirectory,
      }),
    ErrorCode.GIT_OPERATION_FAILED,
  );
  expect(spawnMock).toHaveBeenCalledTimes(1);
  const [, args, opts] = spawnMock.mock.calls[0] as Parameters<typeof spawnCaptured>;
  expect(gitSubcommand(args)).toBe("rev-parse");
  return opts.cwd;
}

describe.skipIf(GIT === null)(
  "the git context refuses a working tree inside a directory the vault protects (skipped where no supported git resolves)",
  () => {
    it.each(TREE_OPERATIONS)(
      "a pull, a push and a fetch whose working tree is inside the vault's directory are refused with one row: %s over HTTPS",
      async (operation) => {
        await expectProtected({
          type: "git",
          operation,
          repository: HTTPS_REPOSITORY,
          working_directory: join(vaultDir, "tree"),
        });
      },
    );

    it.skipIf(SSH === null).each(TREE_OPERATIONS)(
      "a pull, a push and a fetch whose working tree is inside the vault's directory are refused with one row: %s over SSH, the row naming the host (skipped where the native ssh client does not resolve)",
      async (operation) => {
        await expectProtected(
          {
            type: "git",
            operation,
            repository: SSH_REPOSITORY,
            working_directory: join(vaultDir, "tree"),
          },
          { host: SSH_HOST },
        );
      },
    );

    it("a clone into the vault's directory is refused, for a destination that does not exist yet", async () => {
      await expectProtected({
        type: "git",
        operation: "clone",
        repository: HTTPS_REPOSITORY,
        working_directory: join(vaultDir, "clone"),
      });
    });

    it("a clone whose destination lies two levels below the vault's directory, neither level existing yet, is refused", async () => {
      await expectProtected({
        type: "git",
        operation: "clone",
        repository: HTTPS_REPOSITORY,
        working_directory: join(vaultDir, "a", "b"),
      });
    });

    it("a clone without a working directory is judged by the process's own", async () => {
      const cwd = vi.spyOn(process, "cwd").mockReturnValue(vaultDir);
      try {
        await expectProtected({ type: "git", operation: "clone", repository: HTTPS_REPOSITORY });
        expect(cwd).toHaveBeenCalled();
      } finally {
        cwd.mockRestore();
      }
    });

    it("a clone whose working directory is relative is judged from the process's own", async () => {
      const cwd = vi.spyOn(process, "cwd").mockReturnValue(root);
      try {
        await expectProtected({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: "vault/clone",
        });
        expect(cwd).toHaveBeenCalled();
      } finally {
        cwd.mockRestore();
      }
    });

    it.each([
      ["without a working directory", undefined],
      ["with a relative working directory", "clone"],
    ])(
      "a clone %s is refused where the process's own cannot be read",
      async (_form, workingDirectory) => {
        const cwd = vi.spyOn(process, "cwd").mockImplementation(() => {
          throw new Error("ENOENT: no such file or directory, uv_cwd");
        });
        try {
          await expectProtected({
            type: "git",
            operation: "clone",
            repository: HTTPS_REPOSITORY,
            ...(workingDirectory !== undefined ? { working_directory: workingDirectory } : {}),
          });
          expect(cwd).toHaveBeenCalled();
        } finally {
          cwd.mockRestore();
        }
      },
    );

    // A symbolic link needs a privilege on win32.
    it.skipIf(process.platform === "win32")(
      "a working tree reached through a link into the vault's directory is refused",
      async () => {
        const link = join(root, "link");
        symlinkSync(join(vaultDir, "tree"), link, "dir");
        await expectProtected({
          type: "git",
          operation: "pull",
          repository: HTTPS_REPOSITORY,
          working_directory: link,
        });
      },
    );

    // A junction needs no privilege, and only win32 has one.
    it.runIf(process.platform === "win32")(
      "a working tree reached through a junction into the vault's directory is refused",
      async () => {
        const link = join(root, "junction");
        symlinkSync(join(vaultDir, "tree"), link, "junction");
        await expectProtected({
          type: "git",
          operation: "pull",
          repository: HTTPS_REPOSITORY,
          working_directory: link,
        });
      },
    );

    // Only the Win32 path layer drops a trailing dot or space from a name.
    it.runIf(process.platform === "win32").each([
      ["a trailing dot", "."],
      ["a trailing space", " "],
    ])(
      "a clone into the vault's directory spelled with %s is refused",
      async (_spelling, suffix) => {
        await expectProtected({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: join(`${vaultDir}${suffix}`, "clone"),
        });
      },
    );

    // Node makes the directory under the name as spelled; the Win32 path layer, which git's
    // working directory goes through, drops the dot.
    it.runIf(process.platform === "win32").each(["vault-beside.", "vault."])(
      "a pull whose working tree is a directory beside the vault's spelled with a trailing dot is refused: %s",
      async (name) => {
        const spelled = join(root, name);
        mkdirSync(spelled);
        await expectProtected({
          type: "git",
          operation: "pull",
          repository: HTTPS_REPOSITORY,
          working_directory: spelled,
        });
      },
    );

    // Only the Win32 path layer reads a colon in a name as a stream.
    it.runIf(process.platform === "win32")(
      "a clone whose destination holds a colon in a name is refused",
      async () => {
        await expectProtected({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: join(root, "vault:stream", "clone"),
        });
      },
    );

    // A symbolic link needs a privilege on win32, and only off win32 does the system resolve a
    // `..` behind a link from the link's target.
    it.skipIf(WIN32)(
      "a clone whose destination is spelled through a link into the vault's directory and `..` into a declared directory is refused, nothing written",
      async () => {
        const declared = join(root, "declared");
        mkdirSync(declared);
        mkdirSync(join(root, "agent"));
        const link = join(root, "agent", "link");
        symlinkSync(vaultDir, link, "dir");
        await expectInvalid(
          {
            type: "git",
            operation: "clone",
            repository: HTTPS_REPOSITORY,
            working_directory: `${link}/../declared/new`,
          },
          DOT_SEGMENT,
          {},
          { protectedDirs: [declared], protectedFiles: [] },
        );
        expect(readdirSync(declared)).toEqual([]);
        expect(readdirSync(join(root, "agent"))).toEqual(["link"]);
      },
    );

    // A symbolic link needs a privilege on win32, and only off win32 does the system resolve a
    // `..` behind a link from the link's target.
    it.skipIf(WIN32)(
      "a clone whose destination is spelled through a link into the vault's directory and `..` back into it is refused, nothing written",
      async () => {
        mkdirSync(join(root, "agent"));
        const link = join(root, "agent", "link");
        symlinkSync(join(vaultDir, "tree"), link, "dir");
        await expectProtected({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: `${link}/../clone`,
        });
        expect(readdirSync(vaultDir)).toEqual(["tree"]);
        expect(readdirSync(join(root, "agent"))).toEqual(["link"]);
      },
    );

    // A symbolic link needs a privilege on win32, and only off win32 does the system resolve a
    // `..` behind a link from the link's target.
    it.skipIf(WIN32).each(TREE_OPERATIONS)(
      "a working tree spelled through a link into the vault's directory and `..` is refused: %s",
      async (operation) => {
        mkdirSync(join(vaultDir, "other"));
        mkdirSync(join(root, "agent"));
        const link = join(root, "agent", "link");
        symlinkSync(join(vaultDir, "tree"), link, "dir");
        await expectProtected({
          type: "git",
          operation,
          repository: HTTPS_REPOSITORY,
          working_directory: `${link}/../other`,
        });
      },
    );

    // A symbolic link needs a privilege on win32, and only off win32 does the system resolve a
    // `..` behind a link from the link's target.
    it.skipIf(WIN32)(
      "a clone whose destination is spelled through a link and `..` that stay outside the floor runs, and git receives the resolved path",
      async () => {
        mkdirSync(join(root, "elsewhere", "deep"), { recursive: true });
        mkdirSync(join(root, "agent"));
        const link = join(root, "agent", "link");
        symlinkSync(join(root, "elsewhere", "deep"), link, "dir");
        expect(await cloneDestination(`${link}/../clone`)).toBe(join(root, "elsewhere", "clone"));
      },
    );

    // A symbolic link needs a privilege on win32, and only off win32 does the system resolve a
    // `..` behind a link from the link's target.
    it.skipIf(WIN32).each(TREE_OPERATIONS)(
      "a working tree spelled through a link and `..` that stay outside the floor runs, its steps in the resolved directory: %s",
      async (operation) => {
        mkdirSync(join(root, "elsewhere", "deep"), { recursive: true });
        repository(join(root, "elsewhere", "tree"));
        mkdirSync(join(root, "agent"));
        const link = join(root, "agent", "link");
        symlinkSync(join(root, "elsewhere", "deep"), link, "dir");
        expect(await treeDirectory(operation, `${link}/../tree`)).toBe(
          join(root, "elsewhere", "tree"),
        );
      },
    );

    // A symbolic link needs a privilege on win32.
    it.skipIf(WIN32)(
      "a working tree reached through a link outside the floor runs its steps in the link's target",
      async () => {
        repository(join(root, "elsewhere", "tree"));
        const link = join(root, "link");
        symlinkSync(join(root, "elsewhere", "tree"), link, "dir");
        expect(await treeDirectory("pull", link)).toBe(join(root, "elsewhere", "tree"));
      },
    );

    // A junction needs no privilege, and only win32 has one.
    it.runIf(WIN32)(
      "a working tree reached through a junction outside the floor runs its steps in the junction's target",
      async () => {
        repository(join(root, "elsewhere", "tree"));
        const junction = join(root, "junction");
        symlinkSync(join(root, "elsewhere", "tree"), junction, "junction");
        expect(await treeDirectory("pull", junction)).toBe(join(root, "elsewhere", "tree"));
      },
    );

    // A symbolic link needs a privilege on win32. The floor refuses each spelling before git
    // runs, whatever git would make of it.
    it.skipIf(WIN32).each([
      ["as the destination", (link: string) => link],
      ["as the destination, spelled with a trailing separator", (link: string) => `${link}/`],
      ["as the destination, spelled with a trailing `.` step", (link: string) => `${link}/.`],
      ["as a step of the destination", (link: string) => `${link}/clone`],
      ["behind a `..` that it would climb from", (link: string) => `${link}/../clone`],
    ])(
      "a clone through a link into the vault's directory that leads nowhere, %s, is refused, nothing written",
      async (_label, spell) => {
        mkdirSync(join(root, "agent"));
        const link = join(root, "agent", "link");
        symlinkSync(join(vaultDir, "new"), link, "dir");
        await expectProtected({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: spell(link),
        });
        expect(readdirSync(vaultDir)).toEqual(["tree"]);
        expect(readdirSync(join(root, "agent"))).toEqual(["link"]);
      },
    );

    // A symbolic link needs a privilege on win32.
    it.skipIf(WIN32).each([
      ["a link to a link that leads nowhere", (dir: string) => join(dir, "second")],
      ["a link to itself", (dir: string) => join(dir, "link")],
    ])("a clone whose destination is %s is refused", async (_label, target) => {
      const agent = join(root, "agent");
      mkdirSync(agent);
      symlinkSync(join(vaultDir, "new"), join(agent, "second"), "dir");
      symlinkSync(target(agent), join(agent, "link"), "dir");
      await expectProtected({
        type: "git",
        operation: "clone",
        repository: HTTPS_REPOSITORY,
        working_directory: join(agent, "link"),
      });
      expect(readdirSync(vaultDir)).toEqual(["tree"]);
    });

    // A junction needs no privilege, and only win32 has one.
    it.runIf(WIN32)(
      "a clone whose destination is a junction into the vault's directory that leads nowhere is refused, nothing written",
      async () => {
        mkdirSync(join(root, "agent"));
        const junction = join(root, "agent", "junction");
        symlinkSync(join(vaultDir, "new"), junction, "junction");
        await expectProtected({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: junction,
        });
        expect(readdirSync(vaultDir)).toEqual(["tree"]);
      },
    );

    // Off win32 the system cannot resolve a `..` behind a name that does not exist; the Win32
    // path layer collapses it by text before it looks at the disk.
    it.skipIf(WIN32).each([
      ["behind a directory that does not exist yet", "absent/../clone"],
      ["behind two levels that do not exist yet", "absent/deeper/../../clone"],
      ["as the last step, behind a directory that does not exist yet", "absent/clone/.."],
    ])("a clone whose destination holds a `..` %s is refused", async (_label, rest) => {
      await expectProtected({
        type: "git",
        operation: "clone",
        repository: HTTPS_REPOSITORY,
        working_directory: `${root}/${rest}`,
      });
      expect(readdirSync(root)).toEqual(["vault"]);
    });

    // Not on win32, which collapses the `..` by text, and not on darwin: Linux's kernel and
    // its realpath (glibc's and musl's) both answer ENOTDIR for a `..` behind a file, so the
    // `..` stands behind the last step that resolves. Darwin's realpath takes the `..` off the
    // file's name: there the spelling names the file's directory, and that directory is judged
    // and handed to git (local-path.spelled-directory.test.ts scripts it on every platform).
    it.skipIf(WIN32 || process.platform === "darwin")(
      "a clone whose destination holds a `..` behind a file is refused",
      async () => {
        writeFileSync(join(root, "file"), "");
        await expectProtected({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: `${root}/file/../clone`,
        });
        expect(readdirSync(root).sort()).toEqual(["file", "vault"]);
      },
    );

    // A symbolic link needs a privilege on win32. Whatever a system's realpath makes of a `..`
    // behind a file, a link that leads nowhere behind it is not handed to git.
    it.skipIf(WIN32)(
      "a clone whose destination is a link into the vault's directory that leads nowhere, spelled behind a file and `..`, is refused, nothing written",
      async () => {
        const agent = join(root, "agent");
        mkdirSync(agent);
        writeFileSync(join(agent, "file"), "");
        symlinkSync(join(vaultDir, "new"), join(agent, "link"), "dir");
        await expectProtected({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: `${agent}/file/../link`,
        });
        expect(readdirSync(vaultDir)).toEqual(["tree"]);
        expect(readdirSync(agent).sort()).toEqual(["file", "link"]);
      },
    );

    it.each([
      ["as it is", "vault-beside/clone"],
      ["with `.` steps and doubled separators", ".//vault-beside/.//clone"],
      ["with a `..` behind a directory that exists", "vault/../vault-beside/clone"],
    ])(
      "a clone whose working directory is relative, spelled %s, resolves against the process's own, and git receives the absolute path",
      async (_label, spelled) => {
        const cwd = vi.spyOn(process, "cwd").mockReturnValue(root);
        try {
          expect(await cloneDestination(spelled)).toBe(join(root, "vault-beside", "clone"));
          expect(cwd).toHaveBeenCalled();
        } finally {
          cwd.mockRestore();
        }
      },
    );

    it("a working tree spelled relative, with `.` steps and a doubled separator, resolves against the process's own: its steps run in the absolute directory", async () => {
      repository(join(root, "vault-beside"));
      const saved = process.cwd();
      process.chdir(root);
      try {
        expect(await treeDirectory("fetch", ".//vault-beside/.")).toBe(join(root, "vault-beside"));
      } finally {
        process.chdir(saved);
      }
    });

    it("an absolute destination spelled with `.` steps and doubled separators reaches git resolved", async () => {
      const spelled = [root, "", "vault-beside", ".", "", "clone"].join(sep);
      expect(await cloneDestination(spelled)).toBe(join(root, "vault-beside", "clone"));
    });

    // The Win32 path layer collapses a `..` by text before a junction is followed, so the
    // spelling that leaves a link's target off win32 stays beside the junction here.
    it.runIf(WIN32).each([
      ["as it is", ""],
      ["in the \\\\?\\ namespace", "\\\\?\\"],
      ["in the \\\\.\\ namespace", "\\\\.\\"],
    ])(
      "a clone whose destination is spelled through a junction into the vault's directory and `..`, %s, is read as Windows reads it: beside the junction, and git receives that path",
      async (_label, prefix) => {
        mkdirSync(join(root, "agent"));
        const junction = join(root, "agent", "junction");
        symlinkSync(join(vaultDir, "tree"), junction, "junction");
        expect(await cloneDestination(`${prefix}${junction}\\..\\clone`)).toBe(
          join(root, "agent", "clone"),
        );
      },
    );

    // Only the Win32 path layer collapses a `..` behind a name that does not exist.
    it.runIf(WIN32)(
      "a clone whose destination holds a `..` behind a directory that does not exist yet is read as Windows reads it: git receives the collapsed path",
      async () => {
        expect(await cloneDestination(`${root}\\absent\\..\\vault-beside\\clone`)).toBe(
          join(root, "vault-beside", "clone"),
        );
      },
    );

    // Node makes and resolves the directory under the name as stored; the Win32 path layer,
    // which reads the path git is handed, drops the dot and would land in the vault's directory.
    it.runIf(WIN32)(
      "a clone through a junction to a directory beside the vault's whose name ends in a dot is refused",
      async () => {
        mkdirSync(join(root, "vault."));
        mkdirSync(join(root, "agent"));
        const junction = join(root, "agent", "junction");
        symlinkSync(join(root, "vault."), junction, "junction");
        await expectProtected({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: join(junction, "clone"),
        });
      },
    );

    // Linux alone: APFS refuses to create a name that is not UTF-8, and a win32 name is UTF-16.
    it.runIf(process.platform === "linux")(
      "linux: a clone through a link to a directory whose name is not UTF-8 is refused: the resolved spelling would name another directory",
      async () => {
        const stored = Buffer.concat([Buffer.from(join(root, "stored-")), Buffer.from([0xff])]);
        mkdirSync(stored);
        const link = join(root, "link");
        symlinkSync(stored, link, "dir");
        try {
          await expectProtected({
            type: "git",
            operation: "clone",
            repository: HTTPS_REPOSITORY,
            working_directory: join(link, "clone"),
          });
        } finally {
          rmdirSync(stored);
        }
      },
    );

    // Off win32 the system refuses to read a spelling at its length limit, 1024 bytes on macOS
    // and 4096 on Linux, whatever it names; the Win32 path layer has collapsed the `.` steps
    // before the disk is read.
    it.skipIf(WIN32).each(PATH_LIMITS)(
      "a clone whose destination is a link into the vault's directory that leads nowhere, behind a spelling of %i characters of `.` steps, is refused, nothing started or written",
      async (length) => {
        const agent = join(root, "agent");
        mkdirSync(agent);
        const { name, spelled } = padded(length, agent);
        symlinkSync(join(vaultDir, "new"), join(agent, name), "dir");
        expect(spelled).toHaveLength(length);
        await expectProtected({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: spelled,
        });
        expect(readdirSync(vaultDir)).toEqual(["tree"]);
        expect(readdirSync(agent)).toEqual([name]);
      },
    );

    // As above, the link the last step and its target an empty directory, which a plain clone
    // fills. glibc's realpath walks a spelling of any length itself and finds the link, so on
    // Linux with glibc the floor refuses this with or without the rule that only a step that is
    // not there is climbed past. musl's realpath refuses a spelling of 4096 bytes and Darwin's
    // one of 1024, link and all: there the row holds by that rule.
    it.skipIf(WIN32).each(PATH_LIMITS)(
      "a clone whose destination is a link to an empty directory inside the vault's directory, behind a spelling of %i characters of `.` steps, is refused, nothing started or written",
      async (length) => {
        const agent = join(root, "agent");
        mkdirSync(agent);
        const { name, spelled } = padded(length, agent);
        symlinkSync(join(vaultDir, "tree"), join(agent, name), "dir");
        expect(spelled).toHaveLength(length);
        await expectProtected({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: spelled,
        });
        expect(readdirSync(join(vaultDir, "tree"))).toEqual([]);
      },
    );

    // As above; a relative spelling gains the process's directory in front.
    it.skipIf(WIN32).each(PATH_LIMITS)(
      "a clone whose relative destination reaches %i characters with the process's directory in front, and ends in a link that leads nowhere, is refused",
      async (length) => {
        const agent = join(root, "agent");
        mkdirSync(agent);
        const { name, spelled } = padded(length, agent);
        symlinkSync(join(vaultDir, "new"), join(agent, name), "dir");
        const cwd = vi.spyOn(process, "cwd").mockReturnValue(agent);
        try {
          await expectProtected({
            type: "git",
            operation: "clone",
            repository: HTTPS_REPOSITORY,
            working_directory: spelled.slice(agent.length + 1),
          });
          expect(cwd).toHaveBeenCalled();
        } finally {
          cwd.mockRestore();
        }
        expect(readdirSync(vaultDir)).toEqual(["tree"]);
      },
    );

    // POSIX non-root only: a symbolic link needs a privilege on win32 and a mode denies no
    // search there, and root searches a 0o000 directory.
    it.skipIf(WIN32 || process.getuid?.() === 0)(
      "a clone whose destination is a link that leads nowhere inside a directory the vault user may not search is refused",
      async () => {
        const locked = join(root, "locked");
        mkdirSync(locked);
        symlinkSync(join(vaultDir, "new"), join(locked, "link"), "dir");
        chmodSync(locked, 0o000);
        try {
          await expectProtected({
            type: "git",
            operation: "clone",
            repository: HTTPS_REPOSITORY,
            working_directory: join(locked, "link"),
          });
        } finally {
          chmodSync(locked, 0o700);
        }
        expect(readdirSync(vaultDir)).toEqual(["tree"]);
      },
    );

    it("a declared directory is refused as the vault's is", async () => {
      const declared = join(root, "declared");
      mkdirSync(join(declared, "tree"), { recursive: true });
      await expectProtected(
        {
          type: "git",
          operation: "pull",
          repository: HTTPS_REPOSITORY,
          working_directory: join(declared, "tree"),
        },
        {},
        { protectedDirs: [declared], protectedFiles: [] },
      );
    });

    it("in a daemon a clone without a working directory is refused with one row, no git step that touches a repository or the network, and the credential in no process: over HTTPS, the daemon declaring no path", async () => {
      await expectRefusedInDaemon(HTTPS_REPOSITORY);
    });

    it.skipIf(SSH === null)(
      "in a daemon a clone without a working directory is refused with one row, no git step that touches a repository or the network, and the credential in no process: over SSH, the row naming the host (skipped where the native ssh client does not resolve)",
      async () => {
        await expectRefusedInDaemon(SSH_REPOSITORY, { host: SSH_HOST });
      },
    );

    it("in a daemon a clone without a working directory is refused where the process's own directory holds an empty protected directory of the repository's name", async () => {
      const named = join(root, "repo");
      mkdirSync(named);
      const cwd = vi.spyOn(process, "cwd").mockReturnValue(root);
      try {
        await expectRefusedInDaemon(
          HTTPS_REPOSITORY,
          {},
          { protectedDirs: [named], protectedFiles: [] },
        );
        expect(readdirSync(named)).toEqual([]);
      } finally {
        cwd.mockRestore();
      }
    });

    it("in a daemon a clone without a working directory keeps an earlier refusal: a repository outside the allowlist is URL_NOT_ALLOWED", async () => {
      await expectVaultError(
        () =>
          use(
            { type: "git", operation: "clone", repository: "https://9.9.9.9/org/repo.git" },
            NO_PATHS,
          ),
        ErrorCode.URL_NOT_ALLOWED,
      );
      expect(readVersion).not.toHaveBeenCalled();
      expect(spawnMock).not.toHaveBeenCalled();
    });

    it("in a daemon a clone with a working directory outside the floor goes on to the step the suite scripts", async () => {
      const result = await use(
        {
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: join(root, "vault-beside", "clone"),
        },
        NO_PATHS,
      );
      expect(result.exit_code).toBe(1);
      expect(spawnMock).toHaveBeenCalledTimes(1);
      const [, args] = spawnMock.mock.calls[0] as Parameters<typeof spawnCaptured>;
      expect(gitSubcommand(args)).toBe("ls-remote");
    });

    it("without the daemon's paths a clone without a working directory, the process's own outside the floor, goes on to the step the suite scripts", async () => {
      const cwd = vi.spyOn(process, "cwd").mockReturnValue(root);
      try {
        const result = await use({
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
        });
        expect(result.exit_code).toBe(1);
        expect(cwd).toHaveBeenCalled();
        expect(spawnMock).toHaveBeenCalledTimes(1);
        const [, args] = spawnMock.mock.calls[0] as Parameters<typeof spawnCaptured>;
        expect(gitSubcommand(args)).toBe("ls-remote");
      } finally {
        cwd.mockRestore();
      }
    });

    it.each(TREE_OPERATIONS)(
      "a working tree beside the vault's directory passes the floor: %s goes on to the step the suite scripts",
      async (operation) => {
        const beside = repository(join(root, "vault-beside"));
        await expectVaultError(
          () =>
            use({
              type: "git",
              operation,
              repository: HTTPS_REPOSITORY,
              working_directory: beside,
            }),
          ErrorCode.GIT_OPERATION_FAILED,
        );
        expect(spawnMock).toHaveBeenCalledTimes(1);
        const [, args, opts] = spawnMock.mock.calls[0] as Parameters<typeof spawnCaptured>;
        expect(gitSubcommand(args)).toBe("rev-parse");
        expect(opts.cwd).toBe(beside);
      },
    );

    it("a clone beside the vault's directory passes the floor: it goes on to the step the suite scripts", async () => {
      const result = await use({
        type: "git",
        operation: "clone",
        repository: HTTPS_REPOSITORY,
        working_directory: join(root, "vault-beside", "clone"),
      });
      expect(result.exit_code).toBe(1);
      expect(spawnMock).toHaveBeenCalledTimes(1);
      const [, args] = spawnMock.mock.calls[0] as Parameters<typeof spawnCaptured>;
      expect(gitSubcommand(args)).toBe("ls-remote");
    });

    // The rule reads win32 spellings only. A path that begins with two separators answers
    // ENOENT here without calling through, so no row reaches the network.
    describe.runIf(WIN32)("a share's spelling (win32 only)", () => {
      beforeEach(async () => {
        const fs = await vi.importActual<typeof import("node:fs")>("node:fs");
        const promises =
          await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
        vi.mocked(statSync).mockClear();
        vi.mocked(realpath).mockClear();
        vi.mocked(lstat).mockClear();
        vi.mocked(statSync).mockImplementation((path, options) => {
          if (leadsWithTwoSeparators(path)) throw notThere();
          return fs.statSync(path, options);
        });
        vi.mocked(realpath).mockImplementation(async (path, options) => {
          if (leadsWithTwoSeparators(path)) throw notThere();
          return promises.realpath(path, options);
        });
        vi.mocked(lstat).mockImplementation(async (path, options) => {
          if (leadsWithTwoSeparators(path)) throw notThere();
          return promises.lstat(path, options);
        });
      });

      afterEach(() => {
        vi.mocked(statSync).mockReset();
        vi.mocked(realpath).mockReset();
        vi.mocked(lstat).mockReset();
      });

      it.each(SHARE_CASES)(
        "a working directory spelled as a share is refused before anything touches it: %s into %s over HTTPS",
        async (operation, spelled) => {
          await expectInvalid(
            {
              type: "git",
              operation,
              repository: HTTPS_REPOSITORY,
              working_directory: spelled,
            },
            NAMES_A_SHARE,
          );
          expect(shareSpellingsTouched()).toEqual([]);
        },
      );

      it.skipIf(SSH === null).each(SHARE_SPELLINGS)(
        "a working directory spelled as a share is refused before anything touches it: pull in %s over SSH, the row naming the host (skipped where the native ssh client does not resolve)",
        async (spelled) => {
          await expectInvalid(
            {
              type: "git",
              operation: "pull",
              repository: SSH_REPOSITORY,
              working_directory: spelled,
            },
            NAMES_A_SHARE,
            { host: SSH_HOST },
          );
          expect(shareSpellingsTouched()).toEqual([]);
        },
      );

      it.each([
        ["without a working directory", undefined],
        ["with a relative working directory", "clone"],
      ])(
        "the process's own directory is not judged as a share: a clone %s, the process's own spelled as a share, gets the floor's refusal",
        async (_form, workingDirectory) => {
          const cwd = vi.spyOn(process, "cwd").mockReturnValue("\\\\server\\share\\dir");
          try {
            await expectProtected({
              type: "git",
              operation: "clone",
              repository: HTTPS_REPOSITORY,
              ...(workingDirectory !== undefined ? { working_directory: workingDirectory } : {}),
            });
            expect(cwd).toHaveBeenCalled();
          } finally {
            cwd.mockRestore();
          }
        },
      );
    });

    it.each(DOT_SEGMENT_CASES)(
      "in a daemon a `..` segment is refused: %s",
      async (_label, operation, spell) => {
        mkdirSync(join(root, "agent"));
        mkdirSync(join(root, "tree"));
        const cwd = vi.spyOn(process, "cwd").mockReturnValue(join(root, "agent"));
        try {
          await expectInvalid(
            {
              type: "git",
              operation,
              repository: HTTPS_REPOSITORY,
              working_directory: spell(root),
            },
            DOT_SEGMENT,
            {},
            NO_PATHS,
          );
        } finally {
          cwd.mockRestore();
        }
      },
    );

    it("in a daemon a destination whose name holds `..` within it reaches git", async () => {
      expect(await cloneDestination(join(root, "a..b"), NO_PATHS)).toBe(join(root, "a..b"));
    });

    it.each(UNDER_THE_FLOOR_CASES)(
      "under the floor every spelling gets the floor's refusal: %s into %s over HTTPS",
      async (operation, _label, name) => {
        writeFileSync(join(vaultDir, "file"), "");
        await expectProtected({
          type: "git",
          operation,
          repository: HTTPS_REPOSITORY,
          working_directory: join(vaultDir, name),
        });
      },
    );

    it.skipIf(SSH === null).each(UNDER_THE_FLOOR_CASES)(
      "under the floor every spelling gets the floor's refusal: %s into %s over SSH, the row naming the host (skipped where the native ssh client does not resolve)",
      async (operation, _label, name) => {
        writeFileSync(join(vaultDir, "file"), "");
        await expectProtected(
          {
            type: "git",
            operation,
            repository: SSH_REPOSITORY,
            working_directory: join(vaultDir, name),
          },
          { host: SSH_HOST },
        );
      },
    );

    it.each(UNDER_THE_FLOOR_CASES)(
      "under the floor every spelling gets the floor's refusal: %s into %s, spelled relative to the process's own directory",
      async (operation, _label, name) => {
        writeFileSync(join(vaultDir, "file"), "");
        const cwd = vi.spyOn(process, "cwd").mockReturnValue(root);
        try {
          await expectProtected({
            type: "git",
            operation,
            repository: HTTPS_REPOSITORY,
            working_directory: join("vault", name),
          });
          expect(cwd).toHaveBeenCalled();
        } finally {
          cwd.mockRestore();
        }
      },
    );

    // A symbolic link needs a privilege on win32.
    it.skipIf(WIN32).each(UNDER_THE_FLOOR_CASES)(
      "under the floor every spelling gets the floor's refusal: %s into %s, reached through a link outside the floor",
      async (operation, _label, name) => {
        writeFileSync(join(vaultDir, "file"), "");
        const link = join(root, "link");
        symlinkSync(join(vaultDir, name), link);
        await expectProtected({
          type: "git",
          operation,
          repository: HTTPS_REPOSITORY,
          working_directory: link,
        });
      },
    );

    it.each(OUTSIDE_THE_FLOOR_CASES)(
      "outside the floor the two messages name no path: %s into %s",
      async (operation, _label, name, message) => {
        writeFileSync(join(root, "file"), "");
        await expectInvalid(
          {
            type: "git",
            operation,
            repository: HTTPS_REPOSITORY,
            working_directory: join(root, name),
          },
          message,
        );
      },
    );

    it.skipIf(SSH === null)(
      "outside the floor the two messages name no path: pull into a missing name over SSH, the row naming the host (skipped where the native ssh client does not resolve)",
      async () => {
        await expectInvalid(
          {
            type: "git",
            operation: "pull",
            repository: SSH_REPOSITORY,
            working_directory: join(root, "absent"),
          },
          "working_directory does not exist",
          { host: SSH_HOST },
        );
      },
    );

    it.each(TREE_OPERATIONS)(
      "the directory check reads the resolved path: a relative working tree is read from the process's own, and %s goes on to its first probe there",
      async (operation) => {
        repository(join(root, "vault-beside"));
        const cwd = vi.spyOn(process, "cwd").mockReturnValue(root);
        try {
          expect(await treeDirectory(operation, "vault-beside")).toBe(join(root, "vault-beside"));
          expect(cwd).toHaveBeenCalled();
        } finally {
          cwd.mockRestore();
        }
      },
    );

    it("required answers before the floor: a pull without a working directory, the process's own inside the vault's directory, is refused as required", async () => {
      const cwd = vi.spyOn(process, "cwd").mockReturnValue(vaultDir);
      try {
        await expectInvalid(
          { type: "git", operation: "pull", repository: HTTPS_REPOSITORY },
          "working_directory is required for pull",
        );
      } finally {
        cwd.mockRestore();
      }
    });

    it("the daemon's clone rule answers before the floor: a clone without a working directory, the process's own inside the vault's directory, is refused by the rule", async () => {
      const cwd = vi.spyOn(process, "cwd").mockReturnValue(vaultDir);
      try {
        await expectRefusedInDaemon(HTTPS_REPOSITORY);
      } finally {
        cwd.mockRestore();
      }
    });
  },
);
