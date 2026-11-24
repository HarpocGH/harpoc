import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, sep } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs } from "./allowlist.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
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

// On win32 the git context accepts only the native Win32-OpenSSH client, so its
// directory leads the PATH (as in git-injector.floor.test.ts).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const GIT = resolveSupportedGit();
const SSH = resolveNativeSshClient("ssh");
const WIN32 = process.platform === "win32";

const HTTPS_REPOSITORY = "https://8.8.8.8/org/repo.git";
const SSH_HOST = "allowed.invalid";
const SSH_REPOSITORY = `git@${SSH_HOST}:org/repo.git`;
const KNOWN_HOSTS: ConnectionConfig = {
  ssh: { known_hosts: [`${SSH_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`] },
};
const SCRIPTED_SECRET = new Uint8Array(Buffer.from("git-user:dot-git-token-value"));
const PROTECTED = "git working directory is inside a directory the vault protects";
const DOT_GIT_SEGMENT = "working_directory must not hold a .git segment";
const CLONE_DERIVES_DOT_GIT =
  "a clone without working_directory must not derive a .git directory from the repository";
const CLONE_DERIVES_NO_NAME =
  "a clone without working_directory needs a repository address that names a directory";

const OPERATIONS = ["clone", "pull", "push", "fetch"] as const;
const TREE_OPERATIONS = ["pull", "push", "fetch"] as const;
type Operation = (typeof OPERATIONS)[number];
type Floor = Parameters<GitInjector["executeWithSecret"]>[6];

const OK_STEP: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

function gitSubcommand(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === "-c") i++;
    else if (!a.startsWith("-")) return a;
  }
  return undefined;
}

function isNetwork(args: string[]): boolean {
  return args.some((a) => a.startsWith("--git-dir="));
}

/** git's answer of one line each, paths as git prints them, with forward slashes. */
function answer(...lines: string[]): string {
  return lines.map((line) => `${line.replace(/\\/g, "/")}\n`).join("");
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
    ssh_bootstrap: null,
  };
}

const spawnMock = vi.mocked(spawnCaptured);
let root: string;
let vaultDir: string;
let log: Mock;

beforeEach(() => {
  // `.native` like the judgement's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-dot-git-")));
  vaultDir = join(root, "vault");
  mkdirSync(vaultDir);
  writeFileSync(join(vaultDir, "vault.db"), "");
  writeFileSync(join(vaultDir, "session.json"), "");
  log = vi.fn();
  readVersion.mockReset();
  readVersion.mockResolvedValue({ major: 2, minor: 51, patch: 0 });
  spawnMock.mockReset();
});

afterEach(() => {
  spawnMock.mockReset();
  readVersion.mockReset();
  rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function floorAt(dir: string, daemon?: DaemonPaths): Floor {
  return {
    vaultFiles: [join(dir, "vault.db"), join(dir, "session.json")],
    ...(daemon !== undefined ? { daemon } : {}),
  };
}

function networkSteps(): Array<string | undefined> {
  return (spawnMock.mock.calls as Array<Parameters<typeof spawnCaptured>>)
    .filter(([, args]) => isNetwork(args))
    .map(([, args]) => gitSubcommand(args));
}

function failedRow(operation: Operation, error: string, over: Record<string, unknown> = {}) {
  return {
    eventType: "secret.use",
    secretId: "secret-1",
    detail: { context: "git", operation, ...over, error },
    success: false,
  };
}

describe.skipIf(GIT === null)(
  "a .git name in the directory the git context is handed, scripted (skipped where no supported git resolves)",
  () => {
    const FLOORS = [
      ["with a floor", () => floorAt(vaultDir)],
      ["without a floor", () => undefined],
    ] as const;

    function use(
      operation: Operation,
      workingDirectory: string | undefined,
      floor: Floor,
      repository: string = HTTPS_REPOSITORY,
    ) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        {
          type: "git",
          operation,
          repository,
          ...(workingDirectory !== undefined ? { working_directory: workingDirectory } : {}),
        },
        SCRIPTED_SECRET,
        policy(),
        repository.startsWith("https://") ? undefined : KNOWN_HOSTS,
        "secret-1",
        undefined,
        floor,
      );
    }

    /** A work tree whose `.git` has a git directory's shape: `HEAD`, `objects`, `refs`. */
    function repository(): string {
      const tree = join(root, "tree");
      mkdirSync(join(tree, ".git", "objects"), { recursive: true });
      mkdirSync(join(tree, ".git", "refs"));
      writeFileSync(join(tree, ".git", "HEAD"), "ref: refs/heads/main\n");
      return tree;
    }

    /** spawnCaptured answers by argv: the probe, a pull's top level, the push's HEAD, the fetch's remote; every other step succeeds. */
    function script(tree: string = join(root, "tree")): void {
      const gitDir = join(tree, ".git");
      const probe = answer(
        join(gitDir, "objects"),
        join(gitDir, "shallow"),
        "sha1",
        gitDir,
        gitDir,
        "false",
      );
      spawnMock.mockImplementation((_cmd, args) => {
        const sub = gitSubcommand(args);
        let stdout = "";
        if (args.includes("--git-path")) stdout = probe;
        else if (args.includes("--show-toplevel")) stdout = answer(tree);
        else if (sub === "symbolic-ref") stdout = "refs/heads/main\n";
        else if (sub === "config") stdout = "remote.origin.url\0";
        return Promise.resolve({ ...OK_STEP, stdout });
      });
    }

    /** `<root>/alias`, a link into the repository's `.git`: a junction on win32, which needs no privilege. */
    function alias(): string {
      const modules = join(repository(), ".git", "modules");
      mkdirSync(modules);
      const link = join(root, "alias");
      symlinkSync(modules, link, WIN32 ? "junction" : "dir");
      return link;
    }

    function entries(dir: string): string[] {
      return readdirSync(dir, { recursive: true, encoding: "utf8" }).sort();
    }

    const SPELLINGS: ReadonlyArray<readonly [string, () => string]> = [
      ["<root>/.git", () => join(root, ".git")],
      ["<root>/tree/.GIT/x", () => join(root, "tree", ".GIT", "x")],
      ["<root>/tree/.git./x", () => join(root, "tree", ".git.", "x")],
      ["<root>/tree/git~1", () => join(root, "tree", "git~1")],
      ["<root>/tree/.g\\u200cit", () => join(root, "tree", ".g\u200cit")],
    ];

    it.each(
      OPERATIONS.flatMap((operation) =>
        SPELLINGS.map(([label, spell]) => [operation, label, spell] as const),
      ),
    )(
      "a working_directory whose spelling holds a .git name is refused before anything touches it: %s in %s",
      async (operation, _label, spell) => {
        script();
        const workingDirectory = spell();
        expect(existsSync(workingDirectory)).toBe(false);
        const before = entries(root);
        const err = await expectVaultError(
          () => use(operation, workingDirectory, floorAt(vaultDir)),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(DOT_GIT_SEGMENT);
        expect(log.mock.calls).toEqual([[failedRow(operation, "INVALID_GIT_CONFIG")]]);
        expect(spawnMock).not.toHaveBeenCalled();
        expect(entries(root)).toEqual(before);
      },
    );

    it.skipIf(SSH === null).each(SPELLINGS)(
      "over SSH the row names the host: a pull in %s (skipped where the native ssh client does not resolve)",
      async (_label, spell) => {
        script();
        const before = entries(root);
        const err = await expectVaultError(
          () => use("pull", spell(), floorAt(vaultDir), SSH_REPOSITORY),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(DOT_GIT_SEGMENT);
        expect(log.mock.calls).toEqual([
          [failedRow("pull", "INVALID_GIT_CONFIG", { host: SSH_HOST })],
        ]);
        expect(spawnMock).not.toHaveBeenCalled();
        expect(entries(root)).toEqual(before);
      },
    );

    // Only win32 reads a spelling that begins with two separators as a share.
    it.runIf(WIN32).each(OPERATIONS)(
      "the order: a share keeps its own message: %s in \\\\server\\share\\.git",
      async (operation) => {
        const err = await expectVaultError(
          () => use(operation, "\\\\server\\share\\.git", floorAt(vaultDir)),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe("working_directory names a network share");
        expect(log.mock.calls).toEqual([[failedRow(operation, "INVALID_GIT_CONFIG")]]);
        expect(spawnMock).not.toHaveBeenCalled();
      },
    );

    it.each(OPERATIONS)(
      "the order: a .. keeps its own message in a daemon: %s in <root>/a/../.git",
      async (operation) => {
        const err = await expectVaultError(
          () =>
            use(
              operation,
              [root, "a", "..", ".git"].join(sep),
              floorAt(vaultDir, { protectedDirs: [], protectedFiles: [] }),
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe("working_directory must not hold a .. segment");
        expect(log.mock.calls).toEqual([[failedRow(operation, "INVALID_GIT_CONFIG")]]);
        expect(spawnMock).not.toHaveBeenCalled();
      },
    );

    it.each(
      OPERATIONS.flatMap((operation) =>
        FLOORS.map(([label, floor]) => [operation, label, floor] as const),
      ),
    )(
      "a link that leads into a .git directory is refused with the floor's refusal: %s in <root>/alias, %s",
      async (operation, _label, floor) => {
        script();
        const link = alias();
        const err = await expectVaultError(
          () => use(operation, link, floor()),
          ErrorCode.LOCAL_PATH_NOT_ALLOWED,
        );
        expect(err.message).toBe(PROTECTED);
        expect(log.mock.calls).toEqual([[failedRow(operation, "LOCAL_PATH_NOT_ALLOWED")]]);
        expect(spawnMock).not.toHaveBeenCalled();
      },
    );

    it.each(FLOORS)(
      "a clone's destination that does not exist yet below a .git directory: <root>/alias/new is refused with the floor's refusal, %s",
      async (_label, floor) => {
        script();
        const destination = join(alias(), "new");
        const err = await expectVaultError(
          () => use("clone", destination, floor()),
          ErrorCode.LOCAL_PATH_NOT_ALLOWED,
        );
        expect(err.message).toBe(PROTECTED);
        expect(log.mock.calls).toEqual([[failedRow("clone", "LOCAL_PATH_NOT_ALLOWED")]]);
        expect(spawnMock).not.toHaveBeenCalled();
        expect(existsSync(destination)).toBe(false);
      },
    );

    const CLONE_REFUSALS: ReadonlyArray<readonly [string, string, string]> = [
      ["https://8.8.8.8/org/.git.git", "https://8.8.8.8/org/.git.git", CLONE_DERIVES_DOT_GIT],
      ["https://8.8.8.8/org/x:.git.git", "https://8.8.8.8/org/x:.git.git", CLONE_DERIVES_DOT_GIT],
      ["https://8.8.8.8/org/.GIT.git", "https://8.8.8.8/org/.GIT.git", CLONE_DERIVES_DOT_GIT],
      ["https://8.8.8.8/org/.git..git", "https://8.8.8.8/org/.git..git", CLONE_DERIVES_DOT_GIT],
      ["https://8.8.8.8/org/git~1.git", "https://8.8.8.8/org/git~1.git", CLONE_DERIVES_DOT_GIT],
      [
        "https://8.8.8.8/org/\\u200c.git.git",
        "https://8.8.8.8/org/\u200c.git.git",
        CLONE_DERIVES_DOT_GIT,
      ],
      ["https://8.8.8.8/org/ .git.git", "https://8.8.8.8/org/ .git.git", CLONE_DERIVES_DOT_GIT],
      ["https://8.8.8.8/org/.git .git", "https://8.8.8.8/org/.git .git", CLONE_DERIVES_DOT_GIT],
      [
        "https://8.8.8.8/org/\\u0001.git.git",
        "https://8.8.8.8/org/\x01.git.git",
        CLONE_DERIVES_DOT_GIT,
      ],
      ["https://8.8.8.8/org/.git/.git", "https://8.8.8.8/org/.git/.git", CLONE_DERIVES_NO_NAME],
      ["https://8.8.8.8/org/x:.git", "https://8.8.8.8/org/x:.git", CLONE_DERIVES_NO_NAME],
      ["https://8.8.8.8/org/ .git", "https://8.8.8.8/org/ .git", CLONE_DERIVES_NO_NAME],
      ["https://8.8.8.8/org/..git", "https://8.8.8.8/org/..git", CLONE_DERIVES_NO_NAME],
      ["https://8.8.8.8/org/...git", "https://8.8.8.8/org/...git", CLONE_DERIVES_NO_NAME],
    ];

    async function expectCloneRefused(
      repository: string,
      message: string,
      over: Record<string, unknown> = {},
    ): Promise<void> {
      script();
      const err = await expectVaultError(
        () => use("clone", undefined, floorAt(vaultDir), repository),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toBe(message);
      expect(log.mock.calls).toEqual([[failedRow("clone", "INVALID_GIT_CONFIG", over)]]);
      expect(spawnMock).not.toHaveBeenCalled();
    }

    async function expectCloneReachesTheNetwork(repository: string): Promise<void> {
      script();
      const result = await use("clone", undefined, floorAt(vaultDir), repository);
      expect(result.exit_code).toBe(0);
      expect(networkSteps()[0]).toBe("ls-remote");
    }

    it.each(CLONE_REFUSALS)(
      "a clone without working_directory: the name git would derive from %s is refused",
      async (_label, repository, message) => {
        await expectCloneRefused(repository, message);
      },
    );

    it
      .skipIf(SSH === null)
      .each(["git@allowed.invalid:.git.git", "git@allowed.invalid:org/.git.git"])(
      "a clone without working_directory: the name git would derive from %s is refused, the row naming the host (skipped where the native ssh client does not resolve)",
      async (repository) => {
        await expectCloneRefused(repository, CLONE_DERIVES_DOT_GIT, { host: SSH_HOST });
      },
    );

    it.each([
      "https://8.8.8.8/org/repo.git",
      "https://8.8.8.8/org/repo",
      "https://8.8.8.8/org/repo.git/",
      "https://8.8.8.8/org/.git",
      "https://8.8.8.8/.git",
    ])(
      "a clone without working_directory: %s names a directory and reaches the first network step",
      async (repository) => {
        await expectCloneReachesTheNetwork(repository);
      },
    );

    // A backslash separates a path on win32 alone: elsewhere git derives `org\.git`.
    it.runIf(WIN32)(
      "a clone without working_directory: the name git would derive from https://8.8.8.8/org\\.git.git is refused on win32",
      async () => {
        await expectCloneRefused("https://8.8.8.8/org\\.git.git", CLONE_DERIVES_DOT_GIT);
      },
    );

    it.skipIf(WIN32)(
      "a clone without working_directory: https://8.8.8.8/org\\.git.git names a directory off win32 and reaches the first network step (skipped on win32, where a backslash separates)",
      async () => {
        await expectCloneReachesTheNetwork("https://8.8.8.8/org\\.git.git");
      },
    );

    function processDirectoryWithADotGitName(): string {
      const dir = join(root, "x", ".git", "y");
      mkdirSync(dir, { recursive: true });
      return dir;
    }

    it.each(FLOORS)(
      "a clone without working_directory in a process directory with a .git name is refused with the floor's refusal, %s",
      async (_label, floor) => {
        script();
        const cwd = vi.spyOn(process, "cwd").mockReturnValue(processDirectoryWithADotGitName());
        try {
          const err = await expectVaultError(
            () => use("clone", undefined, floor()),
            ErrorCode.LOCAL_PATH_NOT_ALLOWED,
          );
          expect(err.message).toBe(PROTECTED);
          expect(log.mock.calls).toEqual([[failedRow("clone", "LOCAL_PATH_NOT_ALLOWED")]]);
          expect(spawnMock).not.toHaveBeenCalled();
        } finally {
          cwd.mockRestore();
        }
      },
    );

    it.each(
      TREE_OPERATIONS.flatMap((operation) =>
        FLOORS.map(([label, floor]) => [operation, label, floor] as const),
      ),
    )(
      "a process directory with a .git name leaves a %s that names its directory untouched, %s",
      async (operation, _label, floor) => {
        const tree = repository();
        script(tree);
        const cwd = vi.spyOn(process, "cwd").mockReturnValue(processDirectoryWithADotGitName());
        try {
          const result = await use(operation, tree, floor());
          expect(result.exit_code).toBe(0);
          expect(networkSteps()).toEqual([operation === "push" ? "push" : "fetch"]);
        } finally {
          cwd.mockRestore();
        }
      },
    );

    it("the version floor comes first: a pull in <root>/.git with git 2.31.9 is the floor's refusal, nothing spawned", async () => {
      readVersion.mockResolvedValue({ major: 2, minor: 31, patch: 9 });
      const err = await expectVaultError(
        () => use("pull", join(root, ".git"), floorAt(vaultDir)),
        ErrorCode.GIT_OPERATION_FAILED,
      );
      expect(err.message).toBe(
        "Git operation failed: git 2.31.9 is older than 2.32, which the git context needs",
      );
      expect(log.mock.calls).toEqual([
        [failedRow("pull", "GIT_OPERATION_FAILED", { git_version: "2.31.9" })],
      ]);
      expect(spawnMock).not.toHaveBeenCalled();
    });
  },
);

it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no supported git resolves',
    );
  }
});
