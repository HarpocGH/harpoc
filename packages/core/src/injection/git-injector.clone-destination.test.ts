import { execFileSync } from "node:child_process";
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
import { join, parse } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { startGitSmartHttp } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import type { readGitVersion } from "./git-injector-version.js";
import { GitInjector } from "./git-injector.js";
import type { DaemonPaths } from "./local-path.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
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

const { spawnCaptured: realSpawnCaptured } =
  await vi.importActual<typeof import("./spawn-captured.js")>("./spawn-captured.js");
const { readGitVersion: realReadGitVersion } = await vi.importActual<
  typeof import("./git-injector-version.js")
>("./git-injector-version.js");

const GIT = resolveSupportedGit();
const WIN32 = process.platform === "win32";

const HTTPS_REPOSITORY = "https://8.8.8.8/org/repo.git";
const SCRIPTED_SECRET = new Uint8Array(Buffer.from("git-user:clone-destination-token-value"));
const SERVER_USER = "vaultuser";
const SERVER_TOKEN = "S3CRET-TOKEN-clone-destination";
const SERVED_SECRET = new Uint8Array(Buffer.from(`${SERVER_USER}:${SERVER_TOKEN}`));
const PROTECTED = "git working directory is inside a directory the vault protects";
const NO_PATHS: DaemonPaths = { protectedDirs: [], protectedFiles: [] };

const TREE_OPERATIONS = ["pull", "push", "fetch"] as const;
type Operation = "clone" | (typeof TREE_OPERATIONS)[number];
type Floor = Parameters<GitInjector["executeWithSecret"]>[6];
type SpawnCall = Parameters<typeof spawnCaptured>;

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

function policy(urlAllowlist: string[] = ["https://8.8.8.8/*"]): InjectionPolicy {
  return {
    url_allowlist: urlAllowlist,
    command_allowlist: [GIT as string],
    env_allowlist: [],
    host_allowlist: [],
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
    render: { entries: [], approvals: [] },
  };
}

const spawnMock = vi.mocked(spawnCaptured);
let root: string;
let vaultDir: string;
let log: Mock;

beforeEach(() => {
  // `.native` like the judgement's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-clone-destination-")));
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

const FLOORS = [
  ["with a floor", () => floorAt(vaultDir)],
  ["without a floor", () => undefined],
] as const;

const FLOORS_AND_A_DAEMON = [
  ...FLOORS,
  ["in a daemon", () => floorAt(vaultDir, NO_PATHS)],
] as const;

function calls(): SpawnCall[] {
  return spawnMock.mock.calls as SpawnCall[];
}

function entries(dir: string): string[] {
  return readdirSync(dir, { recursive: true, encoding: "utf8" }).sort();
}

function failedRow(operation: Operation, error: string) {
  return {
    eventType: "secret.use",
    secretId: "secret-1",
    detail: { context: "git", operation, error },
    success: false,
  };
}

/** `<root>/<name>`: a directory with a git directory's shape and no `.git` name, as a bare repository has it. */
function shaped(name = "served"): string {
  const dir = join(root, name);
  mkdirSync(join(dir, "objects", "info"), { recursive: true });
  mkdirSync(join(dir, "refs", "heads"), { recursive: true });
  writeFileSync(join(dir, "HEAD"), "ref: refs/heads/main\n");
  return dir;
}

/** A work tree whose `.git` has a git directory's shape: `HEAD`, `objects`, `refs`. */
function workTree(tree: string): string {
  mkdirSync(join(tree, ".git", "objects"), { recursive: true });
  mkdirSync(join(tree, ".git", "refs"));
  writeFileSync(join(tree, ".git", "HEAD"), "ref: refs/heads/main\n");
  return tree;
}

it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no supported git resolves',
    );
  }
});

describe.skipIf(GIT === null)(
  "a clone's destination inside a directory with a git directory's shape, scripted (skipped where no supported git resolves)",
  () => {
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
        undefined,
        "secret-1",
        undefined,
        floor,
      );
    }

    /** spawnCaptured answers by argv: the read of the ref storage as absent, the probe, a pull's top level, the push's HEAD, the fetch's remote; every other step succeeds. */
    function script(
      tree: string = join(root, "tree"),
      gitDir: string = join(tree, ".git"),
      commonDir: string = gitDir,
    ): void {
      const probe = answer(
        join(commonDir, "objects"),
        join(commonDir, "shallow"),
        "sha1",
        gitDir,
        commonDir,
        "false",
      );
      spawnMock.mockImplementation((_cmd, args) => {
        if (args.includes("extensions.refStorage")) {
          return Promise.resolve({ ...OK_STEP, exit_code: 1 });
        }
        const sub = gitSubcommand(args);
        let stdout = "";
        if (args.includes("--git-path")) stdout = probe;
        else if (args.includes("--show-toplevel")) stdout = answer(tree);
        else if (sub === "symbolic-ref") stdout = "refs/heads/main\n";
        else if (sub === "config") stdout = "remote.origin.url\0";
        return Promise.resolve({ ...OK_STEP, stdout });
      });
    }

    async function expectRefused(
      workingDirectory: string | undefined,
      floor: Floor,
      repository: string = HTTPS_REPOSITORY,
    ) {
      script();
      const before = entries(root);
      const err = await expectVaultError(
        () => use("clone", workingDirectory, floor, repository),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
      expect(err.message).toBe(PROTECTED);
      expect(log.mock.calls).toEqual([[failedRow("clone", "LOCAL_PATH_NOT_ALLOWED")]]);
      expect(readVersion).toHaveBeenCalledTimes(1);
      expect(spawnMock).not.toHaveBeenCalled();
      expect(entries(root)).toEqual(before);
    }

    /** The clone ran: its two network steps, then the local step, handed `destination`. */
    function expectCloned(destination: string, repository: string = HTTPS_REPOSITORY): void {
      expect(calls().map(([, args]) => gitSubcommand(args))).toEqual([
        "ls-remote",
        "fetch",
        "clone",
      ]);
      const [, local] = calls()[2] as SpawnCall;
      expect(isNetwork(local)).toBe(false);
      expect(local.slice(local.indexOf("--"))).toEqual(["--", repository, destination]);
    }

    /** Runs `fn` while `process.cwd()` answers `dir`. */
    async function inProcessDirectory(dir: string, fn: () => Promise<void>): Promise<void> {
      const cwd = vi.spyOn(process, "cwd").mockReturnValue(dir);
      try {
        await fn();
      } finally {
        cwd.mockRestore();
      }
    }

    /** `<root>/cwd`, the process's directory of a clone without working_directory. */
    function processDirectory(): string {
      const dir = join(root, "cwd");
      mkdirSync(dir);
      return dir;
    }

    /** A link at `at` whose target is gone: a junction on win32, which needs no privilege. */
    function danglingLink(at: string): void {
      const gone = join(root, "gone");
      mkdirSync(gone);
      symlinkSync(gone, at, WIN32 ? "junction" : "dir");
      rmSync(gone, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }

    const DESTINATIONS: ReadonlyArray<readonly [string, (served: string) => string]> = [
      ["<root>/served/objects/info/x", (served) => join(served, "objects", "info", "x")],
      ["<root>/served/objects/info", (served) => join(served, "objects", "info")],
      ["<root>/served/remotes", (served) => join(served, "remotes")],
      ["<root>/served/refs/heads/x", (served) => join(served, "refs", "heads", "x")],
      ["<root>/served/a/b/c", (served) => join(served, "a", "b", "c")],
    ];

    it.each(
      DESTINATIONS.flatMap(([label, spell]) =>
        FLOORS_AND_A_DAEMON.map(([how, floor]) => [label, how, spell, floor] as const),
      ),
    )(
      "a clone whose destination lies below a directory with the shape is refused with the floor's refusal, nothing spawned, nothing made: %s, %s",
      async (_label, _how, spell, floor) => {
        await expectRefused(spell(shaped()), floor());
      },
    );

    it.each(FLOORS)(
      "a directory with HEAD and commondir has the shape too: a clone into <root>/linked/x is refused, %s",
      async (_how, floor) => {
        const linked = join(root, "linked");
        mkdirSync(linked);
        writeFileSync(join(linked, "HEAD"), "ref: refs/heads/t\n");
        writeFileSync(join(linked, "commondir"), "../..\n");
        await expectRefused(join(linked, "x"), floor());
      },
    );

    it.each(FLOORS)(
      "the resolved destination is the one walked: a clone into <root>/alias/x, the alias a link to <root>/served/objects/info, is refused, %s",
      async (_how, floor) => {
        const link = join(root, "alias");
        symlinkSync(join(shaped(), "objects", "info"), link, WIN32 ? "junction" : "dir");
        await expectRefused(join(link, "x"), floor());
      },
    );

    it.each(
      (
        [
          ["<root>/served", (served: string) => served],
          ["<root>/served/objects/info", (served: string) => join(served, "objects", "info")],
        ] as const
      ).flatMap(([label, at]) => FLOORS.map(([how, floor]) => [label, how, at, floor] as const)),
    )(
      "a clone without working_directory is refused where the process's directory is %s, in which git would make the derived directory, %s",
      async (_label, _how, at, floor) => {
        const cwd = vi.spyOn(process, "cwd").mockReturnValue(at(shaped()));
        try {
          await expectRefused(undefined, floor());
        } finally {
          cwd.mockRestore();
        }
      },
    );

    it.each(FLOORS_AND_A_DAEMON)(
      "a clone into a subdirectory of an ordinary work tree, beside its .git, is served: <root>/tree/sub/new, %s",
      async (_how, floor) => {
        const destination = join(workTree(join(root, "tree")), "sub", "new");
        script();
        const result = await use("clone", destination, floor());
        expect(result.exit_code).toBe(0);
        expectCloned(destination);
      },
    );

    it.each(FLOORS)(
      "a clone beside a directory with the shape is served: <root>/new with <root>/served next to it, %s",
      async (_how, floor) => {
        shaped();
        const destination = join(root, "new");
        script();
        const result = await use("clone", destination, floor());
        expect(result.exit_code).toBe(0);
        expectCloned(destination);
      },
    );

    it.each(FLOORS)(
      "a directory that holds HEAD alone has no shape: a clone into <root>/notes/x is served, %s",
      async (_how, floor) => {
        mkdirSync(join(root, "notes"));
        writeFileSync(join(root, "notes", "HEAD"), "a note\n");
        const destination = join(root, "notes", "x");
        script();
        const result = await use("clone", destination, floor());
        expect(result.exit_code).toBe(0);
        expectCloned(destination);
      },
    );

    it.each(FLOORS)(
      "a clone without working_directory is served where the process's directory is a subdirectory of an ordinary work tree, and git is handed the directory it would derive there, resolved: <root>/tree/sub/repo, %s",
      async (_how, floor) => {
        const sub = join(workTree(join(root, "tree")), "sub");
        mkdirSync(sub);
        script();
        const cwd = vi.spyOn(process, "cwd").mockReturnValue(sub);
        try {
          const result = await use("clone", undefined, floor());
          expect(result.exit_code).toBe(0);
          expectCloned(join(sub, "repo"));
        } finally {
          cwd.mockRestore();
        }
      },
    );

    it.each(FLOORS)(
      "a clone without working_directory is refused where the name git derives is a link that leads nowhere: <root>/cwd/repo, %s",
      async (_how, floor) => {
        const cwd = processDirectory();
        danglingLink(join(cwd, "repo"));
        await inProcessDirectory(cwd, () => expectRefused(undefined, floor()));
      },
    );

    // Only the Win32 path layer drops a name's trailing dot.
    it.runIf(WIN32).each(FLOORS)(
      "a clone without working_directory is refused where the name git derives from https://8.8.8.8/org/repo. is one Windows reads differently, %s",
      async (_how, floor) => {
        const cwd = processDirectory();
        await inProcessDirectory(cwd, () =>
          expectRefused(undefined, floor(), "https://8.8.8.8/org/repo."),
        );
      },
    );

    it.each(FLOORS)(
      "a clone without working_directory is refused where the process's directory, resolved, holds U+FFFD: <root>/a\\ufffdb, %s",
      async (_how, floor) => {
        const cwd = join(root, "a\uFFFDb");
        mkdirSync(cwd);
        await inProcessDirectory(cwd, () => expectRefused(undefined, floor()));
      },
    );

    it.each(
      (
        [
          ["U+FFFD", "https://8.8.8.8/org/\uFFFD.git"],
          ["an unpaired surrogate", "https://8.8.8.8/org/\uD800.git"],
        ] as const
      ).flatMap(([label, repository]) =>
        FLOORS.map(([how, floor]) => [label, how, repository, floor] as const),
      ),
    )(
      "a clone without working_directory is refused where the name git derives holds %s, %s",
      async (_label, _how, repository, floor) => {
        const cwd = processDirectory();
        await inProcessDirectory(cwd, () => expectRefused(undefined, floor(), repository));
      },
    );

    it.skipIf(WIN32).each(FLOORS)(
      "a clone without working_directory is refused where the name git derives is longer than a name may be, 256 bytes, %s (skipped on win32, where the system answers that such a name is not there, so it is joined on and git fails to make it)",
      async (_how, floor) => {
        const cwd = processDirectory();
        await inProcessDirectory(cwd, () =>
          expectRefused(undefined, floor(), `https://8.8.8.8/org/${"x".repeat(256)}.git`),
        );
      },
    );

    it("a clone without working_directory is refused where the name git derives is the vault's own directory: <root>/vault from https://8.8.8.8/org/vault.git, with a floor", async () => {
      await inProcessDirectory(root, () =>
        expectRefused(undefined, floorAt(vaultDir), "https://8.8.8.8/org/vault.git"),
      );
    });

    it.each(FLOORS)(
      "a clone without working_directory from the file system's root hands git the root and the derived name with no separator between them beyond the root's own, %s",
      async (_how, floor) => {
        const top = parse(root).root;
        const repository = "https://8.8.8.8/org/harpoc-clone-from-the-root.git";
        script();
        await inProcessDirectory(top, async () => {
          const result = await use("clone", undefined, floor(), repository);
          expect(result.exit_code).toBe(0);
        });
        expectCloned(`${top}harpoc-clone-from-the-root`, repository);
      },
    );

    // Only the Win32 file API refuses `|` in a name.
    it.runIf(WIN32)(
      "a clone without working_directory whose derived name holds a character NTFS forbids, re|po, is not refused: git, run for real after scripted network steps, fails to make the directory, a result with its exit code and a success row",
      async () => {
        const cwd = processDirectory();
        spawnMock.mockImplementation((cmd, args, opts) =>
          isNetwork(args) ? Promise.resolve(OK_STEP) : realSpawnCaptured(cmd, args, opts),
        );
        const saved = process.cwd();
        process.chdir(cwd);
        let result;
        try {
          result = await use(
            "clone",
            undefined,
            floorAt(vaultDir),
            "https://8.8.8.8/org/re|po.git",
          );
        } finally {
          process.chdir(saved);
        }
        expect(result.exit_code, result.stderr).toBe(128);
        expect(result.error).toBeUndefined();
        expect(log.mock.calls).toEqual([
          [
            expect.objectContaining({
              eventType: "secret.use",
              success: true,
              detail: expect.objectContaining({
                context: "git",
                operation: "clone",
                exit_code: 128,
              }),
            }),
          ],
        ]);
        expect(readdirSync(cwd)).toEqual([]);
      },
    );

    it("a clone without working_directory is refused where the process's directory cannot be read, without a floor", async () => {
      const cwd = vi.spyOn(process, "cwd").mockImplementation(() => {
        throw new Error("the process's directory was removed");
      });
      try {
        await expectRefused(undefined, undefined);
      } finally {
        cwd.mockRestore();
      }
    });

    it("a clone without working_directory is refused where the process's directory does not resolve: <root>/cwd, a link that leads nowhere, without a floor", async () => {
      const cwd = join(root, "cwd");
      danglingLink(cwd);
      await inProcessDirectory(cwd, () => expectRefused(undefined, undefined));
    });

    it.each(
      TREE_OPERATIONS.flatMap((operation) =>
        FLOORS.map(([how, floor]) => [operation, how, floor] as const),
      ),
    )(
      "a repository that lies below a directory with the shape is still served: %s in <root>/served/wt, %s",
      async (operation, _how, floor) => {
        const tree = workTree(join(shaped(), "wt"));
        script(tree);
        const result = await use(operation, tree, floor());
        expect(result.exit_code).toBe(0);
        expect(
          calls()
            .filter(([, args]) => isNetwork(args))
            .map(([, args]) => gitSubcommand(args)),
        ).toEqual([operation === "push" ? "push" : "fetch"]);
      },
    );

    it.each(FLOORS)(
      "a linked work tree laid inside a bare repository: a clone into <root>/served/wt/sub/new is refused, while a pull, a push and a fetch in <root>/served/wt/sub are served, %s",
      async (_how, floor) => {
        const bare = shaped();
        const gitDir = join(bare, "worktrees", "wt");
        mkdirSync(gitDir, { recursive: true });
        writeFileSync(join(gitDir, "HEAD"), "ref: refs/heads/wt\n");
        writeFileSync(join(gitDir, "commondir"), "../..\n");
        const tree = join(bare, "wt");
        const sub = join(tree, "sub");
        mkdirSync(sub, { recursive: true });
        writeFileSync(join(tree, ".git"), `gitdir: ${gitDir}\n`);
        await expectRefused(join(sub, "new"), floor());
        for (const operation of TREE_OPERATIONS) {
          spawnMock.mockReset();
          log.mockClear();
          script(tree, gitDir, bare);
          const result = await use(operation, sub, floor());
          expect(result.exit_code).toBe(0);
          expect(
            calls()
              .filter(([, args]) => isNetwork(args))
              .map(([, args]) => gitSubcommand(args)),
          ).toEqual([operation === "push" ? "push" : "fetch"]);
        }
      },
    );
  },
);

describe.skipIf(GIT === null)(
  "a clone's destination inside a directory with a git directory's shape, on real git against a smart-HTTP listener on 127.0.0.1 (skipped where no supported git resolves)",
  () => {
    let serverRoot: string;
    let server: Listener;
    let gitEnv: NodeJS.ProcessEnv;

    function git(cwd: string, ...args: string[]): string {
      return execFileSync(GIT as string, args, {
        cwd,
        env: gitEnv,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    }

    const address = () => `http://127.0.0.1:${String(server.port)}/repo.git`;

    function clone(destination: string | undefined, floor: Floor) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        {
          type: "git",
          operation: "clone",
          repository: address(),
          ...(destination !== undefined ? { working_directory: destination } : {}),
        },
        SERVED_SECRET,
        policy([`http://127.0.0.1:${String(server.port)}/*`]),
        undefined,
        "secret-1",
        undefined,
        floor,
      );
    }

    /** A clone without working_directory, the process's directory moved to `cwd` for it. */
    async function cloneFrom(cwd: string, floor: Floor) {
      const saved = process.cwd();
      process.chdir(cwd);
      try {
        return await clone(undefined, floor);
      } finally {
        process.chdir(saved);
      }
    }

    /** `<root>/cwd` with a link at `repo`, the name git derives from the address, to `target`: a junction on win32. */
    function linkedName(target: string): string {
      const cwd = join(root, "cwd");
      mkdirSync(cwd);
      symlinkSync(target, join(cwd, "repo"), WIN32 ? "junction" : "dir");
      return cwd;
    }

    beforeAll(async () => {
      serverRoot = realpathSync.native(
        mkdtempSync(join(tmpdir(), "harpoc-git-clone-destination-srv-")),
      );
      const emptyConfig = join(serverRoot, "empty.gitconfig");
      writeFileSync(emptyConfig, "");
      gitEnv = {
        ...process.env,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: emptyConfig,
        GIT_TERMINAL_PROMPT: "0",
        GIT_AUTHOR_NAME: "harpoc-test",
        GIT_AUTHOR_EMAIL: "test@example.com",
        GIT_COMMITTER_NAME: "harpoc-test",
        GIT_COMMITTER_EMAIL: "test@example.com",
      };
      const seed = join(serverRoot, "seed");
      git(serverRoot, "init", "-q", "-b", "main", seed);
      writeFileSync(join(seed, "alternates"), "/elsewhere/objects\n");
      writeFileSync(join(seed, "top.txt"), "1\n");
      git(seed, "add", "alternates", "top.txt");
      git(seed, "commit", "-q", "-m", "c1");
      const srv = join(serverRoot, "srv");
      mkdirSync(srv);
      git(serverRoot, "clone", "-q", "--bare", seed, join(srv, "repo.git"));
      server = await startGitSmartHttp({
        git: GIT as string,
        projectRoot: srv,
        user: SERVER_USER,
        token: SERVER_TOKEN,
        env: gitEnv,
      });
    });

    beforeEach(() => {
      spawnMock.mockImplementation(realSpawnCaptured);
      readVersion.mockImplementation(realReadGitVersion);
    });

    afterAll(async () => {
      try {
        if (server !== undefined) await server.close();
      } finally {
        if (serverRoot !== undefined)
          rmSync(serverRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    });

    it.each(FLOORS)(
      "a clone into a bare repository's empty objects/info is refused, and the remote's file named alternates is not written there: %s",
      async (_how, floor) => {
        const bare = join(root, "served");
        git(root, "init", "-q", "--bare", bare);
        const info = join(bare, "objects", "info");
        expect(readdirSync(info)).toEqual([]);
        let refusal: unknown;
        try {
          await clone(info, floor());
        } catch (err) {
          refusal = err;
        }
        expect(readdirSync(info)).toEqual([]);
        expect(spawnMock).not.toHaveBeenCalled();
        expect(refusal).toBeInstanceOf(VaultError);
        expect((refusal as VaultError).code).toBe(ErrorCode.LOCAL_PATH_NOT_ALLOWED);
        expect((refusal as VaultError).message).toBe(PROTECTED);
        expect(log.mock.calls).toEqual([[failedRow("clone", "LOCAL_PATH_NOT_ALLOWED")]]);
      },
      120_000,
    );

    it("a clone into a subdirectory of a work tree, beside its .git, is served and the remote's files arrive", async () => {
      const tree = join(root, "wt");
      git(root, "init", "-q", "-b", "main", tree);
      const destination = join(tree, "sub", "new");
      const result = await clone(destination, floorAt(vaultDir));
      expect(result.exit_code, result.stderr).toBe(0);
      expect(existsSync(join(destination, "alternates"))).toBe(true);
      expect(existsSync(join(destination, ".git", "HEAD"))).toBe(true);
    }, 120_000);

    it.each(FLOORS)(
      "a clone without working_directory where the name git derives is a link to an ordinary empty directory lands in that directory, and git is handed it resolved: %s",
      async (_how, floor) => {
        const target = join(root, "target");
        mkdirSync(target);
        const cwd = linkedName(target);
        const result = await cloneFrom(cwd, floor());
        expect(result.exit_code, result.stderr).toBe(0);
        const [, local] = calls()[2] as SpawnCall;
        expect(local.at(-1)).toBe(target);
        expect(result.stderr).toContain(`Cloning into '${target}'...`);
        expect(existsSync(join(target, "top.txt"))).toBe(true);
        expect(existsSync(join(target, ".git", "HEAD"))).toBe(true);
        expect(readdirSync(cwd)).toEqual(["repo"]);
      },
      120_000,
    );

    it("a clone without working_directory where the name git derives is a link into a directory under the floor is refused, nothing written there, no git process beyond the version read", async () => {
      const target = join(vaultDir, "inside");
      mkdirSync(target);
      const cwd = linkedName(target);
      const err = await expectVaultError(
        () => cloneFrom(cwd, floorAt(vaultDir)),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
      expect(err.message).toBe(PROTECTED);
      expect(readdirSync(target)).toEqual([]);
      expect(readVersion).toHaveBeenCalledTimes(1);
      expect(spawnMock).not.toHaveBeenCalled();
      expect(log.mock.calls).toEqual([[failedRow("clone", "LOCAL_PATH_NOT_ALLOWED")]]);
    }, 120_000);

    it.each(FLOORS)(
      "a clone without working_directory where the name git derives is a link into a bare repository's empty objects/info is refused, nothing written there, no git process beyond the version read: %s",
      async (_how, floor) => {
        const bare = join(root, "served");
        git(root, "init", "-q", "--bare", bare);
        const info = join(bare, "objects", "info");
        expect(readdirSync(info)).toEqual([]);
        const cwd = linkedName(info);
        const err = await expectVaultError(
          () => cloneFrom(cwd, floor()),
          ErrorCode.LOCAL_PATH_NOT_ALLOWED,
        );
        expect(err.message).toBe(PROTECTED);
        expect(readdirSync(info)).toEqual([]);
        expect(readVersion).toHaveBeenCalledTimes(1);
        expect(spawnMock).not.toHaveBeenCalled();
        expect(log.mock.calls).toEqual([[failedRow("clone", "LOCAL_PATH_NOT_ALLOWED")]]);
      },
      120_000,
    );

    it("a clone without working_directory where the name git derives is an existing non-empty directory is git's failure: a result with its exit code and a success row, the directory untouched", async () => {
      const cwd = join(root, "cwd");
      mkdirSync(join(cwd, "repo"), { recursive: true });
      writeFileSync(join(cwd, "repo", "kept.txt"), "kept\n");
      const result = await cloneFrom(cwd, floorAt(vaultDir));
      expect(result.exit_code, result.stderr).toBe(128);
      expect(result.error).toBeUndefined();
      expect(log.mock.calls).toEqual([
        [
          expect.objectContaining({
            eventType: "secret.use",
            success: true,
            detail: expect.objectContaining({ context: "git", operation: "clone", exit_code: 128 }),
          }),
        ],
      ]);
      expect(readdirSync(join(cwd, "repo"))).toEqual(["kept.txt"]);
    }, 120_000);
  },
);
