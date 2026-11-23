import {
  chmodSync,
  chownSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import type { Stats } from "node:fs";
import { lstat, stat } from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { join, sep } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { assertRepositoryOwned } from "./git-injector-repository.js";
import type { ServedRepository } from "./git-injector-repository.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, lstat: vi.fn(actual.lstat), stat: vi.fn(actual.stat) };
});
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return { ...actual, userInfo: vi.fn(actual.userInfo) };
});

const actualFs = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
const actualOs = await vi.importActual<typeof import("node:os")>("node:os");

const WIN32 = process.platform === "win32";
const OWNER = "working_directory's repository belongs to another account";
const CHANGEABLE = "working_directory's repository can be changed by another account";
const HEAD_REF = "ref: refs/heads/main\n";

type Call = "lstat" | "stat";

const foreignPaths: Record<Call, Set<string>> = { lstat: new Set(), stat: new Set() };
const refusedReads = new Map<string, string>();

/** The reading as another account's: `uid` one higher, the prototype kept. */
function asForeign(reading: Stats): Stats {
  return Object.assign(Object.create(Object.getPrototypeOf(reading) as object) as Stats, reading, {
    uid: reading.uid + 1,
  });
}

/** Every `lstat` (or `stat`) of `path` in this row answers its real reading as another account's. */
function foreign(path: string, call: Call = "lstat"): void {
  foreignPaths[call].add(path);
}

/** Every `lstat` of `path` in this row rejects with `code`. */
function refuseLstat(path: string, code: string): void {
  refusedReads.set(path, code);
}

function lstatPaths(root: string): string[] {
  return vi
    .mocked(lstat)
    .mock.calls.map(([path]) => String(path))
    .filter((path) => path === root || path.startsWith(`${root}${sep}`));
}

function statPaths(): string[] {
  return vi.mocked(stat).mock.calls.map(([path]) => String(path));
}

/** `dir` as a git directory: `0o755` with `HEAD`, `objects/`, `refs/` and a `0o644` `config`. */
function gitDirectory(dir: string): string {
  mkdirSync(join(dir, "objects"), { recursive: true });
  mkdirSync(join(dir, "refs"));
  writeFileSync(join(dir, "HEAD"), HEAD_REF);
  writeFileSync(join(dir, "config"), "");
  chmodSync(dir, 0o755);
  chmodSync(join(dir, "config"), 0o644);
  return dir;
}

/** `top`, `0o755`, holding a `.git` directory: the repository a plain clone makes. */
function repositoryAt(top: string): ServedRepository {
  mkdirSync(top, { recursive: true });
  chmodSync(top, 0o755);
  const entry = gitDirectory(join(top, ".git"));
  return { top, entry, gitDir: entry, commonDir: null };
}

/** The paths the judgement reads, in its order. */
function judgedPaths(repo: ServedRepository): string[] {
  return [
    repo.top,
    repo.entry,
    repo.gitDir,
    join(repo.gitDir, "config"),
    join(repo.gitDir, "config.worktree"),
    join(repo.gitDir, "commondir"),
    ...(repo.commonDir === null ? [] : [repo.commonDir, join(repo.commonDir, "config")]),
  ];
}

beforeEach(() => {
  vi.mocked(lstat).mockImplementation(async (path, options) => {
    const code = refusedReads.get(String(path));
    if (code !== undefined) throw Object.assign(new Error(code), { code });
    const reading = (await actualFs.lstat(path, options)) as Stats;
    return foreignPaths.lstat.has(String(path)) ? asForeign(reading) : reading;
  });
  vi.mocked(stat).mockImplementation(async (path, options) => {
    const reading = (await actualFs.stat(path, options)) as Stats;
    return foreignPaths.stat.has(String(path)) ? asForeign(reading) : reading;
  });
});

afterEach(() => {
  foreignPaths.lstat.clear();
  foreignPaths.stat.clear();
  refusedReads.clear();
  vi.mocked(lstat).mockReset();
  vi.mocked(stat).mockReset();
  vi.mocked(userInfo).mockReset();
  vi.restoreAllMocks();
});

describe.skipIf(WIN32)(
  "assertRepositoryOwned (POSIX only: on win32 git's own check stands in the owner's place)",
  () => {
    let root: string;
    let top: string;
    let repo: ServedRepository;

    beforeEach(() => {
      root = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-git-owner-")));
      top = join(root, "repo");
      repo = repositoryAt(top);
    });

    afterEach(() => {
      rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    function written(path: string): string {
      writeFileSync(path, "");
      chmodSync(path, 0o644);
      return path;
    }

    /** A linked work tree's shape by hand: `E` names a second git directory in its `commondir`. */
    function linked(): ServedRepository {
      const commonDir = gitDirectory(join(root, "common"));
      writeFileSync(join(repo.gitDir, "commondir"), `${commonDir}\n`);
      chmodSync(join(repo.gitDir, "commondir"), 0o644);
      repo = { ...repo, commonDir };
      return repo;
    }

    /** The fixture's top, `.git` and `config` handed to the account's own primary group. */
    function ownGroup(paths: readonly string[]): number {
      const gid = actualOs.userInfo().gid;
      for (const path of paths) chownSync(path, statSync(path).uid, gid);
      return gid;
    }

    it("the account's own repository is served, outside a daemon with six reads", async () => {
      await expect(assertRepositoryOwned(repo, false)).resolves.toBeUndefined();
      expect(lstatPaths(root)).toEqual([
        top,
        repo.entry,
        repo.gitDir,
        join(repo.gitDir, "config"),
        join(repo.gitDir, "config.worktree"),
        join(repo.gitDir, "commondir"),
      ]);
      expect(vi.mocked(stat)).not.toHaveBeenCalled();
    });

    const FOREIGN: ReadonlyArray<readonly [string, () => string]> = [
      ["top", () => repo.top],
      [".git entry", () => repo.entry],
      ["git directory", () => repo.gitDir],
      ["config", () => join(repo.gitDir, "config")],
      ["config.worktree", () => written(join(repo.gitDir, "config.worktree"))],
      ["commondir file", () => written(join(repo.gitDir, "commondir"))],
      ["common directory", () => linked().commonDir as string],
      ["common directory's config", () => join(linked().commonDir as string, "config")],
    ];

    it.each(
      FOREIGN.flatMap(([label, make]) =>
        [false, true].map((daemon) => [label, daemon, make] as const),
      ),
    )(
      "another account's %s refuses, daemon %s: the owner's message, and no path after it is read",
      async (_label, daemon, make) => {
        const path = make();
        foreign(path);
        const err = await expectVaultError(
          () => assertRepositoryOwned(repo, daemon),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(OWNER);
        const judged = judgedPaths(repo);
        expect(lstatPaths(root)).toEqual(judged.slice(0, judged.indexOf(path) + 1));
      },
    );

    /** The gitfile shape by hand: the top's `.git` a file that names a git directory beside the tree. */
    function behindGitfile(): ServedRepository {
      const gitDir = gitDirectory(join(root, "separate"));
      const wt = join(root, "wt");
      mkdirSync(wt);
      chmodSync(wt, 0o755);
      const entry = written(join(wt, ".git"));
      writeFileSync(entry, `gitdir: ${gitDir}\n`);
      return { top: wt, entry, gitDir, commonDir: null };
    }

    it.each([false, true])(
      "another account's git directory behind a gitfile, distinct from the entry, refuses, daemon %s: the top, the entry and the git directory are read, no path after them",
      async (daemon) => {
        const served = behindGitfile();
        await expect(assertRepositoryOwned(served, daemon)).resolves.toBeUndefined();
        vi.mocked(lstat).mockClear();

        foreign(served.gitDir);
        const err = await expectVaultError(
          () => assertRepositoryOwned(served, daemon),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(OWNER);
        expect(lstatPaths(root)).toEqual([served.top, served.entry, served.gitDir]);
      },
    );

    describe("a link is read itself and where it leads", () => {
      function linkedEntry(): ServedRepository {
        const gitDir = gitDirectory(join(root, "beside"));
        const linkedTop = join(root, "linked");
        mkdirSync(linkedTop);
        chmodSync(linkedTop, 0o755);
        symlinkSync(gitDir, join(linkedTop, ".git"));
        return { top: linkedTop, entry: join(linkedTop, ".git"), gitDir, commonDir: null };
      }

      it.each([false, true])(
        "the entry a link to a directory beside the tree is served, stat called once, for the entry, daemon %s",
        async (daemon) => {
          const served = linkedEntry();
          await expect(assertRepositoryOwned(served, daemon)).resolves.toBeUndefined();
          expect(statPaths()).toEqual([served.entry]);
        },
      );

      it.each([false, true])(
        "the link's own reading another account's refuses, daemon %s",
        async (daemon) => {
          const served = linkedEntry();
          foreign(served.entry, "lstat");
          const err = await expectVaultError(
            () => assertRepositoryOwned(served, daemon),
            ErrorCode.INVALID_GIT_CONFIG,
          );
          expect(err.message).toBe(OWNER);
        },
      );

      it.each([false, true])(
        "what the link leads to another account's refuses, daemon %s",
        async (daemon) => {
          const served = linkedEntry();
          foreign(served.entry, "stat");
          const err = await expectVaultError(
            () => assertRepositoryOwned(served, daemon),
            ErrorCode.INVALID_GIT_CONFIG,
          );
          expect(err.message).toBe(OWNER);
          expect(statPaths()).toEqual([served.entry]);
        },
      );

      it.each([false, true])(
        "a config that is a link leading nowhere refuses, daemon %s",
        async (daemon) => {
          const config = join(repo.gitDir, "config");
          unlinkSync(config);
          symlinkSync(join(root, "gone"), config);
          const err = await expectVaultError(
            () => assertRepositoryOwned(repo, daemon),
            ErrorCode.INVALID_GIT_CONFIG,
          );
          expect(err.message).toBe(OWNER);
          expect(statPaths()).toEqual([config]);
        },
      );
    });

    describe("a path that cannot be read", () => {
      it.each([
        ["the git directory", "EACCES", () => repo.gitDir],
        ["config", "EACCES", () => join(repo.gitDir, "config")],
        ["the top", "ENOENT", () => repo.top],
      ] as const)(
        "%s answering %s refuses with the owner's message",
        async (_label, code, path) => {
          refuseLstat(path(), code);
          const err = await expectVaultError(
            () => assertRepositoryOwned(repo, false),
            ErrorCode.INVALID_GIT_CONFIG,
          );
          expect(err.message).toBe(OWNER);
        },
      );

      it.each(["ENOENT", "ENOTDIR"])("config answering %s is absent and served", async (code) => {
        refuseLstat(join(repo.gitDir, "config"), code);
        await expect(assertRepositoryOwned(repo, false)).resolves.toBeUndefined();
        await expect(assertRepositoryOwned(repo, true)).resolves.toBeUndefined();
      });
    });

    it("without geteuid the repository is refused", async () => {
      const geteuid = process.geteuid;
      process.geteuid = undefined;
      try {
        const err = await expectVaultError(
          () => assertRepositoryOwned(repo, false),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(OWNER);
      } finally {
        process.geteuid = geteuid;
      }
    });

    it.each([
      ["the top", "0757", 0o757, () => repo.top],
      ["the .git entry", "0757", 0o757, () => repo.entry],
      ["config", "0646", 0o646, () => join(repo.gitDir, "config")],
    ] as const)(
      "in a daemon a write bit for others refuses, outside one it does not: %s at %s",
      async (_label, _shown, mode, path) => {
        chmodSync(path(), mode);
        const err = await expectVaultError(
          () => assertRepositoryOwned(repo, true),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(CHANGEABLE);
        await expect(assertRepositoryOwned(repo, false)).resolves.toBeUndefined();
      },
    );

    it("in a daemon the group's write bit passes for the account's own primary group alone", async () => {
      const config = join(repo.gitDir, "config");
      const gid = ownGroup([top, repo.entry, config]);
      chmodSync(top, 0o775);
      chmodSync(repo.entry, 0o775);
      chmodSync(config, 0o664);
      await expect(assertRepositoryOwned(repo, true)).resolves.toBeUndefined();

      vi.mocked(userInfo).mockImplementation(() => ({ ...actualOs.userInfo(), gid: gid + 1 }));
      const another = await expectVaultError(
        () => assertRepositoryOwned(repo, true),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(another.message).toBe(CHANGEABLE);

      vi.mocked(userInfo).mockImplementation(() => {
        throw Object.assign(new Error("uv_os_get_passwd"), { code: "ERR_SYSTEM_ERROR" });
      });
      const none = await expectVaultError(
        () => assertRepositoryOwned(repo, true),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(none.message).toBe(CHANGEABLE);

      vi.mocked(userInfo).mockReset();
      vi.spyOn(process, "getegid").mockReturnValue(gid + 1);
      await expect(assertRepositoryOwned(repo, true)).resolves.toBeUndefined();
    });

    it("the owner's message wins over the bits", async () => {
      foreign(join(repo.gitDir, "config"));
      chmodSync(top, 0o777);
      const err = await expectVaultError(
        () => assertRepositoryOwned(repo, true),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toBe(OWNER);
    });

    describe("in a daemon the directories above are walked", () => {
      function openParent(mode: number): string {
        const open = join(root, "open");
        mkdirSync(open);
        chmodSync(open, mode);
        return open;
      }

      it("a parent 0777 holding the repository refuses, outside a daemon it is served", async () => {
        const held = repositoryAt(join(openParent(0o777), "repo"));
        const err = await expectVaultError(
          () => assertRepositoryOwned(held, true),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(CHANGEABLE);
        await expect(assertRepositoryOwned(held, false)).resolves.toBeUndefined();
      });

      it("a parent 0777 holding a work tree whose git directory lies outside it refuses, outside a daemon it is served", async () => {
        const gitDir = gitDirectory(join(root, "outside.git"));
        const wt = join(openParent(0o777), "wt");
        mkdirSync(wt);
        chmodSync(wt, 0o755);
        writeFileSync(join(wt, ".git"), `gitdir: ${gitDir}\n`);
        chmodSync(join(wt, ".git"), 0o644);
        const held: ServedRepository = {
          top: wt,
          entry: join(wt, ".git"),
          gitDir,
          commonDir: null,
        };
        const err = await expectVaultError(
          () => assertRepositoryOwned(held, true),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(CHANGEABLE);
        await expect(assertRepositoryOwned(held, false)).resolves.toBeUndefined();
      });

      it("a parent 0775 of the account's own group is served, and refused once userInfo answers another gid", async () => {
        const open = openParent(0o775);
        const gid = ownGroup([open]);
        const held = repositoryAt(join(open, "repo"));
        await expect(assertRepositoryOwned(held, true)).resolves.toBeUndefined();
        vi.mocked(userInfo).mockImplementation(() => ({ ...actualOs.userInfo(), gid: gid + 1 }));
        const err = await expectVaultError(
          () => assertRepositoryOwned(held, true),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(CHANGEABLE);
      });

      it("a repository that is itself a directory straight in the root-owned sticky /tmp is served", async () => {
        const sticky = realpathSync("/tmp");
        expect(statSync(sticky).mode & 0o1002).toBe(0o1002);
        const made = realpathSync(mkdtempSync(join(sticky, "harpoc-git-owner-tmp-")));
        try {
          const held: ServedRepository = {
            top: made,
            entry: gitDirectory(join(made, ".git")),
            gitDir: join(made, ".git"),
            commonDir: null,
          };
          await expect(assertRepositoryOwned(held, true)).resolves.toBeUndefined();
        } finally {
          rmSync(made, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        }
      });

      it("a git directory outside the top under a 0777 parent refuses, outside a daemon it is served", async () => {
        const gitDir = gitDirectory(join(openParent(0o777), "sep.git"));
        const wt = join(root, "wt");
        mkdirSync(wt);
        chmodSync(wt, 0o755);
        writeFileSync(join(wt, ".git"), `gitdir: ${gitDir}\n`);
        chmodSync(join(wt, ".git"), 0o644);
        const held: ServedRepository = {
          top: wt,
          entry: join(wt, ".git"),
          gitDir,
          commonDir: null,
        };
        const err = await expectVaultError(
          () => assertRepositoryOwned(held, true),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(CHANGEABLE);
        await expect(assertRepositoryOwned(held, false)).resolves.toBeUndefined();
      });

      it("a common directory under a 0777 parent refuses, outside a daemon it is served", async () => {
        const commonDir = gitDirectory(join(openParent(0o777), "main.git"));
        const gitDir = join(root, "linked.git");
        mkdirSync(gitDir);
        chmodSync(gitDir, 0o755);
        writeFileSync(join(gitDir, "HEAD"), HEAD_REF);
        writeFileSync(join(gitDir, "commondir"), `${commonDir}\n`);
        chmodSync(join(gitDir, "commondir"), 0o644);
        const wt = join(root, "wt");
        mkdirSync(wt);
        chmodSync(wt, 0o755);
        writeFileSync(join(wt, ".git"), `gitdir: ${gitDir}\n`);
        chmodSync(join(wt, ".git"), 0o644);
        const held: ServedRepository = { top: wt, entry: join(wt, ".git"), gitDir, commonDir };
        const err = await expectVaultError(
          () => assertRepositoryOwned(held, true),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(CHANGEABLE);
        await expect(assertRepositoryOwned(held, false)).resolves.toBeUndefined();
      });
    });
  },
);

it.runIf(WIN32)(
  "on win32 nothing is read: a repository of paths that do not exist resolves, daemon or not",
  async () => {
    const absent = join(tmpdir(), "harpoc-git-owner-absent-0b6c2e");
    const repo: ServedRepository = {
      top: absent,
      entry: join(absent, ".git"),
      gitDir: join(absent, ".git"),
      commonDir: join(absent, "common"),
    };
    await expect(assertRepositoryOwned(repo, false)).resolves.toBeUndefined();
    await expect(assertRepositoryOwned(repo, true)).resolves.toBeUndefined();
    expect(vi.mocked(lstat)).not.toHaveBeenCalled();
    expect(vi.mocked(stat)).not.toHaveBeenCalled();
  },
);
