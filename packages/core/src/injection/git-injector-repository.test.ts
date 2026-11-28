import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { lstat, open, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import {
  commondirPath,
  derivedCloneDirectory,
  findServedRepository,
  gitfilePath,
} from "./git-injector-repository.js";
import type { ServedRepository } from "./git-injector-repository.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    lstat: vi.fn(actual.lstat),
    open: vi.fn(actual.open),
    stat: vi.fn(actual.stat),
  };
});

const GIT = resolveSupportedGit();
const WIN32 = process.platform === "win32";

const BACKSLASH_ADDRESS = "https://h/org\\.git.git";
const TRAILING_DOT_ADDRESS = "https://h/org/.git..git";
const PARENT_NAME_ADDRESS = "https://h/org/..git";

/** The address, the directory a clone derives from it on linux, on win32; null where it derives none. */
const DERIVED: ReadonlyArray<readonly [string, string | null, string | null]> = [
  ["https://h/org/repo.git", "repo", "repo"],
  ["https://h/org/repo", "repo", "repo"],
  ["https://h/org/repo.git/", "repo", "repo"],
  ["git@h:org/repo.git", "repo", "repo"],
  ["ssh://git@h:2222/org/repo.git", "repo", "repo"],
  ["https://h/org/.git", "org", "org"],
  ["https://h/.git", "h", "h"],
  ["https://h/org/.git.git", ".git", ".git"],
  ["git@h:.git.git", ".git", ".git"],
  ["git@h:org/.git.git", ".git", ".git"],
  ["https://h/org/x:.git.git", ".git", ".git"],
  ["https://h/org/.GIT.git", ".GIT", ".GIT"],
  [TRAILING_DOT_ADDRESS, ".git.", ".git."],
  ["https://h/org/git~1.git", "git~1", "git~1"],
  ["https://h/org/\u200c.git.git", "\u200c.git", "\u200c.git"],
  ["https://h/org/ .git.git", ".git", ".git"],
  ["https://h/org/.git .git", ".git", ".git"],
  ["https://h/org/\x01.git.git", ".git", ".git"],
  ["https://h/org/.git/.git", null, null],
  ["https://h/org/x:.git", null, null],
  ["https://h/org/ .git", null, null],
  [BACKSLASH_ADDRESS, "org\\.git", ".git"],
  [PARENT_NAME_ADDRESS, null, null],
  ["https://h/org/...git", null, null],
];

const GIT_MAKES_NO_NAME = [
  "https://h/org/.git/.git",
  "https://h/org/x:.git",
  "https://h/org/ .git",
];
const GIT_MAKES_A_DIRECTORY = DERIVED.filter(
  ([address, linux, win32]) => linux !== null && win32 !== null && address !== TRAILING_DOT_ADDRESS,
).map(([address]) => address);

function shown(text: string): string {
  return `"${text.replace(
    /[^\x21-\x7e]/g,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
  )}"`;
}

describe("derivedCloneDirectory", () => {
  it.each(
    DERIVED.flatMap(([address, linux, win32]) => [
      [shown(address), "linux", linux === null ? "no name" : shown(linux), address, linux] as const,
      [shown(address), "win32", win32 === null ? "no name" : shown(win32), address, win32] as const,
    ]),
  )("%s on %s derives %s", (_shown, platform, _derived, address, expected) => {
    expect(derivedCloneDirectory(address, platform)).toBe(expected);
  });
});

describe.skipIf(GIT === null)(
  "git derives the same directory (skipped where no supported git resolves)",
  () => {
    let root: string;
    let seedUrl: string;
    let env: NodeJS.ProcessEnv;

    function git(cwd: string, ...args: string[]): void {
      execFileSync(GIT as string, args, { cwd, env, stdio: "ignore" });
    }

    function cloneWithoutDestination(address: string): { status: number | null; made: string[] } {
      const dir = mkdtempSync(join(root, "clone-"));
      const cloned = spawnSync(
        GIT as string,
        [
          "-c",
          "protocol.allow=never",
          "-c",
          "protocol.file.allow=always",
          "-c",
          `url.${seedUrl}.insteadOf=${address}`,
          "clone",
          "-q",
          "--",
          address,
        ],
        { cwd: dir, env, stdio: "ignore" },
      );
      if (cloned.error !== undefined) throw cloned.error;
      return { status: cloned.status, made: readdirSync(dir).sort() };
    }

    beforeAll(() => {
      root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-repository-")));
      const emptyConfig = join(root, "empty.gitconfig");
      writeFileSync(emptyConfig, "");
      env = {
        ...process.env,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: emptyConfig,
        GIT_TERMINAL_PROMPT: "0",
        GIT_AUTHOR_NAME: "harpoc-test",
        GIT_AUTHOR_EMAIL: "test@example.com",
        GIT_COMMITTER_NAME: "harpoc-test",
        GIT_COMMITTER_EMAIL: "test@example.com",
      };
      const seed = join(root, "seed");
      mkdirSync(seed);
      git(seed, "init", "-q", "-b", "main");
      writeFileSync(join(seed, "file.txt"), "1\n");
      git(seed, "add", "file.txt");
      git(seed, "commit", "-q", "-m", "c1");
      const bare = join(root, "seed.git");
      git(root, "clone", "-q", "--bare", seed, bare);
      const slashed = bare.replace(/\\/g, "/");
      seedUrl = slashed.startsWith("/") ? `file://${slashed}` : `file:///${slashed}`;
    });

    afterAll(() => {
      if (root !== undefined)
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    it.each(GIT_MAKES_A_DIRECTORY.map((address) => [shown(address), address]))(
      "a clone of %s without a destination makes exactly the directory the function names",
      (_shown, address) => {
        expect(cloneWithoutDestination(address)).toEqual({
          status: 0,
          made: [derivedCloneDirectory(address, process.platform)],
        });
      },
    );

    it.skipIf(WIN32)(
      `a clone of ${TRAILING_DOT_ADDRESS} without a destination makes exactly the directory the function names (skipped on win32, where git cannot make a directory whose name ends in a dot)`,
      () => {
        expect(cloneWithoutDestination(TRAILING_DOT_ADDRESS)).toEqual({
          status: 0,
          made: [derivedCloneDirectory(TRAILING_DOT_ADDRESS, process.platform)],
        });
      },
    );

    it.each(GIT_MAKES_NO_NAME.map((address) => [shown(address), address]))(
      "a clone of %s without a destination derives no name: git exits 128 and makes nothing, and the function answers no name",
      (_shown, address) => {
        expect(cloneWithoutDestination(address)).toEqual({ status: 128, made: [] });
        expect(derivedCloneDirectory(address, process.platform)).toBeNull();
      },
    );

    it(`a clone of ${PARENT_NAME_ADDRESS} without a destination lands in the directory git was started in, which the function answers as no name`, () => {
      const { status, made } = cloneWithoutDestination(PARENT_NAME_ADDRESS);
      expect(status).toBe(0);
      expect(made).toEqual([".git", "file.txt"]);
      expect(derivedCloneDirectory(PARENT_NAME_ADDRESS, process.platform)).toBeNull();
    });
  },
);

const NOT_SERVED = "working_directory is not in a repository the vault serves";
const HEAD_REF = "ref: refs/heads/main\n";
const MAX_GITFILE_BYTES = 1_048_576;

/** A gitfile's bytes (each code unit one byte), the path it names on linux and darwin, on win32; null where it names none. */
const GITFILES: ReadonlyArray<readonly [string, string | null, string | null]> = [
  ["gitdir: /abs/x\n", "/abs/x", null],
  ["gitdir: /x", "/x", null],
  ["gitdir: \\x", "\\x", null],
  ["gitdir: /", "/", null],
  ["gitdir: //server/share/x", "//server/share/x", "//server/share/x"],
  ["gitdir: \\\\?\\C:\\x", "\\\\?\\C:\\x", "\\\\?\\C:\\x"],
  ["gitdir: C:/x", "C:/x", "C:/x"],
  ["gitdir: ../x.git", "../x.git", "../x.git"],
  ["gitdir: x\r\n", "x", "x"],
  ["gitdir: x\n\n\r\n", "x", "x"],
  ["gitdir:x", null, null],
  ["gitdir:  x", null, null],
  ["Gitdir: x", null, null],
  [" gitdir: x", null, null],
  ["gitdir: x \n", null, null],
  ["gitdir: x\t\n", null, null],
  ["gitdir: x\ny\n", null, null],
  ["gitdir: x\ry\n", null, null],
  ["gitdir: x\x00y\n", null, null],
  ["gitdir: \n", null, null],
  ["gitdir: ", null, null],
  ["", null, null],
  ["gitdir: \xff\n", null, null],
  ["gitdir: C:x\n", "C:x", null],
];

/** The refused gitfiles whose x can stand for a relative path: not one rooted by a single separator. */
const REFUSED_GITFILES = GITFILES.filter(
  ([content, linux, win32]) =>
    (WIN32 ? win32 : linux) === null && !/^gitdir: [\\/](?![\\/])/.test(content),
).map(([content]) => content);

describe("gitfilePath", () => {
  it.each(
    GITFILES.flatMap(([content, linux, win32]) => [
      [shown(content), "linux", linux === null ? "no path" : shown(linux), content, linux] as const,
      [
        shown(content),
        "darwin",
        linux === null ? "no path" : shown(linux),
        content,
        linux,
      ] as const,
      [shown(content), "win32", win32 === null ? "no path" : shown(win32), content, win32] as const,
    ]),
  )("%s on %s names %s", (_shown, platform, _named, content, expected) => {
    expect(gitfilePath(Buffer.from(content, "latin1"), platform)).toBe(expected);
  });
});

/** A `commondir` file's bytes (each code unit one byte), the path it names on linux, on win32; null where it names none. */
const COMMONDIRS: ReadonlyArray<readonly [string, string | null, string | null]> = [
  ["../..\n", "../..", "../.."],
  ["..\r\n", "..", ".."],
  ["", null, null],
  ["\n", null, null],
  ["\xff\n", null, null],
  ["x\x00y", null, null],
  ["a\nb", null, null],
  [" x", null, null],
  ["x ", null, null],
  ["\tx", null, null],
  ["C:x", "C:x", null],
  ["/x", "/x", null],
  ["\\x", "\\x", null],
  ["C:\\x", "C:\\x", "C:\\x"],
  ["//s/h/x", "//s/h/x", "//s/h/x"],
];

describe("commondirPath", () => {
  it.each(
    COMMONDIRS.flatMap(([content, linux, win32]) => [
      [shown(content), "linux", linux === null ? "no path" : shown(linux), content, linux] as const,
      [shown(content), "win32", win32 === null ? "no path" : shown(win32), content, win32] as const,
    ]),
  )("%s on %s names %s", (_shown, platform, _named, content, expected) => {
    expect(commondirPath(Buffer.from(content, "latin1"), platform)).toBe(expected);
  });
});

function gitDirectory(dir: string): string {
  mkdirSync(join(dir, "objects"), { recursive: true });
  mkdirSync(join(dir, "refs"));
  writeFileSync(join(dir, "HEAD"), HEAD_REF);
  return dir;
}

/** A link to a directory: a junction on win32, which needs no privilege. */
function directoryLink(target: string, link: string): void {
  symlinkSync(target, link, WIN32 ? "junction" : "dir");
}

function errno(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(code), { code });
}

async function expectNotServed(dir: string): Promise<void> {
  const err = await expectVaultError(() => findServedRepository(dir), ErrorCode.INVALID_GIT_CONFIG);
  expect(err.message).toBe(NOT_SERVED);
}

describe("findServedRepository", () => {
  let root: string;
  let wt: string;
  let gd: string;

  beforeEach(() => {
    root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-served-")));
    wt = join(root, "wt");
    gd = join(root, "gd");
  });

  afterEach(() => {
    vi.mocked(lstat).mockReset();
    vi.mocked(open).mockReset();
    vi.mocked(stat).mockReset();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  function served(top: string, gitDir: string, commonDir: string | null = null): ServedRepository {
    return { top, entry: join(top, ".git"), gitDir, commonDir };
  }

  function gitfile(content: string | Buffer): void {
    mkdirSync(wt, { recursive: true });
    writeFileSync(join(wt, ".git"), content);
  }

  async function answerLstat(
    answer: (path: string) => NodeJS.ErrnoException | null,
  ): Promise<void> {
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    vi.mocked(lstat).mockImplementation(async (path, options) => {
      const refused = answer(String(path));
      if (refused !== null) throw refused;
      return actual.lstat(path, options);
    });
  }

  /** `path` without its drive, each separator `separator`. */
  function withoutDrive(path: string, separator: string): string {
    return path.replace(/^[A-Za-z]:/, "").replace(/\\/g, separator);
  }

  /** `judge` run with the process in `root`, so a path without a drive names a path on root's drive. */
  async function fromRoot(judge: () => Promise<void>): Promise<void> {
    const saved = process.cwd();
    process.chdir(root);
    try {
      await judge();
    } finally {
      process.chdir(saved);
    }
  }

  const SERVED: ReadonlyArray<readonly [string, () => { named: string; repo: ServedRepository }]> =
    [
      [
        "a .git directory, named from the top",
        () => {
          gitDirectory(join(wt, ".git"));
          return { named: wt, repo: served(wt, join(wt, ".git")) };
        },
      ],
      [
        "a .git directory, named from sub/deep",
        () => {
          gitDirectory(join(wt, ".git"));
          mkdirSync(join(wt, "sub", "deep"), { recursive: true });
          return { named: join(wt, "sub", "deep"), repo: served(wt, join(wt, ".git")) };
        },
      ],
      [
        "a gitfile with an absolute path",
        () => {
          gitfile(`gitdir: ${gitDirectory(gd)}\n`);
          return { named: wt, repo: served(wt, gd) };
        },
      ],
      [
        "a gitfile with a relative path",
        () => {
          gitDirectory(gd);
          gitfile("gitdir: ../gd\n");
          return { named: wt, repo: served(wt, gd) };
        },
      ],
      [
        "a gitfile with CR LF",
        () => {
          gitDirectory(gd);
          gitfile("gitdir: ../gd\r\n");
          return { named: wt, repo: served(wt, gd) };
        },
      ],
      [
        "a .git that is a link to a directory (a junction on win32)",
        () => {
          gitDirectory(gd);
          mkdirSync(wt);
          directoryLink(gd, join(wt, ".git"));
          return { named: wt, repo: served(wt, gd) };
        },
      ],
      [
        "an E whose commondir is ../..: the common directory resolved",
        () => {
          const main = gitDirectory(join(root, "main", ".git"));
          const linked = join(main, "worktrees", "t");
          mkdirSync(linked, { recursive: true });
          writeFileSync(join(linked, "HEAD"), HEAD_REF);
          writeFileSync(join(linked, "commondir"), "../..\n");
          gitfile(`gitdir: ${linked}\n`);
          return { named: wt, repo: served(wt, linked, main) };
        },
      ],
      [
        "an E whose commondir names its common directory through a link (a junction on win32): the link's target",
        () => {
          const main = gitDirectory(join(root, "main", ".git"));
          directoryLink(main, join(root, "main-link"));
          const linked = join(main, "worktrees", "t");
          mkdirSync(linked, { recursive: true });
          writeFileSync(join(linked, "HEAD"), HEAD_REF);
          writeFileSync(join(linked, "commondir"), `${join(root, "main-link")}\n`);
          gitfile(`gitdir: ${linked}\n`);
          return { named: wt, repo: served(wt, linked, main) };
        },
      ],
    ];

  it.each(SERVED)("served: %s", async (_label, make) => {
    const { named, repo } = make();
    expect(await findServedRepository(named)).toEqual(repo);
  });

  it.skipIf(WIN32)(
    "served: a .git that is a link to a gitfile kept elsewhere with a relative path, read from the top (skipped on win32, where a file link needs a privilege)",
    async () => {
      gitDirectory(gd);
      const kept = join(root, "a", "b");
      mkdirSync(kept, { recursive: true });
      writeFileSync(join(kept, "gitfile"), "gitdir: ../gd\n");
      mkdirSync(wt);
      symlinkSync(join(kept, "gitfile"), join(wt, ".git"));
      expect(await findServedRepository(wt)).toEqual(served(wt, gd));
    },
  );

  const REFUSED: ReadonlyArray<readonly [string, () => string]> = [
    [
      "the named directory has the shape",
      () => {
        gitDirectory(join(wt, ".git"));
        return gitDirectory(join(wt, "planted"));
      },
    ],
    [
      "a directory between has the shape: <wt>/a/planted/b",
      () => {
        gitDirectory(join(wt, ".git"));
        gitDirectory(join(wt, "a", "planted"));
        mkdirSync(join(wt, "a", "planted", "b"));
        return join(wt, "a", "planted", "b");
      },
    ],
    [
      "a directory between holds HEAD and commondir alone",
      () => {
        gitDirectory(join(wt, ".git"));
        const planted = join(wt, "planted");
        mkdirSync(join(planted, "b"), { recursive: true });
        writeFileSync(join(planted, "HEAD"), HEAD_REF);
        writeFileSync(join(planted, "commondir"), "../.git\n");
        return join(planted, "b");
      },
    ],
    [
      ".git a directory without HEAD",
      () => {
        mkdirSync(join(wt, ".git", "objects"), { recursive: true });
        mkdirSync(join(wt, ".git", "refs"));
        return wt;
      },
    ],
    [
      ".git an empty file",
      () => {
        gitfile("");
        return wt;
      },
    ],
    [
      "a gitfile naming a directory without the shape",
      () => {
        mkdirSync(gd);
        gitfile("gitdir: ../gd\n");
        return wt;
      },
    ],
    [
      "a gitfile naming a path that does not exist",
      () => {
        gitfile("gitdir: ../gd\n");
        return wt;
      },
    ],
    [
      "a gitfile naming a file",
      () => {
        writeFileSync(gd, HEAD_REF);
        gitfile("gitdir: ../gd\n");
        return wt;
      },
    ],
    [
      ".git a link that leads nowhere (a junction on win32)",
      () => {
        mkdirSync(wt);
        directoryLink(join(root, "gone"), join(wt, ".git"));
        return wt;
      },
    ],
    [
      "E holds a .git entry: the work tree named .git",
      () => {
        const b = join(root, "B");
        gitDirectory(join(b, ".git"));
        gitDirectory(join(b, ".git", ".git"));
        return b;
      },
    ],
    [
      "E's commondir is empty",
      () => {
        writeFileSync(join(gitDirectory(gd), "commondir"), "\n");
        gitfile("gitdir: ../gd\n");
        return wt;
      },
    ],
    [
      "E's commondir names a missing directory",
      () => {
        writeFileSync(join(gitDirectory(gd), "commondir"), "../missing\n");
        gitfile("gitdir: ../gd\n");
        return wt;
      },
    ],
    [
      "E's commondir is a link that leads nowhere (a junction on win32), the entry its shape was counted by",
      () => {
        mkdirSync(gd);
        writeFileSync(join(gd, "HEAD"), HEAD_REF);
        directoryLink(join(root, "gone"), join(gd, "commondir"));
        gitfile("gitdir: ../gd\n");
        return wt;
      },
    ],
    [
      "a linked work tree whose commondir holds a leading blank, the name it spells a link (a junction on win32) to the common directory",
      () => {
        const main = gitDirectory(join(root, "main", ".git"));
        const linked = join(main, "worktrees", "t");
        mkdirSync(linked, { recursive: true });
        writeFileSync(join(linked, "HEAD"), HEAD_REF);
        directoryLink(main, join(linked, " common"));
        writeFileSync(join(linked, "commondir"), " common\n");
        gitfile(`gitdir: ${linked}\n`);
        return wt;
      },
    ],
    [
      "E's commondir naming, through a link (a junction on win32), a name that holds U+FFFD",
      () => {
        directoryLink(gitDirectory(join(root, "main", ".git")), join(root, "l\uFFFDnk"));
        const linked = join(root, "linked");
        mkdirSync(linked);
        writeFileSync(join(linked, "HEAD"), HEAD_REF);
        writeFileSync(join(linked, "commondir"), `${join(root, "l\uFFFDnk")}\n`);
        gitfile(`gitdir: ${linked}\n`);
        return wt;
      },
    ],
    [
      "E's commondir naming a link (a junction on win32) to a common directory whose name holds U+FFFD",
      () => {
        directoryLink(gitDirectory(join(root, "m\uFFFDin", ".git")), join(root, "main-link"));
        const linked = join(root, "linked");
        mkdirSync(linked);
        writeFileSync(join(linked, "HEAD"), HEAD_REF);
        writeFileSync(join(linked, "commondir"), `${join(root, "main-link")}\n`);
        gitfile(`gitdir: ${linked}\n`);
        return wt;
      },
    ],
    [
      "a gitfile naming, through a link (a junction on win32), a name that holds U+FFFD",
      () => {
        directoryLink(gitDirectory(gd), join(root, "l\uFFFDnk"));
        gitfile(Buffer.from("gitdir: ../l\uFFFDnk\n", "utf8"));
        return wt;
      },
    ],
    [
      "a .git that is a link (a junction on win32) to a git directory whose name holds U+FFFD",
      () => {
        mkdirSync(wt);
        directoryLink(gitDirectory(join(root, "g\uFFFDd")), join(wt, ".git"));
        return wt;
      },
    ],
  ];

  it.each(REFUSED)("refused: %s", async (_label, make) => {
    await expectNotServed(make());
  });

  // Only the Win32 path layer drops a trailing dot from a name; Node reads it as spelled.
  it.runIf(WIN32)(
    "refused: a gitfile naming, through a junction, a name that ends in a dot",
    async () => {
      directoryLink(gitDirectory(gd), join(root, "link."));
      gitfile("gitdir: ../link.\n");
      await expectNotServed(wt);
    },
  );

  it.runIf(WIN32)(
    "refused: a linked work tree whose commondir names <common>. beside <common>, a name that ends in a dot (win32 alone, whose path layer drops the dot Node reads as spelled)",
    async () => {
      const main = gitDirectory(join(root, "main", ".git"));
      mkdirSync(`${main}.`);
      const linked = join(main, "worktrees", "t");
      mkdirSync(linked, { recursive: true });
      writeFileSync(join(linked, "HEAD"), HEAD_REF);
      writeFileSync(join(linked, "commondir"), `${main}.\n`);
      gitfile(`gitdir: ${linked}\n`);
      await expectNotServed(wt);
    },
  );

  it.runIf(WIN32).each(["\\", "/"])(
    "refused: a gitfile naming the git directory rooted by %s without a drive; with the drive it is served (win32 alone, where such a path is read on the process's drive)",
    async (separator) => {
      gitDirectory(gd);
      gitfile(`gitdir: ${withoutDrive(gd, separator)}\n`);
      await fromRoot(() => expectNotServed(wt));

      gitfile(`gitdir: ${gd}\n`);
      expect(await findServedRepository(wt)).toEqual(served(wt, gd));
    },
  );

  it.runIf(WIN32).each(["\\", "/"])(
    "refused: a linked work tree whose commondir names the common directory rooted by %s without a drive; with the drive it is served (win32 alone, where such a path is read on the process's drive)",
    async (separator) => {
      const main = gitDirectory(join(root, "main", ".git"));
      const linked = join(main, "worktrees", "t");
      mkdirSync(linked, { recursive: true });
      writeFileSync(join(linked, "HEAD"), HEAD_REF);
      writeFileSync(join(linked, "commondir"), `${withoutDrive(main, separator)}\n`);
      gitfile(`gitdir: ${linked}\n`);
      await fromRoot(() => expectNotServed(wt));

      writeFileSync(join(linked, "commondir"), `${main}\n`);
      expect(await findServedRepository(wt)).toEqual(served(wt, linked, main));
    },
  );

  it("refused: no .git up to the root, the walk ended at the fixture's root by an lstat that answers ENOENT above it", async () => {
    const plain = join(root, "plain");
    mkdirSync(plain);
    await answerLstat((path) => (path.startsWith(`${root}${sep}`) ? null : errno("ENOENT")));
    await expectNotServed(plain);
    expect(vi.mocked(lstat).mock.calls.map(([path]) => path)).toContain(join(root, "..", ".git"));
  });

  it.each(REFUSED_GITFILES.map((content) => [shown(content), content]))(
    "refused: a gitfile %s, its x a git directory's relative path",
    async (_shown, content) => {
      gitDirectory(gd);
      gitfile(Buffer.from(content.replace("x", "../gd"), "latin1"));
      await expectNotServed(wt);

      gitfile("gitdir: ../gd\n");
      expect(await findServedRepository(wt)).toEqual(served(wt, gd));
    },
  );

  it("refused: a gitfile of 1 048 577 bytes; one of 1 048 576 is served", async () => {
    gitDirectory(gd);
    const line = "gitdir: ../gd";
    gitfile(line + "\n".repeat(MAX_GITFILE_BYTES + 1 - line.length));
    await expectNotServed(wt);

    gitfile(line + "\n".repeat(MAX_GITFILE_BYTES - line.length));
    expect(await findServedRepository(wt)).toEqual(served(wt, gd));
  });

  it.skipIf(WIN32)(
    "refused: .git a FIFO, which is never opened (skipped on win32, which has no FIFO)",
    async () => {
      mkdirSync(wt);
      execFileSync("mkfifo", [join(wt, ".git")]);
      await expectNotServed(wt);
      expect(vi.mocked(open).mock.calls.map(([path]) => path)).not.toContain(join(wt, ".git"));
    },
  );

  it.skipIf(WIN32)(
    "refused: .git exchanged for a FIFO after its stat answered a regular file, read without blocking (skipped on win32, which has no FIFO)",
    { timeout: 3_000 },
    async () => {
      mkdirSync(wt);
      const fifo = join(wt, ".git");
      execFileSync("mkfifo", [fifo]);
      const regular = join(root, "regular");
      writeFileSync(regular, "gitdir: ../gd\n");
      const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
      vi.mocked(stat).mockImplementation(async (path, options) =>
        actual.stat(path === fifo ? regular : path, options),
      );
      await expectNotServed(wt);
      expect(vi.mocked(open).mock.calls.map(([path]) => path)).toContain(fifo);
    },
  );

  it("refused: an lstat of <dir>/.git that answers EACCES makes <dir> the top, whose .git then names nothing", async () => {
    gitDirectory(join(wt, ".git"));
    mkdirSync(join(wt, "sub"));
    await answerLstat((path) => (path === join(wt, "sub", ".git") ? errno("EACCES") : null));
    await expectNotServed(join(wt, "sub"));
  });

  it('refused: E whose shape is "unreadable", its HEAD answering EACCES', async () => {
    gitDirectory(join(wt, ".git"));
    await answerLstat((path) => (path === join(wt, ".git", "HEAD") ? errno("EACCES") : null));
    await expectNotServed(wt);
  });
});

describe.skipIf(GIT === null)(
  "the vault's reading is git's: top, git directory and common directory equal git's, resolved (skipped where no supported git resolves)",
  () => {
    let root: string;
    let bare: string;
    let bareUrl: string;
    let env: NodeJS.ProcessEnv;

    function git(cwd: string, ...args: string[]): string {
      return execFileSync(GIT as string, args, {
        cwd,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    }

    function clone(name: string, ...options: string[]): string {
      const wt = join(root, name);
      git(root, "clone", "-q", ...options, bare, wt);
      return wt;
    }

    beforeAll(() => {
      root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-reading-")));
      const emptyConfig = join(root, "empty.gitconfig");
      writeFileSync(emptyConfig, "");
      env = {
        ...process.env,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: emptyConfig,
        GIT_TERMINAL_PROMPT: "0",
        GIT_AUTHOR_NAME: "harpoc-test",
        GIT_AUTHOR_EMAIL: "test@example.com",
        GIT_COMMITTER_NAME: "harpoc-test",
        GIT_COMMITTER_EMAIL: "test@example.com",
      };
      const seed = join(root, "seed");
      mkdirSync(join(seed, "sub"), { recursive: true });
      git(seed, "init", "-q", "-b", "main");
      writeFileSync(join(seed, "file.txt"), "1\n");
      writeFileSync(join(seed, "sub", "s.txt"), "1\n");
      git(seed, "add", "file.txt", "sub/s.txt");
      git(seed, "commit", "-q", "-m", "c1");
      bare = join(root, "seed.git");
      git(root, "clone", "-q", "--bare", seed, bare);
      const slashed = bare.replace(/\\/g, "/");
      bareUrl = slashed.startsWith("/") ? `file://${slashed}` : `file:///${slashed}`;
    });

    afterAll(() => {
      if (root !== undefined)
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    const READINGS: ReadonlyArray<readonly [string, () => string]> = [
      ["a clone, named from its top", () => clone("top")],
      ["a clone, named from a subdirectory", () => join(clone("from-sub"), "sub")],
      [
        "a linked work tree",
        () => {
          const linked = join(root, "linked");
          git(clone("main"), "worktree", "add", "-b", "linked", linked);
          return linked;
        },
      ],
      [
        "a linked work tree of a bare repository",
        () => {
          const linked = join(root, "bare-linked");
          git(clone("bare-main.git", "--bare"), "worktree", "add", "-b", "bare-linked", linked);
          return linked;
        },
      ],
      [
        "a submodule",
        () => {
          const superproject = clone("super");
          git(superproject, "-c", "protocol.file.allow=always", "submodule", "add", bareUrl, "mod");
          return join(superproject, "mod");
        },
      ],
      [
        "a separate git directory",
        () => clone("separate", `--separate-git-dir=${join(root, "separate.git")}`),
      ],
    ];

    async function expectGitsReading(named: string): Promise<void> {
      const [top, gitDir, commonDir] = git(
        named,
        "rev-parse",
        "--path-format=absolute",
        "--show-toplevel",
        "--absolute-git-dir",
        "--git-common-dir",
      )
        .trim()
        .split(/\r?\n/)
        .map((path) => realpathSync.native(path));
      const repo = await findServedRepository(realpathSync.native(named));
      expect({
        top: repo.top,
        gitDir: repo.gitDir,
        commonDir: repo.commonDir ?? repo.gitDir,
      }).toEqual({ top, gitDir, commonDir });
    }

    it.each(READINGS)("%s", async (_label, make) => {
      await expectGitsReading(make());
    });

    // A symbolic link needs a privilege on win32, whose path layer collapses a `..` by text anyway.
    it.skipIf(WIN32)(
      "a gitfile gitdir: link/../gd whose link leads into another directory: the .. climbs from the link's target",
      async () => {
        const elsewhere = join(root, "text-join-elsewhere");
        mkdirSync(join(elsewhere, "inner"), { recursive: true });
        const wt = clone("text-join", `--separate-git-dir=${join(elsewhere, "gd")}`);
        symlinkSync(join(elsewhere, "inner"), join(wt, "link"));
        writeFileSync(join(wt, ".git"), "gitdir: link/../gd\n");
        await expectGitsReading(wt);
      },
    );

    it("a .git that is a link to a git directory (a junction on win32)", async () => {
      const wt = clone("dot-git-link");
      renameSync(join(wt, ".git"), join(root, "moved.git"));
      directoryLink(join(root, "moved.git"), join(wt, ".git"));
      await expectGitsReading(wt);
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
