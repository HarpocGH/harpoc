import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { lstat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import {
  gitDirectoryShape,
  hasGitDirectoryShape,
  holdsDotGitName,
  isDotGitName,
} from "./local-path-git.js";
import type { GitDirectoryShape } from "./local-path-git.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, lstat: vi.fn(actual.lstat) };
});

const GIT = resolveSupportedGit();
const WIN32 = process.platform === "win32";

/** Git's list in `utf8.c`, the same at v2.32.0 and v2.56.1. */
const HFS_IGNORED_CODE_POINTS = [
  "\u200c",
  "\u200d",
  "\u200e",
  "\u200f",
  "\u202a",
  "\u202b",
  "\u202c",
  "\u202d",
  "\u202e",
  "\u206a",
  "\u206b",
  "\u206c",
  "\u206d",
  "\u206e",
  "\u206f",
  "\ufeff",
];

const DOT_GIT_NAMES = [
  ...new Set([
    ".git",
    ".GIT",
    ".Git",
    ".git.",
    ".git ",
    ".git...",
    ".git . .",
    ".git:x",
    ".git::$INDEX_ALLOCATION",
    ".GIT. :$DATA",
    "git~1",
    "GIT~1",
    "git~2",
    "git~10",
    "git~1.",
    "git~1 ",
    "git~1:x",
    ".g\u200cit",
    "\u200c.git",
    ".git\ufeff",
    ".G\u200dI\u202eT. ",
    ...HFS_IGNORED_CODE_POINTS.map((point) => `.g${point}it`),
  ]),
];

const OTHER_NAMES = [
  ".gitignore",
  ".github",
  ".gitmodules",
  ".git2",
  ".git-old",
  "x.git",
  "git",
  "git~",
  "git~x",
  "git~1x",
  "..git",
  " .git",
  ".g\u0131t",
  ".G\u0130T",
  ".git\u200b",
  ".g\u00adit",
  ".\uff47it",
  "",
  "C:",
];

/** Git refuses these three for reasons of its own, not for a `.git` name. */
const NOT_ASKED_OF_GIT = new Set(["..git", "", "C:"]);
const GIT_NAMES = [...DOT_GIT_NAMES, ...OTHER_NAMES].filter((name) => !NOT_ASKED_OF_GIT.has(name));

/** Git's NTFS test takes `git~1` alone; on win32 git refuses a name ending in a space for itself. */
const REFUSED_BY_THE_FUNCTION_ALONE = ["git~2", "git~10", ...(WIN32 ? [] : [".G\u200dI\u202eT. "])];

function shown(name: string): string {
  return `"${name.replace(
    /[^\x21-\x7e]/g,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
  )}"`;
}

function shownEach(names: readonly string[]): Array<[string, string]> {
  return names.map((name) => [shown(name), name]);
}

describe("isDotGitName", () => {
  it.each(shownEach(DOT_GIT_NAMES))("%s is a .git name", (_shown, name) => {
    expect(isDotGitName(name)).toBe(true);
  });

  it.each(shownEach(OTHER_NAMES))("%s is not a .git name", (_shown, name) => {
    expect(isDotGitName(name)).toBe(false);
  });
});

describe("holdsDotGitName", () => {
  it.each(["/a/.git/b", "C:\\x\\.GIT\\y", "a\\git~1/b", "/a/.git", ".git"])(
    "%s holds a .git name: split on / and \\ on every platform",
    (path) => {
      expect(holdsDotGitName(path)).toBe(true);
    },
  );

  it.each(["/a/b.git/c", "C:\\x\\y", "/"])("%s holds none", (path) => {
    expect(holdsDotGitName(path)).toBe(false);
  });
});

describe("the names the leg reads as .git", () => {
  let root: string;

  beforeEach(() => {
    root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-local-path-git-")));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it.skipIf(GIT === null)(
    "the 16 code points are git's own: under core.protectHFS and core.protectNTFS git refuses no name of the 52 the function answers false to, and takes only git~2, git~10 and, off win32, .G\\u200dI\\u202eT. of the ones it answers true to (skipped where no supported git resolves)",
    () => {
      expect(GIT_NAMES).toHaveLength(52);
      const emptyConfig = join(root, "empty.gitconfig");
      writeFileSync(emptyConfig, "");
      const env = {
        ...process.env,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: emptyConfig,
        GIT_TERMINAL_PROMPT: "0",
      };
      const repo = join(root, "repo");
      execFileSync(GIT as string, ["init", "-q", repo], { env, stdio: "ignore" });
      const emptyBlob = execFileSync(GIT as string, ["hash-object", "-w", "--stdin"], {
        cwd: repo,
        env,
        input: "",
        encoding: "utf8",
      }).trim();
      const gitTakes = (name: string): boolean => {
        const added = spawnSync(
          GIT as string,
          [
            "-c",
            "core.protectHFS=true",
            "-c",
            "core.protectNTFS=true",
            "update-index",
            "--add",
            "--cacheinfo",
            `100644,${emptyBlob},${name}`,
          ],
          { cwd: repo, env, stdio: "ignore" },
        );
        if (added.error !== undefined) throw added.error;
        return added.status === 0;
      };
      const taken = GIT_NAMES.filter(gitTakes);
      const refused = GIT_NAMES.filter((name) => !taken.includes(name));
      expect({
        refusedByGitAlone: refused.filter((name) => !isDotGitName(name)).map(shown),
        refusedByTheFunctionAlone: taken.filter(isDotGitName).map(shown),
      }).toEqual({
        refusedByGitAlone: [],
        refusedByTheFunctionAlone: REFUSED_BY_THE_FUNCTION_ALONE.map(shown),
      });
    },
  );

  it("every name this leg's file system reads as .git is a .git name", () => {
    mkdirSync(join(root, ".git"));
    writeFileSync(join(root, ".git", "marker"), "");
    const readAsDotGit = [...DOT_GIT_NAMES, ...OTHER_NAMES].filter((name) =>
      existsSync(join(root, name, "marker")),
    );
    expect(readAsDotGit).toContain(".git");
    expect(readAsDotGit.filter((name) => !isDotGitName(name)).map(shown)).toEqual([]);
  });
});

const HEAD_REF = "ref: refs/heads/main\n";
const A_PATH_THAT_IS_A_FILE = "a path that is a file";

function directory(path: string): void {
  mkdirSync(path, { recursive: true });
}

function head(dir: string, content: string = HEAD_REF): void {
  writeFileSync(join(dir, "HEAD"), content);
}

function objectsAndRefs(dir: string): void {
  directory(join(dir, "objects"));
  directory(join(dir, "refs"));
}

/** A link to `target`, which does not exist: a junction on win32, which needs no privilege. */
function linkNowhere(link: string, target: string): void {
  if (WIN32) symlinkSync(join(link, "..", target), link, "junction");
  else symlinkSync(target, link);
}

function errno(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(code), { code });
}

const SHAPES: ReadonlyArray<readonly [string, GitDirectoryShape, (dir: string) => void]> = [
  [
    "HEAD (a file) with objects/ and refs/",
    "shape",
    (dir) => {
      directory(dir);
      head(dir);
      objectsAndRefs(dir);
    },
  ],
  [
    "HEAD with commondir",
    "shape",
    (dir) => {
      directory(dir);
      head(dir);
      writeFileSync(join(dir, "commondir"), "../common\n");
      objectsAndRefs(join(dir, "..", "common"));
    },
  ],
  [
    "HEAD a link that leads nowhere with both directories",
    "shape",
    (dir) => {
      directory(dir);
      objectsAndRefs(dir);
      linkNowhere(join(dir, "HEAD"), "refs/heads/main");
    },
  ],
  [
    "objects and refs plain files",
    "shape",
    (dir) => {
      directory(dir);
      head(dir);
      writeFileSync(join(dir, "objects"), "");
      writeFileSync(join(dir, "refs"), "");
    },
  ],
  [
    "objects and refs links that lead nowhere",
    "shape",
    (dir) => {
      directory(dir);
      head(dir);
      linkNowhere(join(dir, "objects"), "gone-objects");
      linkNowhere(join(dir, "refs"), "gone-refs");
    },
  ],
  [
    "a HEAD holding garbage",
    "shape",
    (dir) => {
      directory(dir);
      head(dir, "garbage\n");
      objectsAndRefs(dir);
    },
  ],
  [
    "HEAD a directory",
    "shape",
    (dir) => {
      directory(join(dir, "HEAD"));
      objectsAndRefs(dir);
    },
  ],
  ["an empty directory", "none", directory],
  [
    "HEAD alone",
    "none",
    (dir) => {
      directory(dir);
      head(dir);
    },
  ],
  [
    "HEAD with objects alone",
    "none",
    (dir) => {
      directory(join(dir, "objects"));
      head(dir);
    },
  ],
  [
    "objects, refs and commondir without HEAD",
    "none",
    (dir) => {
      directory(dir);
      objectsAndRefs(dir);
      writeFileSync(join(dir, "commondir"), "../common\n");
      objectsAndRefs(join(dir, "..", "common"));
    },
  ],
  [
    A_PATH_THAT_IS_A_FILE,
    "none",
    (dir) => {
      writeFileSync(dir, HEAD_REF);
    },
  ],
];

describe("gitDirectoryShape", () => {
  let root: string;
  let candidate: string;

  beforeEach(() => {
    root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-shape-")));
    candidate = join(root, "candidate");
  });

  afterEach(() => {
    vi.mocked(lstat).mockReset();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it.each(SHAPES)("%s is %s", async (_label, expected, make) => {
    make(candidate);
    expect(await gitDirectoryShape(candidate)).toBe(expected);
    expect(await hasGitDirectoryShape(candidate)).toBe(expected !== "none");
  });

  it("a directory whose lstat of HEAD answers EACCES is unreadable, and hasGitDirectoryShape answers true", async () => {
    directory(candidate);
    head(candidate);
    objectsAndRefs(candidate);
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    vi.mocked(lstat).mockImplementation(async (path, options) => {
      if (path === join(candidate, "HEAD")) throw errno("EACCES");
      return actual.lstat(path, options);
    });
    expect(await gitDirectoryShape(candidate)).toBe("unreadable");
    expect(await hasGitDirectoryShape(candidate)).toBe(true);
  });

  it.skipIf(WIN32 || process.getuid?.() === 0)(
    "a directory of mode 000, whose lstat of HEAD answers EACCES, is unreadable, and hasGitDirectoryShape answers true (skipped on win32, which has no mode bits, and where the process is root, which reads it)",
    async () => {
      directory(candidate);
      head(candidate);
      objectsAndRefs(candidate);
      chmodSync(candidate, 0o000);
      try {
        await expect(lstat(join(candidate, "HEAD"))).rejects.toMatchObject({ code: "EACCES" });
        expect(await gitDirectoryShape(candidate)).toBe("unreadable");
        expect(await hasGitDirectoryShape(candidate)).toBe(true);
      } finally {
        chmodSync(candidate, 0o700);
      }
    },
  );

  it("HEAD is asked first and alone where it is missing", async () => {
    directory(candidate);
    objectsAndRefs(candidate);
    writeFileSync(join(candidate, "commondir"), "");
    vi.mocked(lstat).mockClear();
    expect(await gitDirectoryShape(candidate)).toBe("none");
    expect(vi.mocked(lstat).mock.calls.map(([path]) => path)).toEqual([join(candidate, "HEAD")]);
  });

  it.runIf(WIN32)("on win32 head, Objects and Refs are a shape: NTFS finds them", async () => {
    directory(join(candidate, "Objects"));
    directory(join(candidate, "Refs"));
    writeFileSync(join(candidate, "head"), HEAD_REF);
    expect(await gitDirectoryShape(candidate)).toBe("shape");
  });

  it.skipIf(GIT === null)(
    "no directory git takes is none: each variant in an empty root with GIT_CEILING_DIRECTORIES at that root (skipped where no supported git resolves)",
    async () => {
      const emptyConfig = join(root, "empty.gitconfig");
      writeFileSync(emptyConfig, "");
      const repositoryVariables = [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
      ];
      const env: NodeJS.ProcessEnv = Object.fromEntries(
        Object.entries({
          ...process.env,
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: emptyConfig,
          GIT_TERMINAL_PROMPT: "0",
        }).filter(([name]) => !repositoryVariables.includes(name)),
      );
      const taken: string[] = [];
      const answered: Record<string, GitDirectoryShape> = {};
      for (const [label, , make] of SHAPES.filter(([label]) => label !== A_PATH_THAT_IS_A_FILE)) {
        const variantRoot = realpathSync.native(mkdtempSync(join(root, "variant-")));
        const dir = join(variantRoot, "candidate");
        make(dir);
        const asked = spawnSync(GIT as string, ["rev-parse", "--absolute-git-dir"], {
          cwd: dir,
          env: { ...env, GIT_CEILING_DIRECTORIES: variantRoot },
          encoding: "utf8",
        });
        if (asked.error !== undefined) throw asked.error;
        if (asked.status === 0 && realpathSync.native(asked.stdout.trim()) === dir) {
          taken.push(label);
        }
        answered[label] = (await hasGitDirectoryShape(dir)) ? "shape" : "none";
      }
      expect(taken).toContain("HEAD (a file) with objects/ and refs/");
      expect(taken.filter((label) => answered[label] === "none")).toEqual([]);
    },
  );
});

it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no supported git resolves',
    );
  }
});
