import { execFileSync } from "node:child_process";
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
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import type { LocalPathInput } from "./local-path.js";
import { judgeLocalPath, resolveSftpLocalPath } from "./local-path.js";
import { hasGitDirectoryShape } from "./local-path-git.js";

vi.mock("./local-path-git.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./local-path-git.js")>();
  return { ...actual, hasGitDirectoryShape: vi.fn(actual.hasGitDirectoryShape) };
});

const GIT = resolveSupportedGit();
const WIN32 = process.platform === "win32";
const HEAD_REF = "ref: refs/heads/main\n";
const NOT_ALLOWED = { refusal: "not_allowed" };
const NOT_LISTED_ERROR = {
  code: ErrorCode.LOCAL_PATH_NOT_ALLOWED,
  statusCode: 403,
  message: "sftp local path is not inside a directory the secret's policy lists",
  details: undefined,
};

let root: string;
let listed: string;

function at(...names: string[]): string {
  return join(root, ...names);
}

function file(path: string, content = ""): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function shape(dir: string): void {
  mkdirSync(join(dir, "objects"), { recursive: true });
  mkdirSync(join(dir, "refs"));
  writeFileSync(join(dir, "HEAD"), HEAD_REF);
}

function link(target: string, path: string): void {
  symlinkSync(target, path, WIN32 ? "junction" : "dir");
}

beforeAll(() => {
  root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-local-path-git-")));
  listed = at("listed");
  shape(at("listed", "wt", ".git"));
  file(at("listed", "wt", ".git", "config"), "[core]\n");
  file(at("listed", "wt", "report.pdf"), "report");
  shape(at("listed", "wt-shaped", ".git"));
  shape(at("listed", "wt-shaped"));
  file(at("listed", "wt-shaped", "report.pdf"), "report");
  shape(at("listed", "bare.git"));
  file(at("listed", "bare.git", "config"), "[core]\n");
  mkdirSync(at("listed", "bare.git", "hooks"));
  file(at("listed", "linked", "HEAD"), HEAD_REF);
  file(at("listed", "linked", "commondir"), "../bare.git\n");
  file(at("outside", "report.pdf"), "report");
  file(at("odd", ".git", "projects", "report.pdf"), "report");
  file(at("upper", ".GIT", "f"), "f");
  shape(at("bare-listed.git"));
  file(at("bare-listed.git", "config"), "[core]\n");
  file(at("bare-listed.git", "info", "exclude"));
  shape(at("home"));
  file(at("home", "reports", "report.pdf"), "report");
  file(at("plain", "report.pdf"), "report");
  mkdirSync(at("dotgit-parent"));
  link(at("plain"), at("dotgit-parent", ".git"));
  file(at("vault", "vault.db"));
  link(at("listed", "wt", ".git"), at("listed", "to-dotgit"));
  link(at("listed", "bare.git"), at("listed", "to-bare"));
  link(at("outside"), at("listed", "to-outside"));
  link(at("odd", ".git", "projects"), at("listed", "odd-link"));
  link(at("upper", ".GIT"), at("listed", "to-upper"));
  if (!WIN32) {
    for (const dir of [listed, at("listed", "bare.git")]) chmodSync(dir, 0o755);
  }
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function judged(
  localPath: string,
  access: "read" | "write" = "read",
  allowedDirs: readonly string[] = [listed],
): LocalPathInput {
  return {
    localPath,
    access,
    allowedDirs,
    vaultFiles: [at("vault", "vault.db")],
    refuseGlob: true,
  };
}

async function expectNotAllowed(cases: ReadonlyArray<readonly [string, LocalPathInput]>) {
  for (const [label, input] of cases) {
    await expect(judgeLocalPath(input), label).resolves.toEqual(NOT_ALLOWED);
  }
}

describe("judgeLocalPath: a path inside a git directory is answered as one in no listed directory", () => {
  it("a file of a work tree beside its `.git` is served, read and write", async () => {
    const report = at("listed", "wt", "report.pdf");
    const fresh = at("listed", "wt", "new.pdf");
    await expect(judgeLocalPath(judged(report))).resolves.toEqual({ resolved: report });
    await expect(judgeLocalPath(judged(report, "write"))).resolves.toEqual({ resolved: report });
    await expect(judgeLocalPath(judged(fresh, "write"))).resolves.toEqual({ resolved: fresh });
  });

  it("a link into a `.git`, a link into a bare repository and a link to the outside are refused alike", async () => {
    const through = [
      at("listed", "to-dotgit", "config"),
      at("listed", "to-bare", "config"),
      at("listed", "to-outside", "report.pdf"),
    ];
    await expectNotAllowed(
      (["read", "write"] as const).flatMap((access) =>
        through.map((path) => [`${access} ${path}`, judged(path, access)] as const),
      ),
    );
    for (const operation of ["upload", "download"] as const) {
      for (const localPath of through) {
        const { code, statusCode, message, details } = await expectVaultError(
          () =>
            resolveSftpLocalPath({
              localPath,
              operation,
              allowedDirs: [listed],
              vaultFiles: [at("vault", "vault.db")],
            }),
          ErrorCode.LOCAL_PATH_NOT_ALLOWED,
        );
        expect({ code, statusCode, message, details }, `${operation} ${localPath}`).toEqual(
          NOT_LISTED_ERROR,
        );
      }
    }
  });

  it("the files of a bare repository in a listed directory", async () => {
    await expectNotAllowed([
      ["an upload of config", judged(at("listed", "bare.git", "config"))],
      ["an upload of HEAD", judged(at("listed", "bare.git", "HEAD"))],
      ["a download onto config", judged(at("listed", "bare.git", "config"), "write")],
      [
        "a download to hooks/post-update",
        judged(at("listed", "bare.git", "hooks", "post-update"), "write"),
      ],
      ["a download to new", judged(at("listed", "bare.git", "new"), "write")],
      ["a download to nowhere/x", judged(at("listed", "bare.git", "nowhere", "x"), "write")],
    ]);
  });

  it("a download onto an existing directory inside a git directory is `not_allowed`, not `is_directory`", async () => {
    await expect(
      judgeLocalPath(judged(at("listed", "bare.git", "objects"), "write")),
    ).resolves.toEqual(NOT_ALLOWED);
  });

  it("a linked work tree's git directory", async () => {
    await expect(judgeLocalPath(judged(at("listed", "linked", "HEAD")))).resolves.toEqual(
      NOT_ALLOWED,
    );
  });

  it("a listed directory that is a bare repository admits nothing", async () => {
    const bare = at("bare-listed.git");
    await expectNotAllowed([
      ["an upload of config", judged(join(bare, "config"), "read", [bare])],
      ["a download onto config", judged(join(bare, "config"), "write", [bare])],
      ["a download of new", judged(join(bare, "new"), "write", [bare])],
    ]);
  });

  it("a listed directory inside a git directory admits nothing", async () => {
    await expectNotAllowed([
      [
        "an upload of info/exclude",
        judged(at("bare-listed.git", "info", "exclude"), "read", [at("bare-listed.git", "info")]),
      ],
      [
        "an upload of home/reports/report.pdf",
        judged(at("home", "reports", "report.pdf"), "read", [at("home", "reports")]),
      ],
    ]);
  });

  it("a work tree under a directory named `.git` higher up", async () => {
    await expect(
      judgeLocalPath(
        judged(at("odd", ".git", "projects", "report.pdf"), "read", [
          at("odd", ".git", "projects"),
        ]),
      ),
    ).resolves.toEqual({ refusal: "dot_git" });
    await expect(
      judgeLocalPath(
        judged(at("listed", "odd-link", "report.pdf"), "read", [at("listed", "odd-link")]),
      ),
    ).resolves.toEqual(NOT_ALLOWED);
  });

  it("a stored `.GIT` is a `.git` name on every platform", async () => {
    await expect(
      judgeLocalPath(judged(at("listed", "to-upper", "f"), "read", [at("listed", "to-upper")])),
    ).resolves.toEqual(NOT_ALLOWED);
  });

  it("a listed directory spelled with a `.git` name admits nothing, also where it leads to no git directory", async () => {
    const report = at("plain", "report.pdf");
    await expect(
      judgeLocalPath(judged(report, "read", [at("dotgit-parent", ".git")])),
    ).resolves.toEqual(NOT_ALLOWED);
    await expect(judgeLocalPath(judged(report, "read", [at("plain")]))).resolves.toEqual({
      resolved: report,
    });
  });

  it("a work tree whose top also has a git directory's shape refuses its files", async () => {
    await expect(judgeLocalPath(judged(at("listed", "wt-shaped", "report.pdf")))).resolves.toEqual(
      NOT_ALLOWED,
    );
  });

  it("the walk asks every directory from the file's parent up to the root, once each", async () => {
    const report = at("listed", "wt", "report.pdf");
    const asked: string[] = [];
    for (let dir = dirname(report); ; dir = dirname(dir)) {
      asked.push(dir);
      if (dirname(dir) === dir) break;
    }
    vi.mocked(hasGitDirectoryShape).mockClear();
    await expect(judgeLocalPath(judged(report))).resolves.toEqual({ resolved: report });
    expect(vi.mocked(hasGitDirectoryShape).mock.calls.map(([dir]) => dir)).toEqual(asked);
  });

  it("a spelling refusal, a path that does not resolve, a path under the floor and a path in no listed directory ask no shape", async () => {
    vi.mocked(hasGitDirectoryShape).mockClear();
    await expect(judgeLocalPath(judged(at("listed", "wt", ".git", "config")))).resolves.toEqual({
      refusal: "dot_git",
    });
    await expect(judgeLocalPath(judged(at("listed", "missing.pdf")))).resolves.toEqual(NOT_ALLOWED);
    await expect(
      judgeLocalPath(judged(at("vault", "vault.db"), "read", [at("vault")])),
    ).resolves.toEqual({ refusal: "protected" });
    await expect(judgeLocalPath(judged(at("outside", "report.pdf")))).resolves.toEqual(NOT_ALLOWED);
    expect(hasGitDirectoryShape).not.toHaveBeenCalled();
  });

  it("a directory on the way up that cannot be read refuses", async () => {
    const actual =
      await vi.importActual<typeof import("./local-path-git.js")>("./local-path-git.js");
    const denied = Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
    vi.mocked(hasGitDirectoryShape).mockImplementation(async (dir) => {
      if (dir === listed) throw denied;
      return actual.hasGitDirectoryShape(dir);
    });
    try {
      await expect(judgeLocalPath(judged(at("listed", "wt", "report.pdf")))).resolves.toEqual(
        NOT_ALLOWED,
      );
    } finally {
      vi.mocked(hasGitDirectoryShape).mockImplementation(actual.hasGitDirectoryShape);
    }
  });

  it("a daemon changes nothing", async () => {
    await expect(
      judgeLocalPath({
        ...judged(at("listed", "to-bare", "config")),
        daemon: { protectedDirs: [], protectedFiles: [] },
      }),
    ).resolves.toEqual(NOT_ALLOWED);
  });

  it("a directory gets the shape after its config", async () => {
    const shaped = at("limit", "P");
    mkdirSync(shaped, { recursive: true });
    mkdirSync(at("limit", "X"));
    link(shaped, at("limit", "X", ".git"));
    for (const name of ["config", "HEAD", "objects", "refs"]) {
      const target = join(shaped, name);
      await expect(
        judgeLocalPath(judged(target, "write", [shaped])),
        `a download of ${name}`,
      ).resolves.toEqual({ resolved: target });
      writeFileSync(target, name === "HEAD" ? HEAD_REF : "");
    }
    await expect(judgeLocalPath(judged(join(shaped, "config"), "read", [shaped]))).resolves.toEqual(
      NOT_ALLOWED,
    );
  });
});

describe.skipIf(GIT === null)(
  "judgeLocalPath: the shapes git makes (skipped where no supported git resolves)",
  () => {
    let base: string;

    beforeAll(() => {
      base = at("git");
      mkdirSync(base);
      const emptyConfig = at("empty.gitconfig");
      writeFileSync(emptyConfig, "");
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: emptyConfig,
        GIT_TERMINAL_PROMPT: "0",
        GIT_AUTHOR_NAME: "harpoc-test",
        GIT_AUTHOR_EMAIL: "test@example.com",
        GIT_COMMITTER_NAME: "harpoc-test",
        GIT_COMMITTER_EMAIL: "test@example.com",
      };
      const git = (cwd: string, ...args: string[]): void => {
        execFileSync(GIT as string, args, { cwd, env, stdio: "ignore", timeout: 30_000 });
      };
      git(base, "init", "-q", "wt2");
      git(base, "init", "-q", "--bare", "r.git");
      git(join(base, "wt2"), "commit", "-q", "--allow-empty", "-m", "init");
      git(join(base, "wt2"), "worktree", "add", join("..", "lw"));
      writeFileSync(join(base, "wt2", "report.pdf"), "report");
      writeFileSync(join(base, "lw", "report.pdf"), "report");
      link(join(base, "wt2", ".git"), join(base, "to-wt2-git"));
    });

    it("a git directory git made is refused, through a link and by its spelling; a work tree and a linked work tree are served", async () => {
      const inBase = (localPath: string): LocalPathInput => judged(localPath, "read", [base]);
      await expectNotAllowed([
        ["wt2/.git/config through a link", inBase(join(base, "to-wt2-git", "config"))],
        ["r.git/config", inBase(join(base, "r.git", "config"))],
      ]);
      await expect(
        judgeLocalPath(inBase(join(base, "wt2", ".git", "worktrees", "lw", "HEAD"))),
      ).resolves.toEqual({ refusal: "dot_git" });
      for (const report of [join(base, "wt2", "report.pdf"), join(base, "lw", "report.pdf")]) {
        await expect(judgeLocalPath(inBase(report)), report).resolves.toEqual({ resolved: report });
      }
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
