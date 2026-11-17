import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import {
  formatGitVersion,
  gitVersionAtLeast,
  parseGitVersion,
  readGitVersion,
} from "./git-injector-version.js";

const GIT = resolveExecutable("git", controlledPathDirs());

function baseGitEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  const path = process.env.PATH ?? process.env.Path;
  if (path !== undefined) env.PATH = path;
  if (process.platform === "win32" && process.env.SystemRoot !== undefined) {
    env.SystemRoot = process.env.SystemRoot;
  }
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  return env;
}

describe("parseGitVersion", () => {
  it.each<[string, number, number, number]>([
    ["git version 2.51.0.windows.2", 2, 51, 0],
    ["git version 2.39.5", 2, 39, 5],
    ["git version 2.39.5 (Apple Git-154)", 2, 39, 5],
    ["git version 2.36.6", 2, 36, 6],
    ["git version 2.34.1", 2, 34, 1],
    ["git version 2.30.2", 2, 30, 2],
    ["git version 2.25.1", 2, 25, 1],
    ["git version 2.53.0.rc1", 2, 53, 0],
    ["git version 2.53.0.rc1.12.gabcdef", 2, 53, 0],
    ["git version 2.53.0.rc1.12.gabcdef.dirty", 2, 53, 0],
    ["git version 2.56.GIT", 2, 56, 0],
  ])("reads %j as major %d, minor %d, patch %d", (line, major, minor, patch) => {
    expect(parseGitVersion(line)).toEqual({ major, minor, patch });
  });

  it.each(["", "git version", "version 2.37.0", "x git version 2.40.0", "git version x.y"])(
    "reads %j as null",
    (line) => {
      expect(parseGitVersion(line)).toBeNull();
    },
  );
});

describe("gitVersionAtLeast against [2, 37], judged on major and minor", () => {
  it.each<[number, number, number, boolean]>([
    [2, 36, 99, false],
    [2, 37, 0, true],
    [2, 38, 0, true],
    [3, 0, 0, true],
    [1, 99, 0, false],
  ])("judges %d.%d.%d as %s", (major, minor, patch, atLeast) => {
    expect(gitVersionAtLeast({ major, minor, patch }, [2, 37])).toBe(atLeast);
  });
});

describe("formatGitVersion", () => {
  it("prints a version as <major>.<minor>.<patch>", () => {
    expect(formatGitVersion({ major: 2, minor: 39, patch: 5 })).toBe("2.39.5");
  });
});

describe("readGitVersion on a real git", () => {
  it.skipIf(GIT === null)(
    "reads the host's own git under the base git env, not as null and as parseGitVersion reads its `git version` output (skipped where git does not resolve)",
    async () => {
      const read = await readGitVersion(GIT as string, baseGitEnv());
      expect(read).not.toBeNull();
      expect(read).toEqual(
        parseGitVersion(
          execFileSync(GIT as string, ["version"], {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"],
            timeout: 20_000,
          }),
        ),
      );
    },
  );

  it.skipIf(process.platform !== "darwin" || !existsSync("/usr/bin/git"))(
    "reads Apple's /usr/bin/git under the base git env, not as null (darwin only, where /usr/bin/git exists)",
    async () => {
      expect(await readGitVersion("/usr/bin/git", baseGitEnv())).not.toBeNull();
    },
  );
});

describe("readGitVersion on a path that cannot be spawned", () => {
  it("resolves a path holding a NUL byte as null and does not reject", async () => {
    await expect(readGitVersion("git\u0000", baseGitEnv())).resolves.toBeNull();
  });
});

describe.skipIf(process.platform === "win32")(
  "readGitVersion on a stand-in git (POSIX only: a #!/bin/sh script cannot be spawned shell-free on win32)",
  () => {
    let dir: string;

    beforeEach(() => {
      dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-git-version-")));
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    function standIn(body: string): string {
      const git = join(dir, "git");
      writeFileSync(git, `#!/bin/sh\n${body}\n`);
      chmodSync(git, 0o755);
      return git;
    }

    it("reads a stand-in that prints git version 2.30.2 as major 2, minor 30, patch 2", async () => {
      expect(await readGitVersion(standIn("echo 'git version 2.30.2'"), baseGitEnv())).toEqual({
        major: 2,
        minor: 30,
        patch: 2,
      });
    });

    it("reads a stand-in that prints garbage as null", async () => {
      expect(await readGitVersion(standIn("echo 'garbage'"), baseGitEnv())).toBeNull();
    });

    it("reads a stand-in that prints git version 2.40.0 and exits 1 as null", async () => {
      expect(
        await readGitVersion(standIn("echo 'git version 2.40.0'\nexit 1"), baseGitEnv()),
      ).toBeNull();
    });

    it("reads a stand-in that prints git version 2.40.0 and sleeps past a 1 s bound as null", async () => {
      expect(
        await readGitVersion(
          standIn("echo 'git version 2.40.0'\nexec sleep 15"),
          baseGitEnv(),
          1_000,
        ),
      ).toBeNull();
    });
  },
);
