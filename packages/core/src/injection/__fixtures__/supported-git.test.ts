import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { controlledPathDirs, resolveExecutable } from "../allowlist.js";
import { parseGitVersion } from "../git-injector-version.js";
import { resolveSupportedGit } from "./supported-git.js";

const GIT = resolveExecutable("git", controlledPathDirs());

describe("resolveSupportedGit on the host's git", () => {
  it.skipIf(GIT === null)(
    "returns the host's git where its version is at or above the 2.32 floor and null below it (skipped where git does not resolve)",
    () => {
      const version = parseGitVersion(
        execFileSync(GIT as string, ["version"], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
          timeout: 20_000,
        }),
      );
      const supported =
        version !== null && (version.major > 2 || (version.major === 2 && version.minor >= 32));
      expect(resolveSupportedGit()).toBe(supported ? GIT : null);
    },
  );
});

describe.skipIf(process.platform === "win32")(
  "resolveSupportedGit on a stand-in git first on PATH (POSIX only: on win32 the resolver takes .exe and .com alone and a #!/bin/sh stand-in cannot be spawned shell-free)",
  () => {
    let bin: string;
    let savedPath: string | undefined;

    beforeEach(() => {
      bin = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-supported-git-")));
      savedPath = process.env.PATH;
      process.env.PATH = `${bin}${delimiter}${savedPath ?? ""}`;
    });

    afterEach(() => {
      if (savedPath === undefined) delete process.env.PATH;
      else process.env.PATH = savedPath;
      rmSync(bin, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    function standIn(line: string): string {
      const git = join(bin, "git");
      writeFileSync(git, `#!/bin/sh\necho '${line}'\n`);
      chmodSync(git, 0o755);
      return git;
    }

    it("returns null for a stand-in printing git version 2.31.9, below the 2.32 floor", () => {
      standIn("git version 2.31.9");
      expect(resolveSupportedGit()).toBeNull();
    });

    it("returns the real path of a stand-in printing git version 2.32.0, at the 2.32 floor", () => {
      const git = standIn("git version 2.32.0");
      expect(resolveSupportedGit()).toBe(git);
    });
  },
);
