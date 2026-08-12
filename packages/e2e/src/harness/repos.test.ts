import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveBash, resolveGit } from "./fixtures.js";

const REPOS_DIR = fileURLToPath(new URL("../../fixtures/repos", import.meta.url));
const OUT = join(REPOS_DIR, "out");

// resolveBash, not bare "bash": on a Windows dev host PATH bash may be the
// System32 WSL launcher, which cannot open the absolute Windows script path.
// Forward slashes because the argument crosses into an MSYS program.
const BASH = resolveBash();
const GENERATE = join(REPOS_DIR, "generate.sh").replace(/\\/g, "/");
const GIT = resolveGit();

describe("fixture git repositories", () => {
  beforeAll(() => {
    execFileSync(BASH, [GENERATE], { stdio: "inherit" });
  });

  it("generates bare clean and submodule repositories", () => {
    for (const repo of ["clean.git", "submodule.git"]) {
      expect(existsSync(join(OUT, repo, "HEAD"))).toBe(true);
      // Bare — no working tree checked out beside the git dir.
      expect(existsSync(join(OUT, repo, ".git"))).toBe(false);
    }
  });

  it("makes clean.git cloneable over dumb HTTP (info/refs present)", () => {
    expect(existsSync(join(OUT, "clean.git", "info", "refs"))).toBe(true);
  });

  it("carries a hostile off-box submodule so the recursion request is real (H6b)", () => {
    const gitmodules = execFileSync(
      GIT,
      ["-C", join(OUT, "submodule.git"), "show", "HEAD:.gitmodules"],
      { encoding: "utf8" },
    );
    expect(gitmodules).toContain("https://attacker.example/evil.git");
  });

  it("is idempotent — a second run does not rebuild clean.git", () => {
    // HEAD's content is the constant symref "ref: refs/heads/main" and is
    // byte-identical across a full rebuild, so comparing it pins nothing.
    // Compare the commit sha (rebuilds re-commit with a fresh timestamp) AND
    // HEAD's mtime (catches a rebuild landing in the same clock second, where
    // the sha alone would collide).
    const shaOf = (): string =>
      execFileSync(GIT, ["-C", join(OUT, "clean.git"), "rev-parse", "HEAD"], {
        encoding: "utf8",
      }).trim();
    const before = { sha: shaOf(), mtime: statSync(join(OUT, "clean.git", "HEAD")).mtimeMs };
    execFileSync(BASH, [GENERATE], { stdio: "inherit" });
    expect(shaOf()).toBe(before.sha);
    expect(statSync(join(OUT, "clean.git", "HEAD")).mtimeMs).toBe(before.mtime);
    // readFileSync kept as a sanity floor: the symref itself is intact.
    expect(readFileSync(join(OUT, "clean.git", "HEAD"), "utf8")).toContain("refs/heads/main");
  });
});
