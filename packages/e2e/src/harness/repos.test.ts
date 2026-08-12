import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPOS_DIR = fileURLToPath(new URL("../../fixtures/repos", import.meta.url));
const OUT = join(REPOS_DIR, "out");

describe("fixture git repositories", () => {
  beforeAll(() => {
    execFileSync("bash", [join(REPOS_DIR, "generate.sh")], { stdio: "inherit" });
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
      "git",
      ["-C", join(OUT, "submodule.git"), "show", "HEAD:.gitmodules"],
      { encoding: "utf8" },
    );
    expect(gitmodules).toContain("https://attacker.example/evil.git");
  });

  it("is idempotent — a second run does not rebuild clean.git", () => {
    const head = readFileSync(join(OUT, "clean.git", "HEAD"), "utf8");
    execFileSync("bash", [join(REPOS_DIR, "generate.sh")], { stdio: "inherit" });
    expect(readFileSync(join(OUT, "clean.git", "HEAD"), "utf8")).toBe(head);
  });
});
