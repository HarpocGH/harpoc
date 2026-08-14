import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { preferNativeSsh, resolveBash, resolveGit, resolveSsh } from "./fixtures.js";

describe("binary resolution for the git/ssh contexts", () => {
  it("resolves ssh and git to existing absolute paths for the command allowlist", () => {
    const ssh = resolveSsh();
    const git = resolveGit();
    expect(existsSync(ssh)).toBe(true);
    expect(existsSync(git)).toBe(true);
    // Absolute — the allowlist pins the resolved path, never a bare name.
    expect(ssh).toMatch(process.platform === "win32" ? /^[A-Za-z]:\\/ : /^\//);
    expect(git).toMatch(process.platform === "win32" ? /^[A-Za-z]:\\/ : /^\//);
    // Regular FILES — the previous existsSync walk accepted a PATH entry's
    // subdirectory named `git`/`ssh`, pinning a directory in the allowlist.
    expect(statSync(ssh).isFile()).toBe(true);
    expect(statSync(git).isFile()).toBe(true);
  });

  it("resolves a bash that can open a Windows script path (never the WSL launcher)", () => {
    const bash = resolveBash();
    expect(statSync(bash).isFile()).toBe(true);
    if (process.platform === "win32") {
      expect(bash.toLowerCase()).not.toContain("\\windows\\system32\\");
    }
    // The resolved bash must accept an absolute host-style script path — the
    // exact operation the fixture generators need in beforeAll.
    const probe = fileURLToPath(new URL("../../fixtures/keys/generate.sh", import.meta.url));
    const out = execFileSync(
      bash,
      ["-c", `test -f "$1" && echo openable`, "--", probe.replace(/\\/g, "/")],
      {
        encoding: "utf8",
      },
    );
    expect(out.trim()).toBe("openable");
  });

  it("prefers the native OpenSSH client and is idempotent (Windows F-6)", () => {
    preferNativeSsh();
    const before = process.env.PATH;
    preferNativeSsh();
    expect(process.env.PATH).toBe(before);
    if (process.platform === "win32") {
      const dir = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "OpenSSH");
      expect((process.env.PATH ?? "").split(delimiter)[0]?.toLowerCase()).toBe(dir.toLowerCase());
      expect(resolveSsh().toLowerCase()).toContain("system32\\openssh");
    }
  });
});

describe("baseline fixture injection field names (F2)", () => {
  it("the baseline fixture reads the vault's injection field names", () => {
    const source = readFileSync(
      new URL("../../fixtures/baseline-mcp/server.mjs", import.meta.url),
      "utf8",
    );
    // If the vault renames these, this pin fails and the two arms stop
    // comparing like for like — which is invisible at runtime while every
    // scenario is bearer. Asserted on the DISPATCH EXPRESSIONS, not a bare
    // substring: the file's own explanatory comment contains the literals
    // "header_name"/"query_param" too, so a plain `toContain` check on those
    // words is satisfied by the comment alone and discriminates nothing —
    // it stayed green with the dispatch code reverted to the pre-fix
    // `?? "x-api-key"` fallback (review 2026-08-14, whole-branch finding).
    expect(source).toContain("injection.header_name");
    expect(source).toContain("injection.query_param");
    expect(source).not.toMatch(/injection\.name/);
  });
});
