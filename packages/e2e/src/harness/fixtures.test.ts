import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { delimiter, join } from "node:path";
import { preferNativeSsh, resolveGit, resolveSsh } from "./fixtures.js";

describe("binary resolution for the git/ssh contexts", () => {
  it("resolves ssh and git to existing absolute paths for the command allowlist", () => {
    const ssh = resolveSsh();
    const git = resolveGit();
    expect(existsSync(ssh)).toBe(true);
    expect(existsSync(git)).toBe(true);
    // Absolute — the allowlist pins the resolved path, never a bare name.
    expect(ssh).toMatch(process.platform === "win32" ? /^[A-Za-z]:\\/ : /^\//);
    expect(git).toMatch(process.platform === "win32" ? /^[A-Za-z]:\\/ : /^\//);
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
