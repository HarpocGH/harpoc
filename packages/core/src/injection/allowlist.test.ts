import { basename, dirname, join } from "node:path";
import { mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import {
  controlledPathDirs,
  matchesHostAllowlist,
  matchesHostPortAllowlist,
  matchesUrlAllowlist,
  resolveAndMatchCommand,
  resolveExecutable,
} from "./allowlist.js";

// ---------------------------------------------------------------------------
// Host / host:port allowlist
// ---------------------------------------------------------------------------

describe("matchesHostAllowlist", () => {
  it("is not enforced when the allowlist is empty", () => {
    expect(matchesHostAllowlist("evil.example.com", [])).toBe(true);
  });

  it("matches an exact host (case-insensitive)", () => {
    expect(matchesHostAllowlist("Deploy.Example.com", ["deploy.example.com"])).toBe(true);
    expect(matchesHostAllowlist("other.example.com", ["deploy.example.com"])).toBe(false);
  });

  it("matches a subdomain wildcard but not the bare domain", () => {
    expect(matchesHostAllowlist("a.example.com", ["*.example.com"])).toBe(true);
    expect(matchesHostAllowlist("example.com", ["*.example.com"])).toBe(false);
  });
});

describe("matchesHostPortAllowlist", () => {
  it("is not enforced when the allowlist is empty", () => {
    expect(matchesHostPortAllowlist("db.example.com", 5432, [])).toBe(true);
  });

  it("matches host:port exactly", () => {
    expect(matchesHostPortAllowlist("db.example.com", 5432, ["db.example.com:5432"])).toBe(true);
    expect(matchesHostPortAllowlist("db.example.com", 5433, ["db.example.com:5432"])).toBe(false);
  });

  it("matches any port when the pattern omits the port", () => {
    expect(matchesHostPortAllowlist("db.example.com", 5432, ["db.example.com"])).toBe(true);
    expect(matchesHostPortAllowlist("db.example.com", 3306, ["db.example.com"])).toBe(true);
  });

  it("supports a subdomain wildcard with a port", () => {
    expect(matchesHostPortAllowlist("primary.db.example.com", 5432, ["*.db.example.com:5432"])).toBe(
      true,
    );
    expect(matchesHostPortAllowlist("evil.example.com", 5432, ["*.db.example.com:5432"])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// URL allowlist
// ---------------------------------------------------------------------------

describe("matchesUrlAllowlist", () => {
  it("is not enforced when the allowlist is empty", () => {
    expect(matchesUrlAllowlist("https://anywhere.example/x", [])).toBe(true);
  });

  it("matches an exact URL", () => {
    expect(matchesUrlAllowlist("https://api.github.com/user", ["https://api.github.com/user"])).toBe(
      true,
    );
  });

  it("matches a path wildcard", () => {
    const patterns = ["https://api.github.com/*"];
    expect(matchesUrlAllowlist("https://api.github.com/user/repos", patterns)).toBe(true);
    expect(matchesUrlAllowlist("https://api.github.com/", patterns)).toBe(true);
  });

  it("rejects a different host", () => {
    expect(matchesUrlAllowlist("https://evil.com/steal", ["https://api.github.com/*"])).toBe(false);
  });

  it("rejects a suffix-confusion host", () => {
    // api.github.com.evil.com must not match api.github.com
    expect(
      matchesUrlAllowlist("https://api.github.com.evil.com/x", ["https://api.github.com/*"]),
    ).toBe(false);
  });

  it("rejects a scheme mismatch", () => {
    expect(matchesUrlAllowlist("http://api.github.com/x", ["https://api.github.com/*"])).toBe(false);
  });

  it("rejects a port mismatch", () => {
    expect(
      matchesUrlAllowlist("https://api.github.com:8443/x", ["https://api.github.com/*"]),
    ).toBe(false);
  });

  it("supports a subdomain wildcard", () => {
    const patterns = ["https://*.github.com/*"];
    expect(matchesUrlAllowlist("https://api.github.com/x", patterns)).toBe(true);
    expect(matchesUrlAllowlist("https://raw.github.com/y", patterns)).toBe(true);
    expect(matchesUrlAllowlist("https://github.com/z", patterns)).toBe(false);
    expect(matchesUrlAllowlist("https://api.github.com.evil.com/x", patterns)).toBe(false);
  });

  it("matches any of several patterns", () => {
    const patterns = ["https://api.github.com/*", "https://api.gitlab.com/*"];
    expect(matchesUrlAllowlist("https://api.gitlab.com/projects", patterns)).toBe(true);
  });

  it("rejects an unparseable URL when the allowlist is non-empty", () => {
    expect(matchesUrlAllowlist("not-a-url", ["https://api.github.com/*"])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Command allowlist
// ---------------------------------------------------------------------------

const NODE = realpathSync(process.execPath);
const NODE_DIR = dirname(NODE);
const NODE_BASE = basename(NODE);

describe("controlledPathDirs", () => {
  it("returns a non-empty PATH in the test environment", () => {
    expect(controlledPathDirs().length).toBeGreaterThan(0);
  });
});

describe("resolveExecutable", () => {
  it("resolves an absolute path to its realpath", () => {
    expect(resolveExecutable(process.execPath, [])).toBe(NODE);
  });

  it("resolves a bare name against the provided PATH dirs", () => {
    expect(resolveExecutable(NODE_BASE, [NODE_DIR])).toBe(NODE);
  });

  it("returns null for an unknown command", () => {
    expect(resolveExecutable("definitely-not-a-real-binary-xyz", controlledPathDirs())).toBeNull();
  });

  it("returns null for a relative path with a separator", () => {
    expect(resolveExecutable("./node", [NODE_DIR])).toBeNull();
  });
});

describe("resolveAndMatchCommand", () => {
  it("returns the resolved path when the command is allowlisted (absolute)", () => {
    expect(resolveAndMatchCommand(process.execPath, [process.execPath], [])).toBe(NODE);
  });

  it("treats a bare name and its absolute path as equivalent", () => {
    // requested by absolute path, allowlisted by bare name — both resolve equal
    expect(resolveAndMatchCommand(process.execPath, [NODE_BASE], [NODE_DIR])).toBe(NODE);
    // requested by bare name, allowlisted by absolute path
    expect(resolveAndMatchCommand(NODE_BASE, [process.execPath], [NODE_DIR])).toBe(NODE);
  });

  it("denies by default when the allowlist is empty", () => {
    try {
      resolveAndMatchCommand(process.execPath, [], []);
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.COMMAND_NOT_ALLOWED);
    }
  });

  it("denies a command not in the allowlist", () => {
    try {
      resolveAndMatchCommand(process.execPath, ["some-other-binary"], controlledPathDirs());
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.COMMAND_NOT_ALLOWED);
    }
  });

  it("denies an unresolvable command", () => {
    try {
      resolveAndMatchCommand("definitely-not-real-xyz", ["definitely-not-real-xyz"], []);
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.COMMAND_NOT_ALLOWED);
    }
  });
});

// Batch files are excluded by the vault itself, not by relying on patched
// Node's EINVAL for shell-less .cmd/.bat spawns (CVE-2024-27980).
const describeWindows = process.platform === "win32" ? describe : describe.skip;

describeWindows("Windows batch file exclusion", () => {
  let dir: string;
  let symlinkToBatch: string | null = null;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "harpoc-batch-"));
    writeFileSync(join(dir, "tool.cmd"), "@echo off\r\n");
    writeFileSync(join(dir, "tool.bat"), "@echo off\r\n");
    writeFileSync(join(dir, "tool.exe"), "");
    writeFileSync(join(dir, "batchonly.cmd"), "@echo off\r\n");
    writeFileSync(join(dir, "batchonly.bat"), "@echo off\r\n");
    writeFileSync(join(dir, "UPPER.CMD"), "@echo off\r\n");
    try {
      // File symlinks need Developer Mode or elevation on Windows.
      symlinkSync(join(dir, "tool.cmd"), join(dir, "looks-safe.exe"), "file");
      symlinkToBatch = join(dir, "looks-safe.exe");
    } catch {
      symlinkToBatch = null;
    }
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("does not probe .cmd/.bat when resolving a bare name", () => {
    expect(resolveExecutable("batchonly", [dir])).toBeNull();
  });

  it("still probes .exe for a bare name, even with batch siblings", () => {
    expect(resolveExecutable("tool", [dir])).toBe(realpathSync(join(dir, "tool.exe")));
  });

  it("rejects an absolute path to a batch file, case-insensitively", () => {
    expect(resolveExecutable(join(dir, "tool.cmd"), [])).toBeNull();
    expect(resolveExecutable(join(dir, "tool.bat"), [])).toBeNull();
    expect(resolveExecutable(join(dir, "UPPER.CMD"), [])).toBeNull();
  });

  it("denies a batch file at the command-allowlist choke point even when allowlisted", () => {
    const cmd = join(dir, "tool.cmd");
    try {
      resolveAndMatchCommand(cmd, [cmd], []);
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.COMMAND_NOT_ALLOWED);
    }
  });

  it("rejects a symlink whose resolved target is a batch file", (ctx) => {
    if (!symlinkToBatch) return ctx.skip();
    expect(resolveExecutable(symlinkToBatch, [])).toBeNull();
    try {
      resolveAndMatchCommand(symlinkToBatch, [symlinkToBatch], []);
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.COMMAND_NOT_ALLOWED);
    }
  });
});
