import { basename, dirname, join } from "node:path";
import { mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
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
  it("denies by default when the allowlist is empty", () => {
    expect(matchesHostAllowlist("evil.example.com", [])).toBe(false);
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
  it("denies by default when the allowlist is empty", () => {
    expect(matchesHostPortAllowlist("db.example.com", 5432, [])).toBe(false);
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
    expect(
      matchesHostPortAllowlist("primary.db.example.com", 5432, ["*.db.example.com:5432"]),
    ).toBe(true);
    expect(matchesHostPortAllowlist("evil.example.com", 5432, ["*.db.example.com:5432"])).toBe(
      false,
    );
  });
});

// ---------------------------------------------------------------------------
// URL allowlist
// ---------------------------------------------------------------------------

describe("matchesUrlAllowlist", () => {
  it("denies by default when the allowlist is empty", () => {
    expect(matchesUrlAllowlist("https://anywhere.example/x", [])).toBe(false);
  });

  it("matches a bracketed IPv6 literal host in its WHATWG-canonical form", () => {
    expect(matchesUrlAllowlist("https://[fc00::1]/api", ["https://[fc00::1]/*"])).toBe(true);
    expect(matchesUrlAllowlist("https://[fc00::1]/api", ["https://[FC00:0::1]/*"])).toBe(true);
    expect(matchesUrlAllowlist("http://[::1]:8443/x", ["http://[0:0::1]:8443/*"])).toBe(true);
    expect(
      matchesUrlAllowlist("wss://[::ffff:192.168.1.1]/x", ["wss://[::ffff:192.168.1.1]/*"]),
    ).toBe(true);
  });

  it("a bracketed pattern binds its port and scheme like any other", () => {
    expect(matchesUrlAllowlist("http://[::1]:8443/x", ["http://[::1]/*"])).toBe(false);
    expect(matchesUrlAllowlist("http://[::1]:8443/x", ["https://[::1]:8443/*"])).toBe(false);
    expect(matchesUrlAllowlist("https://[fc00::1]/api", ["https://[fc00::2]/*"])).toBe(false);
  });

  it("matches an exact URL", () => {
    expect(
      matchesUrlAllowlist("https://api.github.com/user", ["https://api.github.com/user"]),
    ).toBe(true);
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
    expect(matchesUrlAllowlist("http://api.github.com/x", ["https://api.github.com/*"])).toBe(
      false,
    );
  });

  it("rejects a port mismatch", () => {
    expect(matchesUrlAllowlist("https://api.github.com:8443/x", ["https://api.github.com/*"])).toBe(
      false,
    );
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

  it("denies by default when the allowlist is empty", async () => {
    await expectVaultError(
      () => resolveAndMatchCommand(process.execPath, [], []),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
  });

  it("denies a command not in the allowlist", async () => {
    await expectVaultError(
      () => resolveAndMatchCommand(process.execPath, ["some-other-binary"], controlledPathDirs()),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
  });

  it("denies an unresolvable command", async () => {
    await expectVaultError(
      () => resolveAndMatchCommand("definitely-not-real-xyz", ["definitely-not-real-xyz"], []),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
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

  it("denies a batch file at the command-allowlist choke point even when allowlisted", async () => {
    const cmd = join(dir, "tool.cmd");
    await expectVaultError(
      () => resolveAndMatchCommand(cmd, [cmd], []),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
  });

  it("rejects a symlink whose resolved target is a batch file", async (ctx) => {
    if (!symlinkToBatch) return ctx.skip();
    const link = symlinkToBatch;
    expect(resolveExecutable(link, [])).toBeNull();
    await expectVaultError(
      () => resolveAndMatchCommand(link, [link], []),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
  });
});

// On Windows only a PE file is spawnable: CreateProcess refuses everything else
// (ERROR_BAD_EXE_FORMAT), and Docker Desktop 4.87 ships a POSIX shell shim named
// `docker` beside `docker.exe`, which the bare-name probe found first (2026-09-17).
describeWindows("Windows executable extensions", () => {
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "harpoc-pe-"));
    writeFileSync(join(dir, "docker"), '#!/usr/bin/env sh\nexec "$0.exe" "$@"\n');
    writeFileSync(join(dir, "docker.exe"), "");
    writeFileSync(join(dir, "shimonly"), "#!/usr/bin/env sh\nexit 0\n");
    writeFileSync(join(dir, "UPPER.EXE"), "");
    writeFileSync(join(dir, "tool2.com"), "");
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("skips an extensionless sibling and resolves the .exe for a bare name", () => {
    expect(resolveExecutable("docker", [dir])).toBe(realpathSync(join(dir, "docker.exe")));
  });

  it("resolves nothing for a bare name whose only candidate is extensionless", () => {
    expect(resolveExecutable("shimonly", [dir])).toBeNull();
  });

  it("refuses an absolute extensionless path at the resolver and at the allowlist choke point", async () => {
    const shim = join(dir, "shimonly");
    expect(resolveExecutable(shim, [])).toBeNull();
    await expectVaultError(
      () => resolveAndMatchCommand(shim, [shim], []),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
  });

  it("resolves an absolute extensionless path to its .exe sibling, never to the file itself", () => {
    const shim = join(dir, "docker");
    const exe = realpathSync(join(dir, "docker.exe"));
    expect(resolveExecutable(shim, [])).toBe(exe);
    expect(resolveAndMatchCommand(shim, [shim], [])).toBe(exe);
  });

  it("accepts .exe and .com, whatever the extension's case", () => {
    const upper = join(dir, "UPPER.EXE");
    expect(resolveExecutable(upper, [])).toBe(realpathSync(upper));
    expect(resolveExecutable("tool2", [dir])).toBe(realpathSync(join(dir, "tool2.com")));
  });
});
