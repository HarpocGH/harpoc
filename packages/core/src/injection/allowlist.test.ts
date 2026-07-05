import { basename, dirname } from "node:path";
import { realpathSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import {
  controlledPathDirs,
  matchesUrlAllowlist,
  resolveAndMatchCommand,
  resolveExecutable,
} from "./allowlist.js";

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
