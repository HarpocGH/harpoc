import { describe, expect, it } from "vitest";

import {
  EXEC_WRAPPERS,
  execWrapperName,
  KNOWN_INTERPRETERS,
  knownInterpreterName,
} from "./interpreters.js";

// ---------------------------------------------------------------------------
// knownInterpreterName
// ---------------------------------------------------------------------------

describe("knownInterpreterName", () => {
  it.each([
    ["sh", "sh"],
    ["bash", "bash"],
    ["zsh", "zsh"],
    ["dash", "dash"],
    ["python", "python"],
    ["node", "node"],
    ["deno", "deno"],
    ["bun", "bun"],
    ["perl", "perl"],
    ["ruby", "ruby"],
    ["php", "php"],
    ["pwsh", "pwsh"],
    ["powershell", "powershell"],
    ["cmd", "cmd"],
    ["busybox", "busybox"],
    ["env", "env"],
    ["npx", "npx"],
    ["uvx", "uvx"],
    ["py", "py"],
  ] as const)("detects the bare name %s", (entry, expected) => {
    expect(knownInterpreterName(entry)).toBe(expected);
  });

  it("detects POSIX absolute paths", () => {
    expect(knownInterpreterName("/usr/bin/python")).toBe("python");
    expect(knownInterpreterName("/bin/sh")).toBe("sh");
    expect(knownInterpreterName("/usr/local/bin/node")).toBe("node");
  });

  it("detects Windows absolute paths with executable extensions", () => {
    expect(knownInterpreterName("C:\\Program Files\\nodejs\\node.exe")).toBe("node");
    expect(knownInterpreterName("C:\\Windows\\System32\\cmd.exe")).toBe("cmd");
    expect(knownInterpreterName("C:\\Python312\\python.exe")).toBe("python");
  });

  it("matches case-insensitively", () => {
    expect(knownInterpreterName("Python")).toBe("python");
    expect(knownInterpreterName("C:\\WINDOWS\\SYSTEM32\\CMD.EXE")).toBe("cmd");
    expect(knownInterpreterName("PowerShell.exe")).toBe("powershell");
  });

  it("strips trailing version suffixes", () => {
    expect(knownInterpreterName("python3")).toBe("python");
    expect(knownInterpreterName("python3.12")).toBe("python");
    expect(knownInterpreterName("/usr/bin/python3.12")).toBe("python");
    expect(knownInterpreterName("php8.2")).toBe("php");
    expect(knownInterpreterName("php-8.2")).toBe("php");
    expect(knownInterpreterName("ruby3.1")).toBe("ruby");
    expect(knownInterpreterName("lua5.4")).toBe("lua");
    expect(knownInterpreterName("perl5.36.0")).toBe("perl");
  });

  it("combines extension and version stripping", () => {
    expect(knownInterpreterName("Python3.12.EXE")).toBe("python");
  });

  it("ignores surrounding whitespace and trailing dots", () => {
    expect(knownInterpreterName("  python  ")).toBe("python");
    expect(knownInterpreterName("python.")).toBe("python");
  });

  it.each([
    "gh",
    "git",
    "curl",
    "aws",
    "kubectl",
    "psql",
    "mysql",
    "ssh",
    "pythonic",
    "node-gyp",
    "ruby-build",
    "some-other-binary",
    "/usr/bin/gh",
    "C:\\Program Files\\Git\\bin\\git.exe",
    "run.sh",
    "deploy.py",
  ])("does not flag the non-interpreter %s", (entry) => {
    expect(knownInterpreterName(entry)).toBeNull();
  });

  it("does not flag scripts named like interpreters with non-executable extensions", () => {
    // A pinned script is a fixed program, not an inline-program vehicle.
    expect(knownInterpreterName("/opt/tools/python-report.sh")).toBeNull();
  });

  it("returns null for empty and separator-only entries", () => {
    expect(knownInterpreterName("")).toBeNull();
    expect(knownInterpreterName("/")).toBeNull();
    expect(knownInterpreterName("C:\\")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// KNOWN_INTERPRETERS
// ---------------------------------------------------------------------------

describe("KNOWN_INTERPRETERS", () => {
  it("contains only normalized (lowercase, unversioned) basenames", () => {
    for (const name of KNOWN_INTERPRETERS) {
      expect(name).toBe(name.toLowerCase());
      expect(knownInterpreterName(name)).toBe(name);
    }
  });

  it("covers the thesis §4.5.3 examples and the common MCP launchers", () => {
    for (const name of ["sh", "bash", "python", "node", "npx"]) {
      expect(KNOWN_INTERPRETERS.has(name)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// execWrapperName / EXEC_WRAPPERS (R6(ii))
// ---------------------------------------------------------------------------

describe("execWrapperName", () => {
  it.each([
    ["sudo", "sudo"],
    ["xargs", "xargs"],
    ["/usr/bin/find", "find"],
    ["C:\\Windows\\System32\\forfiles.exe", "forfiles"],
    ["systemd-run", "systemd-run"],
    ["timeout", "timeout"],
    ["/usr/bin/tar", "tar"],
    ["Rsync.EXE", "rsync"],
    ["/usr/bin/bwrap", "bwrap"],
    ["setpriv", "setpriv"],
    ["/bin/unshare", "unshare"],
  ] as const)("detects %s", (entry, expected) => {
    expect(execWrapperName(entry)).toBe(expected);
  });

  it.each(["gh", "git", "curl", "python", "sh", "env", "busybox", ""])(
    "does not classify %j as an exec wrapper",
    (entry) => {
      expect(execWrapperName(entry)).toBeNull();
    },
  );
});

describe("EXEC_WRAPPERS", () => {
  it("contains only normalized (lowercase, unversioned) basenames", () => {
    for (const name of EXEC_WRAPPERS) {
      expect(name).toBe(name.toLowerCase());
      expect(execWrapperName(name)).toBe(name);
    }
  });

  it("is disjoint from KNOWN_INTERPRETERS — a name belongs to exactly one tier", () => {
    for (const name of EXEC_WRAPPERS) {
      expect(KNOWN_INTERPRETERS.has(name), name).toBe(false);
    }
  });

  it("covers the ruling's examples on both platforms and the vault's own wrapper binaries", () => {
    for (const name of [
      "xargs",
      "find",
      "sudo",
      "tar",
      "rsync",
      "make",
      "forfiles",
      "runas",
      "unshare",
      "setpriv",
      "bwrap",
    ]) {
      expect(EXEC_WRAPPERS.has(name), name).toBe(true);
    }
  });
});
