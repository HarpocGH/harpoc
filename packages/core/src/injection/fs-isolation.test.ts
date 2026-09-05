import { ErrorCode, VaultError } from "@harpoc/shared";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BWRAP_COMBINED_PREFIX_ARGS, BWRAP_FS_PREFIX_ARGS } from "./bwrap.js";
import {
  LANDLOCK_PREFIX_ARGS,
  LINUX_SETPRIV_CANDIDATES,
  SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE,
  SANDBOX_EXEC_DENY_WRITE_PROFILE,
  forceFsIsolationUnavailableForTests,
  requireCombinedIsolation,
  requireFsIsolation,
  resetFsIsolationProbeForTests,
} from "./fs-isolation.js";

/**
 * The mechanism is pure argv composition over injectable seams — the real
 * kernels are exercised by the platform-gated integration suite. These tests
 * pin selection, the exact wrapped argv shape, fail-closed refusals and the
 * once-per-process probe cache.
 */

function expectFsIsolationUnavailable(err: unknown, reasonFragment: string): void {
  expect(err).toBeInstanceOf(VaultError);
  expect((err as VaultError).code).toBe(ErrorCode.FS_ISOLATION_UNAVAILABLE);
  expect((err as VaultError).message).toContain(reasonFragment);
}

/** Every pinned binary present except bwrap — keeps a single-tier case single-tier. */
const noBwrap = (path: string): boolean => !path.endsWith("/bwrap");

describe("fs-isolation wrapper constants", () => {
  it("pins the Landlock prefix argv one token per element (never joined)", () => {
    expect(LANDLOCK_PREFIX_ARGS).toEqual([
      "--landlock-access",
      "fs",
      "--landlock-rule",
      "path-beneath:execute,read-file,read-dir:/",
      "--landlock-rule",
      "path-beneath:write-file:/dev/null",
      "--",
    ]);
  });

  it("pins the setpriv candidates to absolute paths, /usr/bin first", () => {
    expect(LINUX_SETPRIV_CANDIDATES).toEqual(["/usr/bin/setpriv", "/bin/setpriv"]);
  });

  it("pins both sandbox-exec write profiles byte-exactly — the /dev/null allow clause last (D49)", () => {
    expect(SANDBOX_EXEC_DENY_WRITE_PROFILE).toBe(
      '(version 1)(allow default)(deny file-write*)(allow file-write-data (literal "/dev/null"))',
    );
    expect(SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE).toBe(
      '(version 1)(allow default)(deny network*)(deny file-write*)(allow file-write-data (literal "/dev/null"))',
    );
  });
});

describe("requireFsIsolation", () => {
  beforeEach(() => resetFsIsolationProbeForTests());
  afterEach(() => {
    forceFsIsolationUnavailableForTests(null);
    resetFsIsolationProbeForTests();
  });

  it("wraps with setpriv --landlock-* -- on linux (exact argv, payload last and unmodified)", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const wrap = await requireFsIsolation("/usr/bin/tool", ["--flag", "value"], {
      platform: "linux",
      probeBinary: () => true,
      runProbe,
    });
    // The `--` separator is load-bearing: without it a crafted first arg
    // could parse as a setpriv option (negative control: drop it → this
    // assertion goes red).
    expect(wrap).toEqual({
      command: "/usr/bin/setpriv",
      args: [
        "--landlock-access",
        "fs",
        "--landlock-rule",
        "path-beneath:execute,read-file,read-dir:/",
        "--landlock-rule",
        "path-beneath:write-file:/dev/null",
        "--",
        "/usr/bin/tool",
        "--flag",
        "value",
      ],
      mechanism: "landlock",
    });
    expect(runProbe).toHaveBeenCalledWith("/usr/bin/setpriv", [
      ...LANDLOCK_PREFIX_ARGS,
      "/usr/bin/true",
    ]);
  });

  it("falls back to /bin/setpriv when /usr/bin/setpriv is absent", async () => {
    const wrap = await requireFsIsolation("/usr/bin/tool", [], {
      platform: "linux",
      probeBinary: (p) => p !== "/usr/bin/setpriv",
      runProbe: vi.fn().mockResolvedValue(true),
    });
    expect(wrap.command).toBe("/bin/setpriv");
  });

  it("refuses on linux when setpriv is missing, without running a probe", async () => {
    const runProbe = vi.fn();
    await expect(
      requireFsIsolation("/usr/bin/tool", [], {
        platform: "linux",
        probeBinary: () => false,
        runProbe,
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "setpriv not found");
      return true;
    });
    expect(runProbe).not.toHaveBeenCalled();
  });

  it("refuses on linux when the Landlock capability probe fails and no bwrap is pinned", async () => {
    await expect(
      requireFsIsolation("/usr/bin/tool", [], {
        platform: "linux",
        probeBinary: noBwrap,
        runProbe: vi.fn().mockResolvedValue(false),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "Landlock unavailable");
      return true;
    });
  });

  it("falls back to bwrap --ro-bind when the Landlock probe fails (exact argv, payload last)", async () => {
    const runProbe = vi.fn((command: string) => Promise.resolve(command.endsWith("/bwrap")));
    const wrap = await requireFsIsolation("/usr/bin/tool", ["--flag", "value"], {
      platform: "linux",
      probeBinary: () => true,
      runProbe,
    });
    expect(wrap).toEqual({
      command: "/usr/bin/bwrap",
      args: [
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--die-with-parent",
        "--",
        "/usr/bin/tool",
        "--flag",
        "value",
      ],
      mechanism: "bwrap",
    });
    expect(runProbe).toHaveBeenCalledTimes(2);
    expect(runProbe).toHaveBeenNthCalledWith(1, "/usr/bin/setpriv", [
      ...LANDLOCK_PREFIX_ARGS,
      "/usr/bin/true",
    ]);
    expect(runProbe).toHaveBeenNthCalledWith(2, "/usr/bin/bwrap", [
      ...BWRAP_FS_PREFIX_ARGS,
      "/usr/bin/true",
    ]);
  });

  it("falls back to bwrap when setpriv is absent, probing bwrap alone", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const wrap = await requireFsIsolation("/usr/bin/tool", [], {
      platform: "linux",
      probeBinary: (p) => !p.endsWith("/setpriv"),
      runProbe,
    });
    expect(wrap.mechanism).toBe("bwrap");
    expect(runProbe).toHaveBeenCalledTimes(1);
  });

  it("prefers Landlock when its probe passes — bwrap is never probed on the happy path", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const wrap = await requireFsIsolation("/usr/bin/tool", [], {
      platform: "linux",
      probeBinary: () => true,
      runProbe,
    });
    expect(wrap.mechanism).toBe("landlock");
    expect(runProbe).toHaveBeenCalledTimes(1);
  });

  it("refuses naming both tiers when both probes fail", async () => {
    const runProbe = vi.fn().mockResolvedValue(false);
    await expect(
      requireFsIsolation("/usr/bin/tool", [], {
        platform: "linux",
        probeBinary: () => true,
        runProbe,
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "Landlock unavailable");
      expect((err as VaultError).message).toContain("bwrap --ro-bind probe failed");
      return true;
    });
    expect(runProbe).toHaveBeenCalledTimes(2);
  });

  it("refuses naming the absent bwrap when setpriv is absent too, without running a probe", async () => {
    const runProbe = vi.fn();
    await expect(
      requireFsIsolation("/usr/bin/tool", [], {
        platform: "linux",
        probeBinary: () => false,
        runProbe,
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "setpriv not found in /usr/bin or /bin; bwrap not found");
      return true;
    });
    expect(runProbe).not.toHaveBeenCalled();
  });

  it("wraps with sandbox-exec -p <deny-write profile> on darwin (profile byte-exact)", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const wrap = await requireFsIsolation("/usr/bin/tool", ["arg"], {
      platform: "darwin",
      probeBinary: () => true,
      runProbe,
    });
    expect(SANDBOX_EXEC_DENY_WRITE_PROFILE).toBe(
      '(version 1)(allow default)(deny file-write*)(allow file-write-data (literal "/dev/null"))',
    );
    expect(wrap).toEqual({
      command: "/usr/bin/sandbox-exec",
      args: ["-p", SANDBOX_EXEC_DENY_WRITE_PROFILE, "/usr/bin/tool", "arg"],
      mechanism: "sandbox-exec",
    });
    expect(runProbe).toHaveBeenCalledWith("/usr/bin/sandbox-exec", [
      "-p",
      SANDBOX_EXEC_DENY_WRITE_PROFILE,
      "/usr/bin/true",
    ]);
  });

  it("refuses on darwin when sandbox-exec is missing or its probe fails", async () => {
    await expect(
      requireFsIsolation("/usr/bin/tool", [], {
        platform: "darwin",
        probeBinary: () => false,
        runProbe: vi.fn(),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "sandbox-exec not found");
      return true;
    });
    resetFsIsolationProbeForTests();
    await expect(
      requireFsIsolation("/usr/bin/tool", [], {
        platform: "darwin",
        probeBinary: () => true,
        runProbe: vi.fn().mockResolvedValue(false),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "sandbox-exec deny-write probe failed");
      return true;
    });
  });

  it("refuses on win32 without consulting any binary or probe", async () => {
    const probeBinary = vi.fn();
    const runProbe = vi.fn();
    await expect(
      requireFsIsolation("C:\\tool.exe", [], { platform: "win32", probeBinary, runProbe }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "unsupported platform: win32");
      return true;
    });
    expect(probeBinary).not.toHaveBeenCalled();
    expect(runProbe).not.toHaveBeenCalled();
  });

  it("probes exactly once across concurrent and sequential calls (cached)", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const seams = { platform: "linux" as const, probeBinary: () => true, runProbe };
    const [a, b] = await Promise.all([
      requireFsIsolation("/usr/bin/one", [], seams),
      requireFsIsolation("/usr/bin/two", [], seams),
    ]);
    await requireFsIsolation("/usr/bin/three", [], seams);
    expect(runProbe).toHaveBeenCalledTimes(1);
    expect(a.args).toContain("/usr/bin/one");
    expect(b.args).toContain("/usr/bin/two");
  });

  it("re-probes after the test reset hook", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const seams = { platform: "linux" as const, probeBinary: () => true, runProbe };
    await requireFsIsolation("/usr/bin/tool", [], seams);
    resetFsIsolationProbeForTests();
    await requireFsIsolation("/usr/bin/tool", [], seams);
    expect(runProbe).toHaveBeenCalledTimes(2);
  });

  it("does NOT cache a failed probe — a transient failure self-heals (review fix F5)", async () => {
    // Pre-fix, the first rejection was cached for the process lifetime: one
    // loaded-host probe timeout permanently disabled every isolation-
    // demanding spawn until the vault restarted.
    const runProbe = vi.fn().mockResolvedValueOnce(false).mockResolvedValue(true);
    const seams = { platform: "linux" as const, probeBinary: noBwrap, runProbe };
    await expect(requireFsIsolation("/usr/bin/tool", [], seams)).rejects.toBeInstanceOf(VaultError);
    const wrap = await requireFsIsolation("/usr/bin/tool", [], seams);
    expect(wrap.mechanism).toBe("landlock");
    expect(runProbe).toHaveBeenCalledTimes(2);
  });

  it("a persistently failing probe still refuses every call (fail closed, re-probed)", async () => {
    const runProbe = vi.fn().mockResolvedValue(false);
    const seams = { platform: "linux" as const, probeBinary: noBwrap, runProbe };
    await expect(requireFsIsolation("/usr/bin/tool", [], seams)).rejects.toBeInstanceOf(VaultError);
    await expect(requireFsIsolation("/usr/bin/tool", [], seams)).rejects.toBeInstanceOf(VaultError);
    expect(runProbe).toHaveBeenCalledTimes(2);
  });

  it("concurrent callers coalesce on one in-flight probe even when it fails", async () => {
    const runProbe = vi.fn().mockResolvedValue(false);
    const seams = { platform: "linux" as const, probeBinary: noBwrap, runProbe };
    const [a, b] = await Promise.allSettled([
      requireFsIsolation("/usr/bin/one", [], seams),
      requireFsIsolation("/usr/bin/two", [], seams),
    ]);
    expect(a.status).toBe("rejected");
    expect(b.status).toBe("rejected");
    expect(runProbe).toHaveBeenCalledTimes(1);
  });

  it("forceFsIsolationUnavailableForTests forces refusal and restores on null", async () => {
    const seams = {
      platform: "linux" as const,
      probeBinary: () => true,
      runProbe: vi.fn().mockResolvedValue(true),
    };
    forceFsIsolationUnavailableForTests("forced by test");
    await expect(requireFsIsolation("/usr/bin/tool", [], seams)).rejects.toSatisfy(
      (err: unknown) => {
        expectFsIsolationUnavailable(err, "forced by test");
        return true;
      },
    );
    forceFsIsolationUnavailableForTests(null);
    const wrap = await requireFsIsolation("/usr/bin/tool", [], seams);
    expect(wrap.mechanism).toBe("landlock");
  });

  it("is checked before any platform lookup — the force hook wins on darwin too", async () => {
    const probeBinary = vi.fn();
    const runProbe = vi.fn();
    forceFsIsolationUnavailableForTests("forced everywhere");
    await expect(
      requireFsIsolation("/usr/bin/tool", [], { platform: "darwin", probeBinary, runProbe }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "forced everywhere");
      return true;
    });
    expect(probeBinary).not.toHaveBeenCalled();
    expect(runProbe).not.toHaveBeenCalled();
  });
});

describe("requireCombinedIsolation", () => {
  beforeEach(() => resetFsIsolationProbeForTests());
  afterEach(() => {
    forceFsIsolationUnavailableForTests(null);
    resetFsIsolationProbeForTests();
  });

  it("wraps darwin in ONE sandbox-exec -p <combined profile> (profile byte-exact, payload last)", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const wrap = await requireCombinedIsolation("/usr/bin/tool", ["--flag", "value"], {
      platform: "darwin",
      probeBinary: () => true,
      runProbe,
    });
    expect(SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE).toBe(
      '(version 1)(allow default)(deny network*)(deny file-write*)(allow file-write-data (literal "/dev/null"))',
    );
    expect(wrap).toEqual({
      command: "/usr/bin/sandbox-exec",
      args: ["-p", SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE, "/usr/bin/tool", "--flag", "value"],
      mechanism: "sandbox-exec",
    });
    // Exactly one wrapper — never sandbox-exec nested inside sandbox-exec.
    expect(wrap.args.filter((a) => a === "/usr/bin/sandbox-exec")).toHaveLength(0);
    expect(runProbe).toHaveBeenCalledTimes(1);
    expect(runProbe).toHaveBeenCalledWith("/usr/bin/sandbox-exec", [
      "-p",
      SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE,
      "/usr/bin/true",
    ]);
  });

  it("refuses on darwin when sandbox-exec is missing or its probe fails", async () => {
    await expect(
      requireCombinedIsolation("/usr/bin/tool", [], {
        platform: "darwin",
        probeBinary: () => false,
        runProbe: vi.fn(),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "sandbox-exec not found");
      return true;
    });
    resetFsIsolationProbeForTests();
    await expect(
      requireCombinedIsolation("/usr/bin/tool", [], {
        platform: "darwin",
        probeBinary: () => true,
        runProbe: vi.fn().mockResolvedValue(false),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "sandbox-exec deny-network+deny-write probe failed");
      return true;
    });
  });

  it("refuses on win32 without consulting any binary or probe", async () => {
    const probeBinary = vi.fn();
    const runProbe = vi.fn();
    await expect(
      requireCombinedIsolation("C:\\tool.exe", [], { platform: "win32", probeBinary, runProbe }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "unsupported platform: win32");
      return true;
    });
    expect(probeBinary).not.toHaveBeenCalled();
    expect(runProbe).not.toHaveBeenCalled();
  });

  it("resolves ONE bwrap wrapper on linux (exact argv, payload last) — the composer's form when the primaries do not both resolve", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const wrap = await requireCombinedIsolation("/usr/bin/tool", ["--flag", "value"], {
      platform: "linux",
      probeBinary: () => true,
      runProbe,
    });
    expect(wrap).toEqual({
      command: "/usr/bin/bwrap",
      args: [
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--unshare-net",
        "--die-with-parent",
        "--",
        "/usr/bin/tool",
        "--flag",
        "value",
      ],
      mechanism: "bwrap",
    });
    expect(wrap.args.filter((a) => a === "/usr/bin/bwrap")).toHaveLength(0);
    expect(runProbe).toHaveBeenCalledTimes(1);
    expect(runProbe).toHaveBeenCalledWith("/usr/bin/bwrap", [
      ...BWRAP_COMBINED_PREFIX_ARGS,
      "/usr/bin/true",
    ]);
  });

  it("refuses on linux when bwrap is absent or its combined probe fails, never consulting setpriv or unshare", async () => {
    const probeBinary = vi.fn((p: string) => !p.endsWith("/bwrap"));
    const runProbe = vi.fn();
    await expect(
      requireCombinedIsolation("/usr/bin/tool", [], { platform: "linux", probeBinary, runProbe }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "bwrap not found in /usr/bin or /bin");
      return true;
    });
    expect(runProbe).not.toHaveBeenCalled();
    expect(probeBinary.mock.calls.map((c) => c[0])).not.toContain("/usr/bin/setpriv");
    expect(probeBinary.mock.calls.map((c) => c[0])).not.toContain("/usr/bin/unshare");
    resetFsIsolationProbeForTests();
    await expect(
      requireCombinedIsolation("/usr/bin/tool", [], {
        platform: "linux",
        probeBinary: () => true,
        runProbe: vi.fn().mockResolvedValue(false),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectFsIsolationUnavailable(err, "bwrap --ro-bind --unshare-net probe failed");
      return true;
    });
  });

  it("keeps its own cache slot on linux too — the filesystem and combined bwrap probes never share", async () => {
    const runProbe = vi.fn((command: string) => Promise.resolve(command.endsWith("/bwrap")));
    const seams = { platform: "linux" as const, probeBinary: () => true, runProbe };
    const fsWrap = await requireFsIsolation("/usr/bin/tool", [], seams);
    const combinedWrap = await requireCombinedIsolation("/usr/bin/tool", [], seams);
    expect(runProbe).toHaveBeenCalledTimes(3);
    expect(runProbe).toHaveBeenNthCalledWith(2, "/usr/bin/bwrap", [
      ...BWRAP_FS_PREFIX_ARGS,
      "/usr/bin/true",
    ]);
    expect(runProbe).toHaveBeenNthCalledWith(3, "/usr/bin/bwrap", [
      ...BWRAP_COMBINED_PREFIX_ARGS,
      "/usr/bin/true",
    ]);
    expect(fsWrap.args).not.toContain("--unshare-net");
    expect(combinedWrap.args).toContain("--unshare-net");
  });

  it("probes exactly once across concurrent and sequential calls (cached)", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const seams = { platform: "darwin" as const, probeBinary: () => true, runProbe };
    const [a, b] = await Promise.all([
      requireCombinedIsolation("/usr/bin/one", [], seams),
      requireCombinedIsolation("/usr/bin/two", [], seams),
    ]);
    await requireCombinedIsolation("/usr/bin/three", [], seams);
    expect(runProbe).toHaveBeenCalledTimes(1);
    expect(a.args).toContain("/usr/bin/one");
    expect(b.args).toContain("/usr/bin/two");
  });

  it("re-probes after the test reset hook", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const seams = { platform: "darwin" as const, probeBinary: () => true, runProbe };
    await requireCombinedIsolation("/usr/bin/tool", [], seams);
    resetFsIsolationProbeForTests();
    await requireCombinedIsolation("/usr/bin/tool", [], seams);
    expect(runProbe).toHaveBeenCalledTimes(2);
  });

  it("does NOT cache a failed probe — a transient failure self-heals", async () => {
    const runProbe = vi.fn().mockResolvedValueOnce(false).mockResolvedValue(true);
    const seams = { platform: "darwin" as const, probeBinary: () => true, runProbe };
    await expect(requireCombinedIsolation("/usr/bin/tool", [], seams)).rejects.toBeInstanceOf(
      VaultError,
    );
    const wrap = await requireCombinedIsolation("/usr/bin/tool", [], seams);
    expect(wrap.mechanism).toBe("sandbox-exec");
    expect(runProbe).toHaveBeenCalledTimes(2);
  });

  it("a persistently failing probe still refuses every call (fail closed, re-probed)", async () => {
    const runProbe = vi.fn().mockResolvedValue(false);
    const seams = { platform: "darwin" as const, probeBinary: () => true, runProbe };
    await expect(requireCombinedIsolation("/usr/bin/tool", [], seams)).rejects.toBeInstanceOf(
      VaultError,
    );
    await expect(requireCombinedIsolation("/usr/bin/tool", [], seams)).rejects.toBeInstanceOf(
      VaultError,
    );
    expect(runProbe).toHaveBeenCalledTimes(2);
  });

  it("concurrent callers coalesce on one in-flight probe even when it fails", async () => {
    const runProbe = vi.fn().mockResolvedValue(false);
    const seams = { platform: "darwin" as const, probeBinary: () => true, runProbe };
    const [a, b] = await Promise.allSettled([
      requireCombinedIsolation("/usr/bin/one", [], seams),
      requireCombinedIsolation("/usr/bin/two", [], seams),
    ]);
    expect(a.status).toBe("rejected");
    expect(b.status).toBe("rejected");
    expect(runProbe).toHaveBeenCalledTimes(1);
  });

  it("forceFsIsolationUnavailableForTests forces refusal and restores on null", async () => {
    const probeBinary = vi.fn().mockReturnValue(true);
    const runProbe = vi.fn().mockResolvedValue(true);
    const seams = { platform: "darwin" as const, probeBinary, runProbe };
    forceFsIsolationUnavailableForTests("forced by test");
    await expect(requireCombinedIsolation("/usr/bin/tool", [], seams)).rejects.toSatisfy(
      (err: unknown) => {
        expectFsIsolationUnavailable(err, "forced by test");
        return true;
      },
    );
    expect(probeBinary).not.toHaveBeenCalled();
    expect(runProbe).not.toHaveBeenCalled();
    forceFsIsolationUnavailableForTests(null);
    const wrap = await requireCombinedIsolation("/usr/bin/tool", [], seams);
    expect(wrap.mechanism).toBe("sandbox-exec");
  });

  it("keeps its own cache slot — the deny-write and combined probes never share", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const seams = { platform: "darwin" as const, probeBinary: () => true, runProbe };
    const fsWrap = await requireFsIsolation("/usr/bin/tool", [], seams);
    const combinedWrap = await requireCombinedIsolation("/usr/bin/tool", [], seams);
    expect(runProbe).toHaveBeenCalledTimes(2);
    expect(runProbe).toHaveBeenNthCalledWith(1, "/usr/bin/sandbox-exec", [
      "-p",
      SANDBOX_EXEC_DENY_WRITE_PROFILE,
      "/usr/bin/true",
    ]);
    expect(runProbe).toHaveBeenNthCalledWith(2, "/usr/bin/sandbox-exec", [
      "-p",
      SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE,
      "/usr/bin/true",
    ]);
    expect(fsWrap.args[1]).toBe(SANDBOX_EXEC_DENY_WRITE_PROFILE);
    expect(combinedWrap.args[1]).toBe(SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE);
  });
});
