import { ErrorCode, VaultError } from "@harpoc/shared";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  SANDBOX_EXEC_DENY_NETWORK_PROFILE,
  forceNetworkIsolationUnavailableForTests,
  requireNetworkIsolation,
  resetNetworkIsolationProbeForTests,
} from "./network-isolation.js";

/**
 * The mechanism is pure argv composition over injectable seams — the real
 * kernels are exercised by the platform-gated integration suite. These tests
 * pin selection, the exact wrapped argv shape, fail-closed refusals and the
 * once-per-process probe cache.
 */

function expectIsolationUnavailable(err: unknown, reasonFragment: string): void {
  expect(err).toBeInstanceOf(VaultError);
  expect((err as VaultError).code).toBe(ErrorCode.NETWORK_ISOLATION_UNAVAILABLE);
  expect((err as VaultError).message).toContain(reasonFragment);
}

describe("requireNetworkIsolation", () => {
  beforeEach(() => resetNetworkIsolationProbeForTests());
  afterEach(() => {
    forceNetworkIsolationUnavailableForTests(null);
    resetNetworkIsolationProbeForTests();
  });

  it("wraps with unshare -rn -- on linux (exact argv, payload last and unmodified)", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const wrap = await requireNetworkIsolation("/usr/bin/tool", ["--flag", "value"], {
      platform: "linux",
      probeBinary: () => true,
      runProbe,
    });
    // The `--` separator is load-bearing: without it a crafted first arg
    // could parse as an unshare option (negative control: drop it → this
    // assertion goes red).
    expect(wrap).toEqual({
      command: "/usr/bin/unshare",
      args: ["-rn", "--", "/usr/bin/tool", "--flag", "value"],
      mechanism: "unshare",
    });
    expect(runProbe).toHaveBeenCalledWith("/usr/bin/unshare", ["-rn", "--", "/usr/bin/true"]);
  });

  it("falls back to /bin/unshare when /usr/bin/unshare is absent", async () => {
    const wrap = await requireNetworkIsolation("/usr/bin/tool", [], {
      platform: "linux",
      probeBinary: (p) => p !== "/usr/bin/unshare",
      runProbe: vi.fn().mockResolvedValue(true),
    });
    expect(wrap.command).toBe("/bin/unshare");
  });

  it("refuses on linux when unshare is missing, without running a probe", async () => {
    const runProbe = vi.fn();
    await expect(
      requireNetworkIsolation("/usr/bin/tool", [], {
        platform: "linux",
        probeBinary: () => false,
        runProbe,
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectIsolationUnavailable(err, "unshare not found");
      return true;
    });
    expect(runProbe).not.toHaveBeenCalled();
  });

  it("refuses on linux when the userns capability probe fails", async () => {
    await expect(
      requireNetworkIsolation("/usr/bin/tool", [], {
        platform: "linux",
        probeBinary: () => true,
        runProbe: vi.fn().mockResolvedValue(false),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectIsolationUnavailable(err, "user namespaces unavailable");
      return true;
    });
  });

  it("wraps with sandbox-exec -p <profile> on darwin (profile byte-exact)", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const wrap = await requireNetworkIsolation("/usr/bin/tool", ["arg"], {
      platform: "darwin",
      probeBinary: () => true,
      runProbe,
    });
    expect(SANDBOX_EXEC_DENY_NETWORK_PROFILE).toBe("(version 1)(allow default)(deny network*)");
    expect(wrap).toEqual({
      command: "/usr/bin/sandbox-exec",
      args: ["-p", SANDBOX_EXEC_DENY_NETWORK_PROFILE, "/usr/bin/tool", "arg"],
      mechanism: "sandbox-exec",
    });
    expect(runProbe).toHaveBeenCalledWith("/usr/bin/sandbox-exec", [
      "-p",
      SANDBOX_EXEC_DENY_NETWORK_PROFILE,
      "/usr/bin/true",
    ]);
  });

  it("refuses on darwin when sandbox-exec is missing or its probe fails", async () => {
    await expect(
      requireNetworkIsolation("/usr/bin/tool", [], {
        platform: "darwin",
        probeBinary: () => false,
        runProbe: vi.fn(),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectIsolationUnavailable(err, "sandbox-exec not found");
      return true;
    });
    resetNetworkIsolationProbeForTests();
    await expect(
      requireNetworkIsolation("/usr/bin/tool", [], {
        platform: "darwin",
        probeBinary: () => true,
        runProbe: vi.fn().mockResolvedValue(false),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expectIsolationUnavailable(err, "sandbox-exec deny-network probe failed");
      return true;
    });
  });

  it("refuses on win32 without consulting any binary or probe", async () => {
    const probeBinary = vi.fn();
    const runProbe = vi.fn();
    await expect(
      requireNetworkIsolation("C:\\tool.exe", [], { platform: "win32", probeBinary, runProbe }),
    ).rejects.toSatisfy((err: unknown) => {
      expectIsolationUnavailable(err, "unsupported platform: win32");
      return true;
    });
    expect(probeBinary).not.toHaveBeenCalled();
    expect(runProbe).not.toHaveBeenCalled();
  });

  it("probes exactly once across concurrent and sequential calls (cached)", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const seams = { platform: "linux" as const, probeBinary: () => true, runProbe };
    const [a, b] = await Promise.all([
      requireNetworkIsolation("/usr/bin/one", [], seams),
      requireNetworkIsolation("/usr/bin/two", [], seams),
    ]);
    await requireNetworkIsolation("/usr/bin/three", [], seams);
    expect(runProbe).toHaveBeenCalledTimes(1);
    expect(a.args).toContain("/usr/bin/one");
    expect(b.args).toContain("/usr/bin/two");
  });

  it("re-probes after the test reset hook", async () => {
    const runProbe = vi.fn().mockResolvedValue(true);
    const seams = { platform: "linux" as const, probeBinary: () => true, runProbe };
    await requireNetworkIsolation("/usr/bin/tool", [], seams);
    resetNetworkIsolationProbeForTests();
    await requireNetworkIsolation("/usr/bin/tool", [], seams);
    expect(runProbe).toHaveBeenCalledTimes(2);
  });

  it("caches a failed resolution too (capability does not change under the vault)", async () => {
    const runProbe = vi.fn().mockResolvedValue(false);
    const seams = { platform: "linux" as const, probeBinary: () => true, runProbe };
    await expect(requireNetworkIsolation("/usr/bin/tool", [], seams)).rejects.toBeInstanceOf(
      VaultError,
    );
    await expect(requireNetworkIsolation("/usr/bin/tool", [], seams)).rejects.toBeInstanceOf(
      VaultError,
    );
    expect(runProbe).toHaveBeenCalledTimes(1);
  });

  it("forceNetworkIsolationUnavailableForTests forces refusal and restores on null", async () => {
    const seams = {
      platform: "linux" as const,
      probeBinary: () => true,
      runProbe: vi.fn().mockResolvedValue(true),
    };
    forceNetworkIsolationUnavailableForTests("forced by test");
    await expect(requireNetworkIsolation("/usr/bin/tool", [], seams)).rejects.toSatisfy(
      (err: unknown) => {
        expectIsolationUnavailable(err, "forced by test");
        return true;
      },
    );
    forceNetworkIsolationUnavailableForTests(null);
    const wrap = await requireNetworkIsolation("/usr/bin/tool", [], seams);
    expect(wrap.mechanism).toBe("unshare");
  });
});
