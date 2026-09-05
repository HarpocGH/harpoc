import { spawn } from "node:child_process";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { requireIsolation } from "./isolation.js";
import { requireNetworkIsolation } from "./network-isolation.js";
import { spawnCaptured } from "./spawn-captured.js";

/**
 * Seam wiring (thesis §4.5.3 layer 4): `spawnCaptured` is the single choke
 * point where the isolation wrapper applies — these tests pin that the flag
 * consults the adapter, spawns the WRAPPED argv, reports the mechanism, and
 * fails closed before any process exists when the platform cannot isolate.
 * The adapter's own selection/argv logic is pinned in network-isolation.test.ts.
 */

vi.mock("./network-isolation.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./network-isolation.js")>();
  return { ...actual, requireNetworkIsolation: vi.fn(actual.requireNetworkIsolation) };
});

vi.mock("./isolation.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./isolation.js")>();
  return { ...actual, requireIsolation: vi.fn(actual.requireIsolation) };
});

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});

const NODE = process.execPath;
const ENV = process.env as Record<string, string>;
const isolationMock = vi.mocked(requireNetworkIsolation);
const spawnMock = vi.mocked(spawn);
const composerMock = vi.mocked(requireIsolation);

beforeEach(() => {
  isolationMock.mockReset();
  spawnMock.mockClear();
});

describe("spawnCaptured — network isolation seam", () => {
  it("never consults the isolation adapter when the flag is absent", async () => {
    const r = await spawnCaptured(NODE, ["-e", "process.exit(0)"], {
      env: ENV,
      timeoutMs: 30_000,
    });
    expect(r.exit_code).toBe(0);
    expect(r.isolation_mechanism).toBeUndefined();
    expect(isolationMock).not.toHaveBeenCalled();
  });

  it("spawns the wrapped argv and reports the mechanism when the flag is set", async () => {
    isolationMock.mockResolvedValueOnce({
      command: NODE,
      args: ["-e", "process.exit(0)"],
      mechanism: "unshare",
    });
    const r = await spawnCaptured("/audited/original-command", ["original-arg"], {
      env: ENV,
      timeoutMs: 30_000,
      networkIsolation: true,
    });
    expect(isolationMock).toHaveBeenCalledWith("/audited/original-command", ["original-arg"]);
    // The actual spawn used the wrapper's command/args, not the originals.
    const spawnCall = spawnMock.mock.calls.at(-1);
    if (spawnCall === undefined) throw new Error("expected a spawn call");
    const [spawnedCommand, spawnedArgs] = spawnCall;
    expect(spawnedCommand).toBe(NODE);
    expect(spawnedArgs).toEqual(["-e", "process.exit(0)"]);
    expect(r.exit_code).toBe(0);
    expect(r.isolation_mechanism).toBe("unshare");
  });

  it("fails closed before any spawn when the platform cannot isolate", async () => {
    isolationMock.mockRejectedValueOnce(VaultError.networkIsolationUnavailable("mocked"));
    await expect(
      spawnCaptured(NODE, ["-e", "process.exit(0)"], {
        env: ENV,
        timeoutMs: 30_000,
        networkIsolation: true,
      }),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(spawnMock).not.toHaveBeenCalled();
  });
});

/**
 * The composer (`requireIsolation`) is the seam's single adapter once a secret
 * can demand two isolation dimensions: these tests pin that `spawnCaptured`
 * hands it the demanded dimensions, spawns whatever argv it returns, reports
 * BOTH mechanisms, and refuses before any process exists when it rejects.
 * The composition rules themselves are pinned in isolation.test.ts.
 */
describe("spawnCaptured — filesystem isolation seam", () => {
  beforeEach(() => {
    composerMock.mockClear();
  });

  it("never consults the composer when neither isolation flag is set", async () => {
    const r = await spawnCaptured(NODE, ["-e", "process.exit(0)"], {
      env: ENV,
      timeoutMs: 30_000,
    });
    expect(r.exit_code).toBe(0);
    expect(r.isolation_mechanism).toBeUndefined();
    expect(r.fs_isolation_mechanism).toBeUndefined();
    expect(composerMock).not.toHaveBeenCalled();
  });

  it("spawns the wrapped argv and reports the fs mechanism when fsIsolation is set", async () => {
    composerMock.mockResolvedValueOnce({
      command: NODE,
      args: ["-e", "process.exit(0)"],
      fsMechanism: "landlock",
    });
    const r = await spawnCaptured("/audited/original-command", ["original-arg"], {
      env: ENV,
      timeoutMs: 30_000,
      fsIsolation: true,
    });
    expect(composerMock).toHaveBeenCalledWith("/audited/original-command", ["original-arg"], {
      network: false,
      fs: true,
    });
    // The actual spawn used the wrapper's command/args, not the originals.
    const spawnCall = spawnMock.mock.calls.at(-1);
    if (spawnCall === undefined) throw new Error("expected a spawn call");
    const [spawnedCommand, spawnedArgs] = spawnCall;
    expect(spawnedCommand).toBe(NODE);
    expect(spawnedArgs).toEqual(["-e", "process.exit(0)"]);
    expect(r.exit_code).toBe(0);
    expect(r.fs_isolation_mechanism).toBe("landlock");
    expect(r.isolation_mechanism).toBeUndefined();
  });

  it("demands both dimensions and reports both mechanisms when both flags are set", async () => {
    composerMock.mockResolvedValueOnce({
      command: NODE,
      args: ["-e", "process.exit(0)"],
      networkMechanism: "unshare",
      fsMechanism: "landlock",
    });
    const r = await spawnCaptured("/audited/original-command", ["original-arg"], {
      env: ENV,
      timeoutMs: 30_000,
      networkIsolation: true,
      fsIsolation: true,
    });
    expect(composerMock).toHaveBeenCalledWith("/audited/original-command", ["original-arg"], {
      network: true,
      fs: true,
    });
    expect(r.exit_code).toBe(0);
    expect(r.isolation_mechanism).toBe("unshare");
    expect(r.fs_isolation_mechanism).toBe("landlock");
  });

  it("reports bwrap for both dimensions when the composer took the one-wrapper form", async () => {
    composerMock.mockResolvedValueOnce({
      command: NODE,
      args: ["-e", "process.exit(0)"],
      networkMechanism: "bwrap",
      fsMechanism: "bwrap",
    });
    const r = await spawnCaptured("/audited/original-command", ["original-arg"], {
      env: ENV,
      timeoutMs: 30_000,
      networkIsolation: true,
      fsIsolation: true,
    });
    expect(r.exit_code).toBe(0);
    expect(r.isolation_mechanism).toBe("bwrap");
    expect(r.fs_isolation_mechanism).toBe("bwrap");
  });

  it("fails closed before any spawn when the composer refuses fs isolation", async () => {
    composerMock.mockRejectedValueOnce(VaultError.fsIsolationUnavailable("mocked"));
    await expect(
      spawnCaptured(NODE, ["-e", "process.exit(0)"], {
        env: ENV,
        timeoutMs: 30_000,
        fsIsolation: true,
      }),
    ).rejects.toMatchObject({ code: ErrorCode.FS_ISOLATION_UNAVAILABLE });
    expect(spawnMock).not.toHaveBeenCalled();
  });
});
