import { ErrorCode, VaultError } from "@harpoc/shared";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  LANDLOCK_PREFIX_ARGS,
  SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE,
  requireCombinedIsolation,
  requireFsIsolation,
} from "./fs-isolation.js";
import { requireIsolation } from "./isolation.js";
import { requireNetworkIsolation } from "./network-isolation.js";

/**
 * The composer is pure delegation + argv nesting over the two per-dimension
 * resolvers, so both are mocked here: these tests pin which resolver each
 * dimension combination consults, the nesting order (network outermost, fs
 * inner, payload last) and the deterministic refusal code when both dimensions
 * are demanded on a platform that can deliver neither.
 */

vi.mock("./network-isolation.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./network-isolation.js")>();
  return { ...actual, requireNetworkIsolation: vi.fn(actual.requireNetworkIsolation) };
});

vi.mock("./fs-isolation.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./fs-isolation.js")>();
  return {
    ...actual,
    requireFsIsolation: vi.fn(actual.requireFsIsolation),
    requireCombinedIsolation: vi.fn(actual.requireCombinedIsolation),
  };
});

const netMock = vi.mocked(requireNetworkIsolation);
const fsMock = vi.mocked(requireFsIsolation);
const combinedMock = vi.mocked(requireCombinedIsolation);

const PAYLOAD = "/audited/payload";
const PAYLOAD_ARGS = ["--flag", "value"];
const LANDLOCK_ARGS = [...LANDLOCK_PREFIX_ARGS, PAYLOAD, ...PAYLOAD_ARGS];

function withPlatform(platform: NodeJS.Platform, fn: () => Promise<void>): Promise<void> {
  const original = process.platform;
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
  return fn().finally(() => {
    Object.defineProperty(process, "platform", { value: original, configurable: true });
  });
}

beforeEach(() => {
  netMock.mockReset();
  fsMock.mockReset();
  combinedMock.mockReset();
});

describe("requireIsolation — network only", () => {
  it("delegates to requireNetworkIsolation with the payload argv unchanged", async () => {
    netMock.mockResolvedValueOnce({
      command: "/usr/bin/unshare",
      args: ["-rn", "--", PAYLOAD, ...PAYLOAD_ARGS],
      mechanism: "unshare",
    });

    const wrap = await requireIsolation(PAYLOAD, PAYLOAD_ARGS, { network: true, fs: false });

    expect(netMock).toHaveBeenCalledTimes(1);
    expect(netMock).toHaveBeenCalledWith(PAYLOAD, PAYLOAD_ARGS);
    expect(fsMock).not.toHaveBeenCalled();
    expect(combinedMock).not.toHaveBeenCalled();
    expect(wrap.command).toBe("/usr/bin/unshare");
    expect(wrap.args).toEqual(["-rn", "--", PAYLOAD, ...PAYLOAD_ARGS]);
    expect(wrap.networkMechanism).toBe("unshare");
    expect(wrap.fsMechanism).toBeUndefined();
  });

  it("propagates the network resolver's refusal unchanged", async () => {
    netMock.mockRejectedValueOnce(VaultError.networkIsolationUnavailable("mocked"));

    await expect(
      requireIsolation(PAYLOAD, PAYLOAD_ARGS, { network: true, fs: false }),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
  });
});

describe("requireIsolation — filesystem only", () => {
  it("delegates to requireFsIsolation and reports only the fs mechanism", async () => {
    fsMock.mockResolvedValueOnce({
      command: "/usr/bin/setpriv",
      args: LANDLOCK_ARGS,
      mechanism: "landlock",
    });

    const wrap = await requireIsolation(PAYLOAD, PAYLOAD_ARGS, { network: false, fs: true });

    expect(fsMock).toHaveBeenCalledTimes(1);
    expect(fsMock).toHaveBeenCalledWith(PAYLOAD, PAYLOAD_ARGS);
    expect(netMock).not.toHaveBeenCalled();
    expect(combinedMock).not.toHaveBeenCalled();
    expect(wrap.command).toBe("/usr/bin/setpriv");
    expect(wrap.args).toEqual(LANDLOCK_ARGS);
    expect(wrap.fsMechanism).toBe("landlock");
    expect(wrap.networkMechanism).toBeUndefined();
  });

  it("propagates the fs resolver's refusal unchanged", async () => {
    fsMock.mockRejectedValueOnce(VaultError.fsIsolationUnavailable("mocked"));

    await expect(
      requireIsolation(PAYLOAD, PAYLOAD_ARGS, { network: false, fs: true }),
    ).rejects.toMatchObject({ code: ErrorCode.FS_ISOLATION_UNAVAILABLE });
  });
});

describe("requireIsolation — both dimensions", () => {
  it("composes unshare outside setpriv on linux, payload last", () =>
    withPlatform("linux", async () => {
      fsMock.mockResolvedValueOnce({
        command: "/usr/bin/setpriv",
        args: LANDLOCK_ARGS,
        mechanism: "landlock",
      });
      netMock.mockImplementation((command: string, args: string[]) =>
        Promise.resolve({
          command: "/usr/bin/unshare",
          args: ["-rn", "--", command, ...args],
          mechanism: "unshare" as const,
        }),
      );

      const wrap = await requireIsolation(PAYLOAD, PAYLOAD_ARGS, { network: true, fs: true });

      expect(fsMock).toHaveBeenCalledWith(PAYLOAD, PAYLOAD_ARGS);
      expect(netMock).toHaveBeenCalledWith("/usr/bin/setpriv", LANDLOCK_ARGS);
      expect(combinedMock).not.toHaveBeenCalled();
      expect(fsMock.mock.invocationCallOrder[0] as number).toBeLessThan(
        netMock.mock.invocationCallOrder[0] as number,
      );
      expect(wrap.command).toBe("/usr/bin/unshare");
      expect(wrap.args).toEqual([
        "-rn",
        "--",
        "/usr/bin/setpriv",
        ...LANDLOCK_PREFIX_ARGS,
        PAYLOAD,
        ...PAYLOAD_ARGS,
      ]);
      expect(wrap.args.slice(-3)).toEqual([PAYLOAD, ...PAYLOAD_ARGS]);
      expect(wrap.networkMechanism).toBe("unshare");
      expect(wrap.fsMechanism).toBe("landlock");
    }));

  it("uses ONE combined sandbox-exec wrapper on darwin, never nesting two sandboxes", () =>
    withPlatform("darwin", async () => {
      combinedMock.mockResolvedValueOnce({
        command: "/usr/bin/sandbox-exec",
        args: ["-p", SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE, PAYLOAD, ...PAYLOAD_ARGS],
        mechanism: "sandbox-exec",
      });

      const wrap = await requireIsolation(PAYLOAD, PAYLOAD_ARGS, { network: true, fs: true });

      expect(combinedMock).toHaveBeenCalledTimes(1);
      expect(combinedMock).toHaveBeenCalledWith(PAYLOAD, PAYLOAD_ARGS);
      expect(fsMock).not.toHaveBeenCalled();
      expect(netMock).not.toHaveBeenCalled();
      expect(wrap.command).toBe("/usr/bin/sandbox-exec");
      expect(wrap.args).toEqual([
        "-p",
        SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE,
        PAYLOAD,
        ...PAYLOAD_ARGS,
      ]);
      expect(wrap.networkMechanism).toBe("sandbox-exec");
      expect(wrap.fsMechanism).toBe("sandbox-exec");
    }));

  it("refuses on win32 with FS_ISOLATION_UNAVAILABLE, never consulting the network resolver", () =>
    withPlatform("win32", async () => {
      fsMock.mockRejectedValueOnce(
        VaultError.fsIsolationUnavailable("unsupported platform: win32"),
      );

      await expect(
        requireIsolation(PAYLOAD, PAYLOAD_ARGS, { network: true, fs: true }),
      ).rejects.toMatchObject({ code: ErrorCode.FS_ISOLATION_UNAVAILABLE });
      expect(netMock).not.toHaveBeenCalled();
      expect(combinedMock).not.toHaveBeenCalled();
    }));
});

describe("requireIsolation — no dimension demanded", () => {
  it("throws a programmer error (not a VaultError) and consults no resolver", async () => {
    const err = await requireIsolation(PAYLOAD, PAYLOAD_ARGS, {
      network: false,
      fs: false,
    }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(VaultError);
    expect((err as Error).message).toBe("requireIsolation called with no dimension demanded");
    expect(netMock).not.toHaveBeenCalled();
    expect(fsMock).not.toHaveBeenCalled();
    expect(combinedMock).not.toHaveBeenCalled();
  });
});
