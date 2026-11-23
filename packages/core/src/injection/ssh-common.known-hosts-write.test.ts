import { existsSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { writeKnownHosts } from "./ssh-common.js";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, writeFileSync: vi.fn(actual.writeFileSync) };
});

const actualFs = await vi.importActual<typeof import("node:fs")>("node:fs");
const writeMock = vi.mocked(writeFileSync);

const PIN = "deploy.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIApin";

afterEach(() => {
  writeMock.mockReset();
  writeMock.mockImplementation(actualFs.writeFileSync);
});

describe("writeKnownHosts — the two writes", () => {
  it("the global file is created exclusively, 0600, beside the pinned file", () => {
    const kh = writeKnownHosts([PIN]);
    try {
      expect(writeMock.mock.calls).toEqual([
        [kh.file, `${PIN}\n`, { mode: 0o600 }],
        [kh.globalFile, "", { mode: 0o600, flag: "wx" }],
      ]);
      expect(dirname(kh.globalFile)).toBe(dirname(kh.file));
    } finally {
      kh.dispose();
    }
  });

  it("a second write that fails is rethrown as it is, and the directory with the pinned file is gone", () => {
    const failure = Object.assign(new Error("EIO: the second write"), { code: "EIO" });
    writeMock.mockImplementation((file, data, options) => {
      if (basename(String(file)) === "global_known_hosts") throw failure;
      actualFs.writeFileSync(file, data, options);
    });

    let thrown: unknown;
    try {
      writeKnownHosts([PIN]);
    } catch (err) {
      thrown = err;
    }

    expect(writeMock.mock.calls).toHaveLength(2);
    const [pinned, global] = writeMock.mock.calls as [
      Parameters<typeof writeFileSync>,
      Parameters<typeof writeFileSync>,
    ];
    const dir = dirname(String(pinned[0]));
    try {
      expect(Object.is(thrown, failure)).toBe(true);
      expect(basename(String(pinned[0]))).toBe("known_hosts");
      expect(dirname(String(global[0]))).toBe(dir);
      expect(global.slice(1)).toEqual(["", { mode: 0o600, flag: "wx" }]);
      expect(existsSync(dir)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
});
