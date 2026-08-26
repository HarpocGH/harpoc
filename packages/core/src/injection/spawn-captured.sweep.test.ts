import { spawn } from "node:child_process";
import type { SpawnOptions } from "node:child_process";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { sweepDescendants } from "./descendant-sweep.js";
import { spawnCaptured } from "./spawn-captured.js";

vi.mock("./descendant-sweep.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./descendant-sweep.js")>();
  return { ...actual, sweepDescendants: vi.fn(actual.sweepDescendants) };
});

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});

const { spawn: realSpawn } =
  await vi.importActual<typeof import("node:child_process")>("node:child_process");

const sweepMock = vi.mocked(sweepDescendants);
const spawnMock = vi.mocked(spawn);
const NODE = process.execPath;
const HANG = "setTimeout(() => {}, 30000);";

/**
 * Runs taskkill's real argv only after a 3 s sleep — the shape of a loaded host
 * where the tree kill lands the child's exit past the 2 s settle backstop.
 */
const DELAYED_TASKKILL =
  "const [exe, ...args] = process.argv.slice(1);" +
  "setTimeout(() => require('node:child_process').spawnSync(exe, args, { stdio: 'ignore', windowsHide: true }), 3000);";

beforeEach(() => {
  // mockReset() leaves an undefined-returning mock, and the production code
  // chains `.catch` on the call — give every test a resolving default.
  sweepMock.mockReset();
  sweepMock.mockResolvedValue({ killed: 0, failed: false });
  spawnMock.mockImplementation(realSpawn);
});

describe("spawnCaptured → descendant sweep wiring", () => {
  it.runIf(process.platform === "win32")(
    "a timed-out child is swept once, by its pid and spawn/exit window, and settlement waits for the sweep",
    async () => {
      let sweepDone = false;
      sweepMock.mockImplementation(async () => {
        await new Promise((r) => setTimeout(r, 300));
        sweepDone = true;
        return { killed: 0, failed: false };
      });

      const before = Date.now();
      const result = await spawnCaptured(NODE, ["-e", HANG], {
        env: {},
        timeoutMs: 300,
      });

      expect(result.timed_out).toBe(true);
      expect(sweepMock).toHaveBeenCalledTimes(1);
      const [pid, window] = sweepMock.mock.calls[0] as [
        number,
        { spawnedAtMs: number; exitedAtMs: number },
      ];
      expect(Number.isInteger(pid) && pid > 0).toBe(true);
      expect(window.spawnedAtMs).toBeGreaterThanOrEqual(before);
      expect(window.spawnedAtMs).toBeLessThanOrEqual(window.exitedAtMs);
      expect(window.exitedAtMs).toBeLessThanOrEqual(Date.now());
      expect(sweepDone).toBe(true);
    },
    15_000,
  );

  // RED before killTree resolved on the taskkill helper's close: the settle
  // backstop was armed at dispatch, so a kill that landed the child's exit
  // past 2 s settled the spawn first and the exit handler found it settled —
  // no sweep, under exactly the load that opens the snapshot gap.
  it.runIf(process.platform === "win32")(
    "a tree kill that lands after the settle backstop still sweeps exactly once",
    async () => {
      spawnMock.mockImplementation(
        (command: string, args: readonly string[], options: SpawnOptions) =>
          command.toLowerCase().endsWith("taskkill.exe")
            ? realSpawn(NODE, ["-e", DELAYED_TASKKILL, command, ...args], options)
            : realSpawn(command, args, options),
      );

      const result = await spawnCaptured(NODE, ["-e", HANG], {
        env: {},
        timeoutMs: 300,
      });

      expect(result.timed_out).toBe(true);
      expect(sweepMock).toHaveBeenCalledTimes(1);
    },
    20_000,
  );

  it.runIf(process.platform === "win32")(
    "a sweep that rejects still lets the spawn settle with its capture",
    async () => {
      sweepMock.mockRejectedValue(new Error("cim exploded"));
      const result = await spawnCaptured(NODE, ["-e", `process.stdout.write('before'); ${HANG}`], {
        env: {},
        timeoutMs: 300,
      });
      expect(result.timed_out).toBe(true);
      expect(result.stdout).toContain("before");
    },
    15_000,
  );

  it("a child that exits on its own is never swept", async () => {
    const result = await spawnCaptured(NODE, ["-e", "process.exit(0)"], {
      env: {},
      timeoutMs: 5_000,
    });
    expect(result.exit_code).toBe(0);
    expect(sweepMock).not.toHaveBeenCalled();
  }, 15_000);

  it.skipIf(process.platform === "win32")(
    "POSIX never sweeps — the group signal did the job",
    async () => {
      const result = await spawnCaptured(NODE, ["-e", HANG], {
        env: {},
        timeoutMs: 300,
      });
      expect(result.timed_out).toBe(true);
      expect(sweepMock).not.toHaveBeenCalled();
    },
    15_000,
  );
});
