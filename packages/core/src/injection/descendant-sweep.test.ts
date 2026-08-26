import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { describe, expect, it, vi } from "vitest";
import { sweepDescendants, win32SweepDeps } from "./descendant-sweep.js";
import type { DescendantProcess, DescendantSweepDeps } from "./descendant-sweep.js";

const SPAWNED_AT = 900_000;
const EXITED_AT = 1_000_000;
const WINDOW = { spawnedAtMs: SPAWNED_AT, exitedAtMs: EXITED_AT };

function deps(
  processes: DescendantProcess[],
  overrides: Partial<DescendantSweepDeps> = {},
): DescendantSweepDeps & { killPid: ReturnType<typeof vi.fn> } {
  return {
    listDescendants: vi.fn().mockResolvedValue(processes),
    killPid: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  } as DescendantSweepDeps & { killPid: ReturnType<typeof vi.fn> };
}

describe("sweepDescendants", () => {
  it("kills every descendant created inside the child's lifetime", async () => {
    const d = deps([
      { pid: 11, createdAtMs: SPAWNED_AT },
      { pid: 12, createdAtMs: EXITED_AT - 500 },
      { pid: 13, createdAtMs: EXITED_AT },
    ]);
    await expect(sweepDescendants(7, WINDOW, d)).resolves.toEqual({
      killed: 3,
      failed: false,
    });
    expect(d.killPid.mock.calls.map((c) => c[0])).toEqual([11, 12, 13]);
  });

  // pid reuse: a process that inherited the dead child's pid can only have
  // children NEWER than the exit — those are somebody else's, not survivors.
  it("skips a descendant created after the child exited", async () => {
    const d = deps([{ pid: 13, createdAtMs: EXITED_AT + 1 }]);
    await expect(sweepDescendants(7, WINDOW, d)).resolves.toEqual({
      killed: 0,
      failed: false,
    });
    expect(d.killPid).not.toHaveBeenCalled();
  });

  // pid reuse, the other side: an orphan of an EARLIER holder of the child's
  // pid still names it as parent and is older than the child — an unrelated
  // operator process, never a survivor of this spawn.
  it("skips a descendant created before the child was spawned", async () => {
    const d = deps([{ pid: 14, createdAtMs: SPAWNED_AT - 1 }]);
    await expect(sweepDescendants(7, WINDOW, d)).resolves.toEqual({
      killed: 0,
      failed: false,
    });
    expect(d.killPid).not.toHaveBeenCalled();
  });

  it("asks for the child's own pid", async () => {
    const d = deps([]);
    await sweepDescendants(4242, WINDOW, d);
    expect(d.listDescendants).toHaveBeenCalledWith(4242);
  });

  it("reports a listing failure as failed and kills nothing", async () => {
    const d = deps([], {
      listDescendants: vi.fn().mockRejectedValue(new Error("cim")),
    });
    await expect(sweepDescendants(7, WINDOW, d)).resolves.toEqual({
      killed: 0,
      failed: true,
    });
    expect(d.killPid).not.toHaveBeenCalled();
  });

  it("a kill that fails does not stop the remaining kills", async () => {
    const killPid = vi.fn().mockRejectedValueOnce(new Error("gone")).mockResolvedValue(undefined);
    const d = deps(
      [
        { pid: 11, createdAtMs: EXITED_AT - 10 },
        { pid: 12, createdAtMs: EXITED_AT - 10 },
      ],
      { killPid },
    );
    await expect(sweepDescendants(7, WINDOW, d)).resolves.toEqual({
      killed: 1,
      failed: true,
    });
    expect(killPid).toHaveBeenCalledTimes(2);
  });

  it("settles as failed when the listing outlives the bound and kills nothing after it", async () => {
    let release: (found: DescendantProcess[]) => void = () => {};
    const d = deps([], {
      listDescendants: vi.fn(
        () =>
          new Promise<DescendantProcess[]>((resolve) => {
            release = resolve;
          }),
      ),
    });
    const started = Date.now();
    await expect(sweepDescendants(7, WINDOW, d, 100)).resolves.toEqual({
      killed: 0,
      failed: true,
    });
    expect(Date.now() - started).toBeLessThan(2_000);

    release([{ pid: 11, createdAtMs: EXITED_AT - 10 }]);
    await new Promise((r) => setTimeout(r, 50));
    expect(d.killPid).not.toHaveBeenCalled();
  });

  it("stops the kill loop once the bound expires", async () => {
    const killPid = vi.fn(() => new Promise<void>((resolve) => setTimeout(resolve, 300)));
    const d = deps(
      [
        { pid: 11, createdAtMs: EXITED_AT - 10 },
        { pid: 12, createdAtMs: EXITED_AT - 10 },
      ],
      { killPid },
    );
    await expect(sweepDescendants(7, WINDOW, d, 100)).resolves.toEqual({
      killed: 0,
      failed: true,
    });
    await new Promise((r) => setTimeout(r, 500));
    expect(killPid).toHaveBeenCalledTimes(1);
  });

  it.each([0, -1, 1.5, Number.NaN])(
    "refuses a non-positive-integer pid %p without listing",
    async (pid) => {
      const d = deps([]);
      await expect(sweepDescendants(pid, WINDOW, d)).resolves.toEqual({
        killed: 0,
        failed: true,
      });
      expect(d.listDescendants).not.toHaveBeenCalled();
    },
  );
});

const exitOf = (child: ChildProcess): Promise<void> =>
  new Promise((resolve) => child.once("exit", () => resolve()));

describe.runIf(process.platform === "win32")("win32SweepDeps — live helpers", () => {
  it("killPid tolerates a process that is already gone (taskkill exit 128)", async () => {
    const child = spawn(process.execPath, ["-e", "process.exit(0)"], {
      stdio: "ignore",
      windowsHide: true,
    });
    await exitOf(child);

    await expect(win32SweepDeps().killPid(child.pid as number)).resolves.toBeUndefined();
  }, 30_000);

  it("killPid terminates a live process (taskkill exit 0)", async () => {
    const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], {
      stdio: "ignore",
      windowsHide: true,
    });
    await new Promise<void>((resolve) => child.once("spawn", resolve));
    const exited = exitOf(child);

    await expect(win32SweepDeps().killPid(child.pid as number)).resolves.toBeUndefined();
    await exited;
  }, 30_000);
});

describe.runIf(process.platform === "win32")("sweepDescendants — live win32 orphan", () => {
  // Survival is pinned by a second listing, not by a marker file: a cold
  // PowerShell host plus taskkill can take seconds under load, and a marker
  // written on the grandchild's own clock would race that. The grandchild's
  // 12 s lifetime only keeps it findable long enough and self-terminates it
  // if the sweep never reaches it.
  it("kills a grandchild orphaned by a plain (non-tree) kill of its parent", async () => {
    const grandchild = "setTimeout(() => {}, 12000)";
    // `detached` keeps the grandchild out of the parent's libuv job object,
    // which would otherwise kill it with the parent — the survivor the sweep
    // targets is one no job ever claimed.
    const parentScript = `
      const { spawn } = require("node:child_process");
      const gc = spawn(process.execPath, ["-e", ${JSON.stringify(grandchild)}], { stdio: "ignore", windowsHide: true, detached: true });
      gc.unref();
      console.log("child-done");
      setTimeout(() => {}, 60000);
    `;
    const spawnedAt = Date.now();
    const parent = spawn(process.execPath, ["-e", parentScript], {
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
    });
    await new Promise<void>((resolve) => {
      parent.stdout.on("data", (chunk: Buffer) => {
        if (chunk.toString().includes("child-done")) resolve();
      });
    });
    const pid = parent.pid as number;
    const exited = exitOf(parent);
    parent.kill();
    await exited;
    const exitedAt = Date.now();

    const live = win32SweepDeps();
    const before = await live.listDescendants(pid);
    expect(before.length).toBeGreaterThanOrEqual(1);

    const result = await sweepDescendants(
      pid,
      { spawnedAtMs: spawnedAt, exitedAtMs: exitedAt },
      live,
    );

    expect(result.killed).toBeGreaterThanOrEqual(1);
    await new Promise((r) => setTimeout(r, 1_000));
    await expect(live.listDescendants(pid)).resolves.toEqual([]);
  }, 30_000);
});
