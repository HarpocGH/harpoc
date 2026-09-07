import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
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

  // RED while expiry resolves a hard-coded { killed: 0 }: the first kill lands
  // inside the bound, the second outlives it — the result must say so.
  it("reports the kills that landed before the bound expired", async () => {
    let calls = 0;
    let pending: NodeJS.Timeout | undefined;
    const killPid = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          calls += 1;
          if (calls === 1) resolve();
          else pending = setTimeout(resolve, 300);
        }),
    );
    const d = deps(
      [
        { pid: 11, createdAtMs: EXITED_AT - 10 },
        { pid: 12, createdAtMs: EXITED_AT - 10 },
      ],
      { killPid },
    );
    try {
      await expect(sweepDescendants(7, WINDOW, d, 100)).resolves.toEqual({
        killed: 1,
        failed: true,
      });
      expect(killPid).toHaveBeenCalledTimes(2);
    } finally {
      clearTimeout(pending);
    }
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

const POLL_INTERVAL_MS = 250;
const POLL_DEADLINE_MS = 10_000;
/**
 * At least one retry after a non-empty listing, whatever the clock says: on
 * the windows-latest runners one listing outlasts the whole deadline (warm
 * 19–33 s against 10 s — decisions.md § "The WMI listing series"), so without
 * this floor the poll was a single listing with no retry exactly where the
 * retry matters (2026-09-07).
 */
const POLL_MIN_LISTINGS = 2;

interface PollClock {
  now(): number;
  sleep(ms: number): Promise<void>;
}

const realClock: PollClock = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};

/**
 * Polls until the listing is empty, taking `POLL_MIN_LISTINGS` listings before
 * the deadline is consulted; resolves the last listing either way, so a
 * survivor stays visible in the failure.
 */
async function untilEmpty(
  list: () => Promise<DescendantProcess[]>,
  clock: PollClock = realClock,
): Promise<DescendantProcess[]> {
  const deadline = clock.now() + POLL_DEADLINE_MS;
  let last = await list();
  let listings = 1;
  while (last.length > 0 && (listings < POLL_MIN_LISTINGS || clock.now() < deadline)) {
    await clock.sleep(POLL_INTERVAL_MS);
    last = await list();
    listings += 1;
  }
  return last;
}

// Runs on every platform: the helper is the live cases' instrument, and its
// floor is what makes the "poll" a poll on a host whose listing is slow.
describe("untilEmpty — the live cases' poll", () => {
  it("retries once after a non-empty listing even when one listing outlasts the deadline", async () => {
    let t = 0;
    let calls = 0;
    const clock: PollClock = { now: () => t, sleep: () => Promise.resolve() };
    const list = vi.fn((): Promise<DescendantProcess[]> => {
      calls += 1;
      t += POLL_DEADLINE_MS * 3;
      return Promise.resolve(calls === 1 ? [{ pid: 11, createdAtMs: SPAWNED_AT }] : []);
    });
    await expect(untilEmpty(list, clock)).resolves.toEqual([]);
    expect(list).toHaveBeenCalledTimes(2);
  });

  it("stops at the deadline once the floor is met, resolving the survivor", async () => {
    let t = 0;
    const clock: PollClock = { now: () => t, sleep: () => Promise.resolve() };
    const survivor: DescendantProcess[] = [{ pid: 11, createdAtMs: SPAWNED_AT }];
    const list = vi.fn((): Promise<DescendantProcess[]> => {
      t += POLL_DEADLINE_MS * 3;
      return Promise.resolve(survivor);
    });
    await expect(untilEmpty(list, clock)).resolves.toEqual(survivor);
    expect(list).toHaveBeenCalledTimes(2);
  });
});

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

// The live test proves the sweep's logic against a real process tree; it does
// not certify the CI runner's WMI latency. windows-latest under the full gate
// answers `Get-CimInstance Win32_Process` in 19–33 s warm and 30–52 s cold,
// with the cold call at the 60 s bound on four of thirty-one legs between
// 2026-09-02 and 2026-09-07 (decisions.md § "The WMI listing series"; an idle
// host: ~250 ms; the same leg's DPAPI round-trips — a fresh powershell.exe
// each — 0.3–0.7 s, so the cost is the CIM/WMI listing, not PowerShell
// start-up). The product keeps its 20 s / 30 s bounds and fails open past
// them by design; here the helpers get 60 s and the sweep 90 s, so a slow
// provider stretches the test instead of failing it, and the one-time cold
// cost is paid by a warm-up whose duration — with the warm listing's — is
// printed to stderr for the CI log; a cold call at the bound is absorbed there.
const LIVE_HELPER_TIMEOUT_MS = 60_000;
const LIVE_SWEEP_TIMEOUT_MS = 90_000;
// Outlasts every bound the case waits on before its last listing — the
// pre-listing (60 s), the sweep (90 s) and a two-listing poll (120 s) — and
// equals the budget, so a grandchild that self-terminates can never pass as
// swept: the budget expires first.
const LIVE_LISTING_LIFETIME_MS = 300_000;

describe.runIf(process.platform === "win32")("sweepDescendants — live win32 orphan", () => {
  const live = win32SweepDeps({ helperTimeoutMs: LIVE_HELPER_TIMEOUT_MS });
  /** Every process the live case spawned: the parent, then the grandchild it printed. */
  const liveProcesses: number[] = [];

  afterEach(() => {
    // A red run leaves the detached grandchild (and, before the kill, the
    // parent) standing; end them here so nothing outlives the case. A green
    // run has proved both gone and empties the list itself, so no freed pid
    // is ever signalled.
    for (const pid of liveProcesses.splice(0)) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // Already gone.
      }
    }
  });

  beforeAll(
    async () => {
      const timings: string[] = [];
      for (const label of ["cold", "warm"]) {
        const started = Date.now();
        let outcome = "ok";
        try {
          await live.listDescendants(process.pid);
        } catch (err) {
          outcome = err instanceof Error ? err.message : String(err);
        }
        timings.push(`${label}=${String(Date.now() - started)}ms (${outcome})`);
      }
      console.error(`[descendant-sweep live] WMI listing warm-up: ${timings.join(", ")}`);
    },
    LIVE_HELPER_TIMEOUT_MS * 2 + 5_000,
  );

  // Survival is pinned by a second listing, not by a marker file: a cold
  // provider plus taskkill can take seconds under load, and a marker written
  // on the grandchild's own clock would race that. The grandchild's lifetime
  // equals the case's budget (LIVE_LISTING_LIFETIME_MS): it stays findable
  // past the pre-listing, the sweep's own listing and the poll, and a
  // grandchild that self-terminates can never pass as swept — the budget
  // expires first. A red run leaves it standing; the afterEach above ends it.
  it(
    "kills a grandchild orphaned by a plain (non-tree) kill of its parent",
    async () => {
      const grandchild = `setTimeout(() => {}, ${String(LIVE_LISTING_LIFETIME_MS)})`;
      // `detached` keeps the grandchild out of the parent's libuv job object,
      // which would otherwise kill it with the parent — the survivor the sweep
      // targets is one no job ever claimed.
      const parentScript = `
      const { spawn } = require("node:child_process");
      const gc = spawn(process.execPath, ["-e", ${JSON.stringify(grandchild)}], { stdio: "ignore", windowsHide: true, detached: true });
      gc.unref();
      console.log("child-done " + gc.pid);
      setTimeout(() => {}, 60000);
    `;
      const spawnedAt = Date.now();
      const parent = spawn(process.execPath, ["-e", parentScript], {
        stdio: ["ignore", "pipe", "ignore"],
        windowsHide: true,
      });
      const pid = parent.pid as number;
      liveProcesses.push(pid);
      const grandchildPid = await new Promise<number>((resolve) => {
        let buffered = "";
        parent.stdout.on("data", (chunk: Buffer) => {
          buffered += chunk.toString();
          const match = /child-done (\d+)/.exec(buffered);
          if (match) resolve(Number(match[1]));
        });
      });
      liveProcesses.push(grandchildPid);
      const exited = exitOf(parent);
      parent.kill();
      await exited;
      liveProcesses.splice(liveProcesses.indexOf(pid), 1);
      const exitedAt = Date.now();

      const before = await live.listDescendants(pid);
      expect(before.length).toBeGreaterThanOrEqual(1);

      const result = await sweepDescendants(
        pid,
        { spawnedAtMs: spawnedAt, exitedAtMs: exitedAt },
        live,
        LIVE_SWEEP_TIMEOUT_MS,
      );

      expect(result.killed).toBeGreaterThanOrEqual(1);
      // taskkill reports success once the kill is delivered, not once the
      // process is gone: under load the listing can still see the grandchild
      // for a moment, so wait for it to disappear rather than for a fixed
      // settle — at least one retry even where a listing outlasts the deadline.
      // The last listing is what fails, so a survivor stays visible.
      await expect(untilEmpty(() => live.listDescendants(pid))).resolves.toEqual([]);
      liveProcesses.length = 0;
      // Budget: pre-listing (≤ 60 s) + sweep (≤ 90 s) + poll (≤ 2 × 60 s) + spawn —
      // a bound; measured 2026-09-02 → 07 at ~100–130 s on the runners.
    },
    LIVE_LISTING_LIFETIME_MS,
  );
});
