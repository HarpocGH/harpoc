import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnCaptured } from "./spawn-captured.js";

/**
 * M4. The timeout killed only the immediate child (no process group, no job
 * object) and the promise settled only from `'close'` — which Node emits once
 * every stdio stream is closed. A grandchild that inherited stdout/stderr keeps
 * them open, so the promise stayed pending with no second timer: the caller's
 * `finally` never ran (plaintext left unwiped, ephemeral ssh-agent socket and
 * identity temp files never disposed) and the request never returned.
 */

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-spawn-lifecycle-"));
});

/** The grandchild's pid when the tree-kill case has read it and not yet seen it gone. */
let survivor: number | undefined;

afterEach(() => {
  // A survivor is the failure the tree-kill case reports; never let it outlive the test.
  if (survivor !== undefined) {
    try {
      process.kill(survivor, "SIGKILL");
    } catch {
      // Already gone.
    }
    survivor = undefined;
  }
  rmSync(dir, { recursive: true, force: true });
});

/**
 * Child that spawns a grandchild inheriting its stdio, then behaves as told.
 * `escape` detaches and unrefs the grandchild so the child can exit while the
 * grandchild still holds the inherited pipes — the shape that stalled `'close'`.
 * `pidPath` makes the child write the grandchild's pid the moment it exists,
 * before any kill can land.
 */
function grandchildScript(opts: {
  holdMs: number;
  pidPath?: string;
  parentWaits: boolean;
  escape?: boolean;
}): string {
  const inner = `setTimeout(() => {}, ${String(opts.holdMs)})`;
  return `
    const { spawn } = require("node:child_process");
    const gc = spawn(process.execPath, ["-e", ${JSON.stringify(inner)}], {
      stdio: "inherit",
      windowsHide: true,
      detached: ${opts.escape ? "true" : "false"},
    });
    ${opts.escape ? "gc.unref();" : ""}
    ${opts.pidPath ? `require("node:fs").writeFileSync(${JSON.stringify(opts.pidPath)}, String(gc.pid));` : ""}
    console.log("child-done");
    ${opts.parentWaits ? "setTimeout(() => {}, 60000);" : ""}
  `;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Far beyond every settlement bound (a 5 s timeout plus up to 42 s of win32
 * taskkill wait and sweep): a grandchild alive after settlement escaped the
 * kill, one that is gone was killed — it cannot have exited on its own.
 */
const GRANDCHILD_HOLD_MS = 120_000;
const GONE_POLL_MS = 250;
const GONE_DEADLINE_MS = 10_000;

const isAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM: exists but not ours (never for a grandchild this test spawned); ESRCH: gone.
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
};

/** Polls liveness after settlement; true once the pid is gone, false at the deadline. */
async function untilGone(pid: number): Promise<boolean> {
  const deadline = Date.now() + GONE_DEADLINE_MS;
  while (isAlive(pid)) {
    if (Date.now() >= deadline) return false;
    await sleep(GONE_POLL_MS);
  }
  return true;
}

describe("spawnCaptured lifecycle (M4)", () => {
  it("pins the vulnerability: a surviving grandchild cannot hold the promise open", async () => {
    const started = Date.now();
    const result = await spawnCaptured(
      process.execPath,
      ["-e", grandchildScript({ holdMs: 8_000, parentWaits: false, escape: true })],
      { env: {}, timeoutMs: 20_000 },
    );
    const elapsed = Date.now() - started;

    // The child exits immediately; only the grandchild's inherited pipe is
    // still open. Settlement must follow the child's exit, not the pipe.
    expect(result.exit_code).toBe(0);
    expect(result.stdout).toContain("child-done");
    expect(result.timed_out).toBe(false);
    expect(elapsed).toBeLessThan(4_000);
  }, 25_000);

  // Discriminating only if the grandchild exists when the timeout fires (on
  // win32 `taskkill /T`'s descendant snapshot is taken once — the
  // spawn-during-kill window is the descendant sweep's to close, pinned in
  // descendant-sweep.test.ts and spawn-captured.sweep.test.ts, not here); the
  // 5 s timeout leaves the child's boot and its spawn well inside. Survival is
  // pinned by liveness after settlement, not by a marker on the grandchild's
  // own clock, which raced taskkill's delivery under load (the forced gate's
  // sole miss at three tranches, 2026-08-30 → 09-01): the grandchild holds far
  // longer than any settlement bound, so one alive here escaped the kill
  // whatever the delivery latency, and one gone was killed. On win32 a
  // non-detached grandchild sits in the child's libuv job object, which ends
  // it with the child whether or not taskkill's /T reached it (probed
  // 2026-09-07); the /T-only shape is a detached grandchild, the sweep's case.
  // On POSIX the group signal is the whole mechanism.
  it("the timeout kills the whole process tree, not just the direct child", async () => {
    const pidFile = join(dir, "grandchild.pid");
    const result = await spawnCaptured(
      process.execPath,
      ["-e", grandchildScript({ holdMs: GRANDCHILD_HOLD_MS, pidPath: pidFile, parentWaits: true })],
      { env: {}, timeoutMs: 5_000 },
    );

    expect(result.timed_out).toBe(true);

    // Written by the child the moment it spawned the grandchild, well before
    // the 5 s kill: a missing file is a child that never got that far — a
    // different failure from a survivor.
    const pid = Number(readFileSync(pidFile, "utf8"));
    expect(Number.isInteger(pid) && pid > 0).toBe(true);
    survivor = pid;

    await expect(untilGone(pid)).resolves.toBe(true);
    survivor = undefined;
    // Budget: 5 s timeout + up to 42 s of win32 taskkill wait and sweep + a 10 s poll.
  }, 60_000);

  it("control: an ordinary command still returns its full output and exit code", async () => {
    const result = await spawnCaptured(
      process.execPath,
      ["-e", "process.stdout.write('out'); process.stderr.write('err'); process.exit(3);"],
      { env: {}, timeoutMs: 10_000 },
    );

    expect(result.exit_code).toBe(3);
    expect(result.stdout).toBe("out");
    expect(result.stderr).toBe("err");
    expect(result.timed_out).toBe(false);
    expect(result.spawn_failed).toBe(false);
  }, 15_000);

  it("control: a timed-out child with no grandchild still reports its capture", async () => {
    const result = await spawnCaptured(
      process.execPath,
      ["-e", "process.stdout.write('before'); setTimeout(() => {}, 30000);"],
      { env: {}, timeoutMs: 300 },
    );

    expect(result.timed_out).toBe(true);
    expect(result.stdout).toContain("before");
    expect(result.spawn_failed).toBe(false);
    // Times a child out, so on win32 its settlement waits for the descendant
    // sweep — up to the same timeout + 42 s bound as the tree-kill test above
    // (a 15 s budget lost to the 20 s helper bound on windows-latest, 18b58b9).
  }, 60_000);

  it("control: a failed spawn still settles as spawn_failed", async () => {
    const result = await spawnCaptured(join(dir, "does-not-exist"), [], {
      env: {},
      timeoutMs: 5_000,
    });

    expect(result.spawn_failed).toBe(true);
    expect(result.exit_code).toBeNull();
  }, 15_000);
});
