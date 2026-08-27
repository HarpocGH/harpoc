import { existsSync, mkdtempSync, rmSync } from "node:fs";
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

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/**
 * Child that spawns a grandchild inheriting its stdio, then behaves as told.
 * `escape` detaches and unrefs the grandchild so the child can exit while the
 * grandchild still holds the inherited pipes — the shape that stalled `'close'`.
 */
function grandchildScript(opts: {
  holdMs: number;
  markerPath?: string;
  parentWaits: boolean;
  escape?: boolean;
}): string {
  const inner = opts.markerPath
    ? `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(
        opts.markerPath,
      )}, 'survived'), ${opts.holdMs})`
    : `setTimeout(() => {}, ${opts.holdMs})`;
  return `
    const { spawn } = require("node:child_process");
    const gc = spawn(process.execPath, ["-e", ${JSON.stringify(inner)}], {
      stdio: "inherit",
      windowsHide: true,
      detached: ${opts.escape ? "true" : "false"},
    });
    ${opts.escape ? "gc.unref();" : ""}
    console.log("child-done");
    ${opts.parentWaits ? "setTimeout(() => {}, 60000);" : ""}
  `;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

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

  // Discriminating on both platforms only if the grandchild already exists when
  // the timeout fires: `killTree` on win32 is one `taskkill /T` whose descendant
  // snapshot is taken once, so a grandchild created after that snapshot escapes
  // it (observed under the parallel root gate with a 300 ms timeout, where node
  // start-up outran the kill). Hence the wide timeout below — that
  // spawn-during-kill window is the descendant sweep's to close (pinned in
  // descendant-sweep.test.ts and spawn-captured.sweep.test.ts), not what this
  // case pins.
  it("the timeout kills the whole process tree, not just the direct child", async () => {
    const marker = join(dir, "grandchild-marker.txt");
    const result = await spawnCaptured(
      process.execPath,
      ["-e", grandchildScript({ holdMs: 6_000, markerPath: marker, parentWaits: true })],
      { env: {}, timeoutMs: 2_000 },
    );

    expect(result.timed_out).toBe(true);

    // Well past the grandchild's own deadline: if it had survived the kill it
    // would have written the marker with the credential still in its env. The
    // kill fires at t+2 s; the grandchild's 6 s timer starts at its own boot,
    // allowed the same 2 s the child had, so the marker would land by t+10 s
    // at the latest. On win32 the spawn itself settles only after the taskkill
    // wait and the descendant sweep — up to 27 s past the timeout, the bound
    // spawnCaptured documents — so this 9 s wait starts after that, and the
    // budget below covers 2 + 27 + 9 with a margin for a cold PowerShell host.
    await sleep(9_000);
    expect(existsSync(marker)).toBe(false);
  }, 40_000);

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
  }, 15_000);

  it("control: a failed spawn still settles as spawn_failed", async () => {
    const result = await spawnCaptured(join(dir, "does-not-exist"), [], {
      env: {},
      timeoutMs: 5_000,
    });

    expect(result.spawn_failed).toBe(true);
    expect(result.exit_code).toBeNull();
  }, 15_000);
});
