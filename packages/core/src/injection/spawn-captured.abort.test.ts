import { ChildProcess } from "node:child_process";
import { getEventListeners } from "node:events";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { untilWritten } from "./__fixtures__/spawn-children.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { wrapInJob } from "./win32-job-wrapper.js";

vi.mock("./win32-job-wrapper.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./win32-job-wrapper.js")>();
  return { ...actual, wrapInJob: vi.fn(actual.wrapInJob) };
});

const actualWrap =
  await vi.importActual<typeof import("./win32-job-wrapper.js")>("./win32-job-wrapper.js");
const wrapMock = vi.mocked(wrapInJob);

const NODE = process.execPath;
const ENV: Record<string, string> = {
  PATH: process.env.PATH ?? process.env.Path ?? "",
  ...(process.platform === "win32" && process.env.SystemRoot
    ? { SystemRoot: process.env.SystemRoot }
    : {}),
};

/** Beyond a row's own timeout: a child or grandchild seen gone within it was ended by the abort, never by its own timer. */
const HOLD_MS = 60_000;
/** Beyond the rows' own budgets, so a run that ignores its signal reds by the row's timeout, never by its own. */
const RUN_TIMEOUT_MS = 120_000;
const MARKER_BOUND_MS = 10_000;

const isAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== "ESRCH";
  }
};
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
async function untilGone(pid: number, deadlineMs = 10_000): Promise<boolean> {
  const deadline = Date.now() + deadlineMs;
  while (isAlive(pid)) {
    if (Date.now() >= deadline) return false;
    await sleep(250);
  }
  return true;
}

function renameInto(pidPath: string, pids: string): string {
  return `const fs = require("node:fs"); fs.writeFileSync(${JSON.stringify(`${pidPath}.tmp`)}, ${pids}); fs.renameSync(${JSON.stringify(`${pidPath}.tmp`)}, ${JSON.stringify(pidPath)});`;
}

/** A child that writes its first byte, then its own pid in that write's callback, and sleeps. */
function sleepingChild(pidPath: string): string {
  return `process.stdout.write("before", () => { ${renameInto(pidPath, "String(process.pid)")} }); setTimeout(() => {}, ${String(HOLD_MS)});`;
}

/** `spawn-captured.lifecycle.test.ts`'s waiting child: a grandchild on its stdio, the child's and the grandchild's pids renamed into place whole. */
function grandchildScript(pidPath: string): string {
  const inner = `setTimeout(() => {}, ${String(HOLD_MS)})`;
  return `
    const { spawn } = require("node:child_process");
    const gc = spawn(process.execPath, ["-e", ${JSON.stringify(inner)}], {
      stdio: "inherit",
      windowsHide: true,
      detached: false,
    });
    ${renameInto(pidPath, "`${process.pid} ${gc.pid}`")}
    setTimeout(() => {}, ${String(HOLD_MS)});
  `;
}

/** A child whose only act is the marker file. */
function markingChild(marker: string): string {
  return `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "")`;
}

/** The pids a child wrote, each recorded before any assertion so a red never leaves one to nobody. */
function readPids(pidPath: string): number[] {
  const pids = readFileSync(pidPath, "utf8")
    .split(" ")
    .map(Number)
    .filter((pid) => Number.isInteger(pid) && pid > 0);
  survivors.push(...pids);
  return pids;
}

let dir: string;
/** The pids a row has read and not yet seen gone. */
let survivors: number[] = [];
let pending: Promise<SpawnCapturedResult> | undefined;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-spawn-abort-"));
  wrapMock.mockClear();
});

afterEach(async () => {
  const own = dir;
  for (const pid of survivors) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Already gone.
    }
  }
  survivors = [];
  await pending;
  pending = undefined;
  rmSync(own, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("spawnCaptured — an abort signal", () => {
  it("an abort ends a running child", async () => {
    const pidFile = join(dir, "child.pid");
    const controller = new AbortController();
    pending = spawnCaptured(NODE, ["-e", sleepingChild(pidFile)], {
      env: ENV,
      timeoutMs: RUN_TIMEOUT_MS,
      signal: controller.signal,
    });
    await untilWritten(pidFile, pending, MARKER_BOUND_MS);
    const [pid] = readPids(pidFile);
    expect(pid).toBeDefined();

    controller.abort();
    const r = await pending;

    expect(r).toMatchObject({ timed_out: true, exit_code: null, spawn_failed: false });
    expect(r.stdout).toBe("before");
    await expect(untilGone(pid as number)).resolves.toBe(true);
  });

  it("an abort ends a grandchild", async () => {
    const pidFile = join(dir, "grandchild.pid");
    const controller = new AbortController();
    pending = spawnCaptured(NODE, ["-e", grandchildScript(pidFile)], {
      env: ENV,
      timeoutMs: RUN_TIMEOUT_MS,
      signal: controller.signal,
    });
    await untilWritten(pidFile, pending, MARKER_BOUND_MS);
    const [, grandchild] = readPids(pidFile);
    expect(grandchild).toBeDefined();

    controller.abort();
    const r = await pending;

    expect(r.timed_out).toBe(true);
    await expect(untilGone(grandchild as number)).resolves.toBe(true);
  });

  it("under an aborted signal no child starts", async () => {
    const marker = join(dir, "started");
    const controller = new AbortController();
    controller.abort();

    const r = await spawnCaptured(NODE, ["-e", markingChild(marker)], {
      env: ENV,
      timeoutMs: 10_000,
      signal: controller.signal,
    });

    expect(r).toMatchObject({
      spawn_failed: true,
      timed_out: false,
      exit_code: null,
      signal: null,
      stdout: "",
      stderr: "",
    });
    expect(existsSync(marker)).toBe(false);
  });

  it("a signal aborted during prepareSpawn starts no child", async () => {
    const marker = join(dir, "started");
    const controller = new AbortController();
    wrapMock.mockImplementationOnce(async (command, args, mode) => {
      controller.abort();
      return actualWrap.wrapInJob(command, args, mode);
    });

    const r = await spawnCaptured(NODE, ["-e", markingChild(marker)], {
      env: ENV,
      timeoutMs: 10_000,
      signal: controller.signal,
    });

    expect(wrapMock).toHaveBeenCalledTimes(1);
    expect(r).toMatchObject({ spawn_failed: true, timed_out: false, exit_code: null });
    expect(existsSync(marker)).toBe(false);
  });

  it("a run that settled first ignores a later abort", async () => {
    const controller = new AbortController();
    const r = await spawnCaptured(NODE, ["-e", "process.exit(0)"], {
      env: ENV,
      timeoutMs: 10_000,
      signal: controller.signal,
    });
    expect(r).toMatchObject({ exit_code: 0, timed_out: false, spawn_failed: false });
    const groupKill = vi.spyOn(process, "kill");
    const childKill = vi.spyOn(ChildProcess.prototype, "kill");

    try {
      expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
      controller.abort();
      expect(groupKill).not.toHaveBeenCalled();
      expect(childKill).not.toHaveBeenCalled();
    } finally {
      groupKill.mockRestore();
      childKill.mockRestore();
    }
  });
});
