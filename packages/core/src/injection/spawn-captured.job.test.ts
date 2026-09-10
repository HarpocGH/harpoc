import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sweepDescendants } from "./descendant-sweep.js";
import { spawnCaptured } from "./spawn-captured.js";
import {
  JOB_WRAPPER_KEEP_FLAG,
  forceJobWrapperUnavailableForTests,
  resetJobWrapperProbeForTests,
  wrapInJob,
} from "./win32-job-wrapper.js";

vi.mock("./win32-job-wrapper.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./win32-job-wrapper.js")>();
  return { ...actual, wrapInJob: vi.fn(actual.wrapInJob) };
});
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
const actualWrap =
  await vi.importActual<typeof import("./win32-job-wrapper.js")>("./win32-job-wrapper.js");
const wrapMock = vi.mocked(wrapInJob);
const sweepMock = vi.mocked(sweepDescendants);
const spawnMock = vi.mocked(spawn);
const NODE = process.execPath;
const ENV = process.env as Record<string, string>;

/**
 * A node-scripted stand-in for the wrapper on every platform: like harpoc-job it
 * hands its pipes to the payload and returns the payload's exit status. Its
 * argv shape is the product's — `--keep <payload> <args>` — so the seam's
 * composition is pinned, not the wrapper's kernel work (the live cases below).
 */
const MONITOR = `
const [flag, command, ...args] = process.argv.slice(1);
if (flag !== "--keep") { process.stderr.write("harpoc-job: usage"); process.exit(9008); }
const child = require("node:child_process").spawn(command, args, { stdio: "inherit" });
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
`;

/**
 * `node -e <script>` refuses a following `--keep` as a node option, so the
 * stand-in's argv carries the `--` node itself strips: the payload's own argv
 * still starts at the keep flag, one index further along than the product's.
 */
const MONITOR_PREFIX = ["-e", MONITOR, "--"];

function monitorWrap(): void {
  wrapMock.mockImplementation((command, args) =>
    Promise.resolve({
      command: NODE,
      args: [...MONITOR_PREFIX, JOB_WRAPPER_KEEP_FLAG, command, ...args],
      mechanism: "job" as const,
    }),
  );
}

beforeEach(() => {
  wrapMock.mockReset();
  sweepMock.mockReset();
  sweepMock.mockResolvedValue({ killed: 0, failed: false });
  spawnMock.mockClear();
  spawnMock.mockImplementation(realSpawn);
  resetJobWrapperProbeForTests();
  forceJobWrapperUnavailableForTests(null);
});

afterEach(() => {
  forceJobWrapperUnavailableForTests(null);
});

describe("spawnCaptured — the job wrapper seam (D4)", () => {
  it("consults the wrapper once with the resolved command and args, and spawns the WRAPPER", async () => {
    monitorWrap();
    const r = await spawnCaptured(NODE, ["-e", "process.stdout.write('hi'); process.exit(3)"], {
      env: ENV,
      timeoutMs: 10_000,
    });
    expect(wrapMock).toHaveBeenCalledTimes(1);
    expect(wrapMock.mock.calls[0]?.[0]).toBe(NODE);
    expect(wrapMock.mock.calls[0]?.[1]).toEqual([
      "-e",
      "process.stdout.write('hi'); process.exit(3)",
    ]);
    const spawnCall = spawnMock.mock.calls[0];
    if (spawnCall === undefined) throw new Error("expected a spawn call");
    const command = spawnCall[0];
    const args = spawnCall[1] as string[];
    expect(command).toBe(NODE);
    expect(args.slice(0, MONITOR_PREFIX.length)).toEqual(MONITOR_PREFIX);
    expect(args[MONITOR_PREFIX.length]).toBe(JOB_WRAPPER_KEEP_FLAG);
    expect(r).toMatchObject({ exit_code: 3, stdout: "hi", tree_kill: "job", spawn_failed: false });
  });

  it("a timeout on the job path kills the wrapper directly — no taskkill helper, no sweep", async () => {
    monitorWrap();
    const r = await spawnCaptured(NODE, ["-e", "setTimeout(() => {}, 30000)"], {
      env: ENV,
      timeoutMs: 500,
    });
    expect(r.timed_out).toBe(true);
    expect(r.tree_kill).toBe("job");
    expect("descendant_sweep" in r).toBe(false);
    expect(sweepMock).not.toHaveBeenCalled();
    expect(
      spawnMock.mock.calls.some(([c]) => String(c).toLowerCase().endsWith("taskkill.exe")),
    ).toBe(false);
  });

  // The wrapper's reserved codes exist only where the wrapper does: a POSIX exit
  // status is eight bits, so a stand-in's `process.exit(9009)` arrives as 49 there
  // and the pair (code AND marker) cannot be produced off win32 — where the job
  // tier is never set in production either.
  it.runIf(process.platform === "win32")(
    "the wrapper's own failure reads as spawn_failed with a null exit code",
    async () => {
      wrapMock.mockImplementation(() =>
        Promise.resolve({
          command: NODE,
          args: [
            "-e",
            "process.stderr.write('harpoc-job: CreateProcess failed: 3'); process.exit(9009)",
          ],
          mechanism: "job" as const,
        }),
      );
      const r = await spawnCaptured("C:\\no-such\\payload.exe", ["x"], {
        env: ENV,
        timeoutMs: 10_000,
      });
      expect(r).toMatchObject({
        spawn_failed: true,
        exit_code: null,
        tree_kill: "job",
        timed_out: false,
      });
    },
  );

  it.runIf(process.platform === "win32")(
    "a payload exiting 9009 without the marker is an ordinary exit",
    async () => {
      monitorWrap();
      const r = await spawnCaptured(
        NODE,
        ["-e", "process.stderr.write('mine'); process.exit(9009)"],
        {
          env: ENV,
          timeoutMs: 10_000,
        },
      );
      expect(r).toMatchObject({ spawn_failed: false, exit_code: 9009, stderr: "mine" });
    },
  );

  it("without a wrap: tree_kill is taskkill on win32 and absent elsewhere, and the sweep path is untouched", async () => {
    wrapMock.mockResolvedValue(null);
    const r = await spawnCaptured(NODE, ["-e", "process.exit(0)"], {
      env: ENV,
      timeoutMs: 10_000,
    });
    if (process.platform === "win32") expect(r.tree_kill).toBe("taskkill");
    else expect("tree_kill" in r).toBe(false);
  });

  it("the spawn-failed result carries tree_kill too", async () => {
    wrapMock.mockResolvedValue(null);
    const r = await spawnCaptured("C:\\harpoc-no-such\\app.exe", [], {
      env: ENV,
      timeoutMs: 1_000,
    });
    expect(r.spawn_failed).toBe(true);
    if (process.platform === "win32") expect(r.tree_kill).toBe("taskkill");
  });
});

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
/**
 * A node child that spawns a **detached** node grandchild, writes the
 * grandchild's pid to a file the moment it exists, then holds (`exitAfter`
 * false) or exits 0. libuv puts only its non-detached children into the job it
 * closes at exit, so the grandchild is OUTSIDE the child's libuv job — nothing
 * but the wrapper can reach it — and INSIDE the wrapper's, whose job permits no
 * breakaway (every descendant of a member is a member). That is the orphan
 * class the two live cases pin. Node, not PowerShell: two PowerShell start-ups
 * do not fit inside the timeout case's budget on the windows-2025 runners.
 */
function nodeTree(pidFile: string, exitAfter: boolean): string[] {
  return [
    "-e",
    `const g = require("node:child_process").spawn(process.execPath, ["-e", "setTimeout(() => {}, 120000)"], { detached: true, stdio: "ignore", windowsHide: true });
     g.unref();
     require("node:fs").writeFileSync(${JSON.stringify(pidFile)}, String(g.pid));
     ${exitAfter ? "process.exit(0);" : "setTimeout(() => {}, 120000);"}`,
  ];
}

describe.runIf(process.platform === "win32")("spawnCaptured — the real wrapper on win32", () => {
  let dir: string;
  /**
   * The grandchild's pid, only ever a real one: a kill landing between the
   * child's `writeFileSync` truncate and its write leaves a 0-byte file, whose
   * `Number("")` is 0 — and `process.kill(0, "SIGKILL")` below would take the
   * vitest worker itself. Guarded at both recording sites, as in
   * `spawn-captured.lifecycle.test.ts`.
   */
  let survivor: number | undefined;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harpoc-spawn-job-"));
    wrapMock.mockImplementation(actualWrap.wrapInJob);
  });
  afterEach(() => {
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

  it("the timeout kill through the wrapper takes a grandchild that no libuv job would have", async () => {
    const pidFile = join(dir, "g.pid");
    const r = await spawnCaptured(NODE, nodeTree(pidFile, false), { env: ENV, timeoutMs: 5_000 });
    const pid = Number(readFileSync(pidFile, "utf8").trim());
    survivor = Number.isInteger(pid) && pid > 0 ? pid : undefined;
    expect(r).toMatchObject({ timed_out: true, tree_kill: "job" });
    expect("descendant_sweep" in r).toBe(false);
    await expect(untilGone(pid)).resolves.toBe(true);
    survivor = undefined;
  }, 60_000);

  it("keep: a grandchild outliving a normal exit is left alone, as today", async () => {
    const pidFile = join(dir, "g.pid");
    const r = await spawnCaptured(NODE, nodeTree(pidFile, true), { env: ENV, timeoutMs: 30_000 });
    const pid = Number(readFileSync(pidFile, "utf8").trim());
    survivor = Number.isInteger(pid) && pid > 0 ? pid : undefined;
    expect(r).toMatchObject({ exit_code: 0, timed_out: false, tree_kill: "job" });
    await sleep(500);
    expect(isAlive(pid)).toBe(true);
    // Flip: JOB_WRAPPER_KEEP_FLAG → JOB_WRAPPER_STRICT_FLAG in wrapInJob makes this grandchild die with the wrapper.
  }, 60_000);

  it("argv reaches the payload byte-identical through the wrapper", async () => {
    const tricky = [
      "a b",
      'c"d',
      "e\\f",
      'g\\"h',
      "",
      "i\\\\",
      '"',
      " j ",
      "k=l m",
      "tab\there",
      '\\\\"\\',
      "end\\",
      "trail\\\\ ",
    ];
    const r = await spawnCaptured(
      NODE,
      ["-e", "console.log(JSON.stringify(process.argv.slice(1)))", "--", ...tricky],
      { env: ENV, timeoutMs: 20_000 },
    );
    expect(r.exit_code).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual(tricky);
  }, 60_000);
});
