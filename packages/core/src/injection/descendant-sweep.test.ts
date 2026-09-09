import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { recordSeriesLine } from "@harpoc/test-utils";
import { sweepDescendants, win32SweepDeps } from "./descendant-sweep.js";
import type { DescendantProcess, DescendantSweepDeps } from "./descendant-sweep.js";
import { system32Path } from "../win32-paths.js";

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
// printed to stderr for the CI log and, on a runner, to the job summary with
// the 60 s trigger judged on the warm listing (D4, 2026-09-08); a cold call
// at the bound is absorbed there.
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
      let warmMs = 0;
      for (const label of ["cold", "warm"]) {
        const started = Date.now();
        let outcome = "ok";
        try {
          await live.listDescendants(process.pid);
        } catch (err) {
          outcome = err instanceof Error ? err.message : String(err);
        }
        const elapsed = Date.now() - started;
        if (label === "warm") warmMs = elapsed;
        timings.push(`${label}=${String(elapsed)}ms (${outcome})`);
      }
      // Judged on the warm listing alone: the 2026-08-29 rule discusses a
      // listing mechanism when a WARM listing exceeds 60 s, and a cold call at
      // the bound is absorbed here by design.
      recordSeriesLine(`[descendant-sweep live] WMI listing warm-up: ${timings.join(", ")}`, {
        judgedMs: warmMs,
      });
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
      const grandchildPid = await new Promise<number>((resolve, reject) => {
        let buffered = "";
        parent.stdout.on("data", (chunk: Buffer) => {
          buffered += chunk.toString();
          const match = /child-done (\d+)/.exec(buffered);
          if (match) resolve(Number(match[1]));
        });
        // A parent that dies before printing fails the case now, not at its
        // 300 s budget; its pid is on the teardown list already.
        parent.once("exit", (code, signal) => {
          reject(
            new Error(
              `parent exited before child-done (code ${String(code)}, signal ${String(signal)})`,
            ),
          );
        });
        parent.once("error", reject);
      });
      liveProcesses.push(grandchildPid);
      const exited = exitOf(parent);
      parent.kill();
      await exited;
      liveProcesses.shift();
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

// Diagnostics only (D1 / D2 of docs/implementation-plan-listing-probe-series-artifact-2026-09-09.md):
// the NtQuerySystemInformation listing — bound through Add-Type and through
// Reflection.Emit — timed beside the WMI listing and a bare host start-up on
// one live parent with a detached grandchild, on the windows-latest legs.
// Prints one stderr line, asserts nothing, and is removed by the tranche
// commit either way.
describe.runIf(process.platform === "win32")(
  "listing probe — diagnostics only (2026-09-09)",
  () => {
    const PROBE_HELPER_TIMEOUT_MS = 60_000;
    const PROBE_HOLD_MS = 600_000;
    const probePids: number[] = [];

    afterEach(() => {
      for (const pid of probePids.splice(0)) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // Already gone.
        }
      }
    });

    // The Add-Type candidate's syscall block: byte-identical to what
    // descendant-sweep.ts ships on GO (D3), minus the header line.
    const ADD_TYPE_BLOCK = [
      "Add-Type -TypeDefinition @'",
      "using System;",
      "using System.Runtime.InteropServices;",
      "public static class HarpocProcList {",
      '  [DllImport("ntdll.dll")]',
      "  static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int needed);",
      "  public static string Children(long parent) {",
      "    int len = 1 << 20; int needed; int st;",
      "    IntPtr buf = Marshal.AllocHGlobal(len);",
      "    try {",
      "      while ((st = NtQuerySystemInformation(5, buf, len, out needed)) == unchecked((int)0xC0000004)) {",
      "        Marshal.FreeHGlobal(buf); len = needed + (64 << 10); buf = Marshal.AllocHGlobal(len);",
      "      }",
      '      if (st != 0) throw new Exception("NtQuerySystemInformation failed: 0x" + st.ToString("x8"));',
      "      var sb = new System.Text.StringBuilder();",
      "      long off = 0;",
      "      while (true) {",
      "        IntPtr e = new IntPtr(buf.ToInt64() + off);",
      "        int next = Marshal.ReadInt32(e, 0);",
      "        long create = Marshal.ReadInt64(e, 32);",
      "        long pid = Marshal.ReadInt64(e, 80);",
      "        long ppid = Marshal.ReadInt64(e, 88);",
      "        if (ppid == parent && pid > 0) sb.Append(pid).Append(' ').Append((create - 116444736000000000L) / 10000L).Append('\\n');",
      "        if (next == 0) break;",
      "        off += next;",
      "      }",
      "      return sb.ToString();",
      "    } finally { Marshal.FreeHGlobal(buf); }",
      "  }",
      "}",
      "'@",
    ];

    function addTypeScript(pid: number): string {
      return [
        "$ErrorActionPreference = 'Stop'",
        "$sw = [System.Diagnostics.Stopwatch]::StartNew()",
        ...ADD_TYPE_BLOCK,
        "$compile = $sw.ElapsedMilliseconds; $sw.Restart()",
        `$rows = [HarpocProcList]::Children(${String(pid)})`,
        "$call = $sw.ElapsedMilliseconds",
        "'# compile={0} call={1} lang={2}' -f $compile, $call, $ExecutionContext.SessionState.LanguageMode",
        "$rows",
      ].join("\n");
    }

    // The Reflection.Emit candidate: the same syscall bound without csc.exe.
    function emitScript(pid: number): string {
      return [
        "$ErrorActionPreference = 'Stop'",
        "$sw = [System.Diagnostics.Stopwatch]::StartNew()",
        "$an = New-Object System.Reflection.AssemblyName 'HarpocNtQ'",
        "$ab = [System.AppDomain]::CurrentDomain.DefineDynamicAssembly($an, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)",
        "$mb = $ab.DefineDynamicModule('HarpocNtQ', $false)",
        "$tb = $mb.DefineType('HarpocNtQ.Native', 'Public, Class, Abstract, Sealed, BeforeFieldInit')",
        "$pm = $tb.DefinePInvokeMethod('NtQuerySystemInformation', 'ntdll.dll', 'Public, Static, PinvokeImpl', [System.Reflection.CallingConventions]::Standard, [int], [Type[]]@([int], [IntPtr], [int], [int].MakeByRefType()), [System.Runtime.InteropServices.CallingConvention]::Winapi, [System.Runtime.InteropServices.CharSet]::Auto)",
        "$pm.SetImplementationFlags($pm.GetMethodImplementationFlags() -bor [System.Reflection.MethodImplAttributes]::PreserveSig)",
        "$t = $tb.CreateType()",
        "$emit = $sw.ElapsedMilliseconds; $sw.Restart()",
        "$len = 1048576; $needed = 0",
        "$buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($len)",
        "$out = @()",
        "try {",
        "  while (($st = $t::NtQuerySystemInformation(5, $buf, $len, [ref]$needed)) -eq -1073741820) {",
        "    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf); $len = $needed + 65536",
        "    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($len)",
        "  }",
        "  if ($st -ne 0) { throw ('NtQuerySystemInformation failed: 0x{0:x8}' -f $st) }",
        "  $off = [int64]0",
        "  while ($true) {",
        "    $e = [IntPtr]($buf.ToInt64() + $off)",
        "    $next = [System.Runtime.InteropServices.Marshal]::ReadInt32($e, 0)",
        "    $create = [System.Runtime.InteropServices.Marshal]::ReadInt64($e, 32)",
        "    $p = [System.Runtime.InteropServices.Marshal]::ReadInt64($e, 80)",
        "    $pp = [System.Runtime.InteropServices.Marshal]::ReadInt64($e, 88)",
        `    if ($pp -eq ${String(pid)} -and $p -gt 0) { $out += ('{0} {1}' -f $p, [int64][math]::Floor(($create - 116444736000000000) / 10000)) }`,
        "    if ($next -eq 0) { break }",
        "    $off += $next",
        "  }",
        "} finally { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }",
        "$call = $sw.ElapsedMilliseconds",
        "'# emit={0} call={1} lang={2}' -f $emit, $call, $ExecutionContext.SessionState.LanguageMode",
        "$out",
      ].join("\n");
    }

    function runProbeHelper(script: string): Promise<{ code: number | null; stdout: string }> {
      return new Promise((resolve, reject) => {
        const child = spawn(
          system32Path("WindowsPowerShell", "v1.0", "powershell.exe"),
          ["-NoProfile", "-NonInteractive", "-Command", script],
          {
            shell: false,
            windowsHide: true,
            stdio: ["ignore", "pipe", "ignore"],
          },
        );
        const chunks: Buffer[] = [];
        let settled = false;
        const finish = (err: Error | null, code: number | null): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (err) reject(err);
          else resolve({ code, stdout: Buffer.concat(chunks).toString("utf8") });
        };
        const timer = setTimeout(() => {
          child.kill();
          finish(new Error("probe helper timed out"), null);
        }, PROBE_HELPER_TIMEOUT_MS);
        child.stdout?.on("data", (chunk: Buffer) => chunks.push(chunk));
        child.on("error", (err) => finish(err, null));
        child.on("close", (code) => finish(null, code));
      });
    }

    function parseListing(stdout: string): DescendantProcess[] {
      const found: DescendantProcess[] = [];
      for (const line of stdout.split(/\r?\n/)) {
        const match = /^(\d+) (\d+)$/.exec(line.trim());
        if (match) found.push({ pid: Number(match[1]), createdAtMs: Number(match[2]) });
      }
      return found;
    }

    /** The `# …` header a candidate prints ahead of its rows, without the `# `. */
    function parseHeader(stdout: string): string {
      const line = stdout.split(/\r?\n/).find((l) => l.startsWith("#"));
      return line === undefined ? "" : line.trim().slice(2);
    }

    it(
      "prints the start-up, WMI, Add-Type and Reflection.Emit listings of one live parent: durations, rows, agreement",
      async () => {
        const grandchild = `setTimeout(() => {}, ${String(PROBE_HOLD_MS)})`;
        const parentScript = `
      const { spawn } = require("node:child_process");
      const gc = spawn(process.execPath, ["-e", ${JSON.stringify(grandchild)}], { stdio: "ignore", windowsHide: true, detached: true });
      gc.unref();
      console.log("child-done " + gc.pid);
      setTimeout(() => {}, ${String(PROBE_HOLD_MS)});
    `;
        const parent = spawn(process.execPath, ["-e", parentScript], {
          stdio: ["ignore", "pipe", "ignore"],
          windowsHide: true,
        });
        const pid = parent.pid as number;
        probePids.push(pid);
        const grandchildPid = await new Promise<number>((resolve) => {
          let buffered = "";
          parent.stdout.on("data", (chunk: Buffer) => {
            buffered += chunk.toString();
            const match = /child-done (\d+)/.exec(buffered);
            if (match) resolve(Number(match[1]));
          });
        });
        probePids.push(grandchildPid);

        const wmi = win32SweepDeps({
          helperTimeoutMs: PROBE_HELPER_TIMEOUT_MS,
        });
        const samples: string[] = [];
        const pidSets: string[] = [];
        let lang = "";

        const startupStarted = Date.now();
        try {
          const { code } = await runProbeHelper("exit");
          samples.push(`startup=${String(Date.now() - startupStarted)}ms (exit ${String(code)})`);
        } catch (err) {
          samples.push(
            `startup=${String(Date.now() - startupStarted)}ms (${err instanceof Error ? err.message : String(err)})`,
          );
        }

        const take = async (
          label: string,
          list: () => Promise<{ rows: DescendantProcess[]; header: string }>,
        ): Promise<void> => {
          const started = Date.now();
          try {
            const { rows, header } = await list();
            pidSets.push(
              rows
                .map((r) => r.pid)
                .sort((a, b) => a - b)
                .join(","),
            );
            const langMatch = /lang=(\S+)/.exec(header);
            if (langMatch?.[1] !== undefined) lang = langMatch[1];
            const timing = header.replace(/ ?lang=\S+/, "");
            samples.push(
              `${label}=${String(Date.now() - started)}ms (ok, rows ${String(rows.length)}${timing === "" ? "" : `, ${timing}`})`,
            );
          } catch (err) {
            pidSets.push("error");
            samples.push(
              `${label}=${String(Date.now() - started)}ms (${err instanceof Error ? err.message : String(err)})`,
            );
          }
        };
        const viaScript =
          (script: string) => async (): Promise<{ rows: DescendantProcess[]; header: string }> => {
            const { code, stdout } = await runProbeHelper(script);
            if (code !== 0) throw new Error(`listing exited ${String(code)}`);
            return { rows: parseListing(stdout), header: parseHeader(stdout) };
          };

        await take("wmi", async () => ({
          rows: await wmi.listDescendants(pid),
          header: "",
        }));
        await take("addtype cold", viaScript(addTypeScript(pid)));
        await take("addtype warm", viaScript(addTypeScript(pid)));
        await take("emit cold", viaScript(emitScript(pid)));
        await take("emit warm", viaScript(emitScript(pid)));

        const first = pidSets[0];
        const equal = first !== undefined && first !== "error" && pidSets.every((s) => s === first);
        console.error(
          `[descendant-sweep live] listing probe: ${samples.join("; ")}; lang=${lang}; pids equal=${String(equal)} (grandchild ${String(grandchildPid)})`,
        );
      },
      PROBE_HELPER_TIMEOUT_MS * 6 + 30_000,
    );
  },
);
