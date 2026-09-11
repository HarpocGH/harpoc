/**
 * The vault's win32 lifecycle wrapper (thesis §4.5.3 layer 4; D1–D5 of
 * docs/implementation-plan-win32-job-wrapper-2026-09-10.md).
 *
 * `taskkill /T` snapshots a process tree once, so a grandchild created between
 * the snapshot and the kill escapes with the inherited environment — the
 * credential included; the descendant sweep behind a WMI listing closes that
 * window at 20–60 s under load and fails open. A job object closes it by
 * construction: every process a job member creates is a job member, and
 * `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` terminates them all when the last
 * handle closes. Node cannot spawn a suspended child or call the job API, so
 * a vault-authored wrapper does: `harpoc-job.exe --keep|--strict <payload>
 * <args...>` creates the job, spawns the payload suspended inside it with the
 * inherited standard handles, resumes it and exits with its exit code, handing
 * its own command-line tail to the payload verbatim. Killed by the vault, its
 * handle closes and the kernel takes the tree; on a normal exit `--keep`
 * clears the flag first (survivors left exactly as before, the default) and
 * `--strict` leaves it set, so the exit closes the job on every survivor (the
 * per-secret `strict_tree_exit` policy, 2026-09-10).
 *
 * The program is C# 5 — the `csc.exe` every Windows with PowerShell 5.1
 * carries under `%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319` — held
 * here as a constant and compiled once into a directory named by the
 * source's hash (freshness by name; the filename stays `harpoc-job.exe` so
 * `EXEC_WRAPPERS` matches it). Compiled at build time on Windows hosts
 * (`scripts/build-win32-helper.mjs`), on first use otherwise, or into
 * `~/.harpoc/helpers` when dist is read-only. Availability is a live probe
 * cached per process on success; an unavailable verdict is held for
 * JOB_WRAPPER_RETRY_MS and re-resolved, and every spawn without the wrapper
 * runs today's taskkill + sweep tier. Never PATH; never a shell.
 */
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { system32Path } from "../win32-paths.js";

export const JOB_WRAPPER_SOURCE = `// harpoc-job: the vault's win32 lifecycle wrapper (thesis 4.5.3 layer 4; D1 of
// docs/implementation-plan-win32-job-wrapper-2026-09-10.md). Creates a kill-on-close job
// object, spawns the payload suspended inside it with the inherited standard handles,
// resumes it, waits, and exits with the payload's exit code. Killed by the vault on timeout,
// its job handle closes and the kernel terminates every process in the job. Under --keep the
// flag is cleared after a normal exit, so survivors are left as they were before this wrapper
// existed; --strict leaves it set (the test flip, never passed by the product). Reads no
// environment variable; writes nothing but its own failure line. C# 5: the inbox compiler.
using System;
using System.Runtime.InteropServices;
using System.Text;

static class HarpocJob {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct STARTUPINFO { public int cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
  [StructLayout(LayoutKind.Sequential)]
  struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
  [StructLayout(LayoutKind.Sequential)] struct BASIC { public long a, b; public uint LimitFlags; public UIntPtr c, d; public uint e; public UIntPtr f; public uint g, h; }
  [StructLayout(LayoutKind.Sequential)] struct IOC { public ulong a, b, c, d, e, f; }
  [StructLayout(LayoutKind.Sequential)] struct EXT { public BASIC Basic; public IOC Io; public UIntPtr a, b, c, d; }

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr CreateJobObjectW(IntPtr a, string name);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int cls, IntPtr info, uint len);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);
  [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr t);
  [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);
  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr GetStdHandle(int n);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetHandleInformation(IntPtr h, uint mask, uint flags);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern IntPtr GetCommandLineW();

  // JobObjectExtendedLimitInformation = 9; 0x2000 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
  static bool SetLimit(IntPtr job, uint flags) {
    var info = new EXT(); info.Basic.LimitFlags = flags;
    int len = Marshal.SizeOf(info); IntPtr p = Marshal.AllocHGlobal(len);
    Marshal.StructureToPtr(info, p, false);
    bool ok = SetInformationJobObject(job, 9, p, (uint)len);
    Marshal.FreeHGlobal(p); return ok;
  }

  // The command line after its first token, by the rule CommandLineToArgvW applies to
  // that token: the payload's own command line exactly as the parent quoted it.
  static string Tail(string cl) {
    int i;
    if (cl.Length > 0 && cl[0] == '"') { i = cl.IndexOf('"', 1); i = i < 0 ? cl.Length : i + 1; }
    else { i = cl.IndexOf(' '); if (i < 0) i = cl.Length; }
    while (i < cl.Length && cl[i] == ' ') i++;
    return cl.Substring(i);
  }

  static int Main(string[] args) {
    if (args.Length < 2 || (args[0] != "--keep" && args[0] != "--strict")) { Console.Error.WriteLine("harpoc-job: usage: --keep|--strict <application> [args]"); return 9008; }
    bool strict = args[0] == "--strict";
    string app = args[1];
    string tail = Tail(Tail(Marshal.PtrToStringUni(GetCommandLineW())));
    IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
    if (job == IntPtr.Zero || !SetLimit(job, 0x2000)) { Console.Error.WriteLine("harpoc-job: job object failed: " + Marshal.GetLastWin32Error()); return 9010; }
    var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si); si.dwFlags = 0x100;
    si.hStdInput = GetStdHandle(-10); si.hStdOutput = GetStdHandle(-11); si.hStdError = GetStdHandle(-12);
    SetHandleInformation(si.hStdInput, 1, 1); SetHandleInformation(si.hStdOutput, 1, 1); SetHandleInformation(si.hStdError, 1, 1);
    PROCESS_INFORMATION pi;
    var cmd = new StringBuilder(tail);
    // CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW
    if (!CreateProcessW(app, cmd, IntPtr.Zero, IntPtr.Zero, true, 0x4 | 0x400 | 0x08000000, IntPtr.Zero, null, ref si, out pi)) {
      Console.Error.WriteLine("harpoc-job: CreateProcess failed: " + Marshal.GetLastWin32Error()); return 9009;
    }
    if (!AssignProcessToJobObject(job, pi.hProcess)) { int e = Marshal.GetLastWin32Error(); TerminateProcess(pi.hProcess, 1); Console.Error.WriteLine("harpoc-job: assign failed: " + e); return 9011; }
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
    uint code; GetExitCodeProcess(pi.hProcess, out code);
    if (!strict) SetLimit(job, 0);
    return (int)code;
  }
}
`;

export const JOB_WRAPPER_SOURCE_SHA256 = createHash("sha256")
  .update(JOB_WRAPPER_SOURCE, "utf8")
  .digest("hex");
export const JOB_WRAPPER_DIR_NAME = "harpoc-job";
export const JOB_WRAPPER_EXE = "harpoc-job.exe";
export const JOB_WRAPPER_KEEP_FLAG = "--keep";
/** Strict normal-exit mode: the job closes on the whole tree when the payload exits (D2, 2026-09-10 — `strict_tree_exit`). */
export const JOB_WRAPPER_STRICT_FLAG = "--strict";
/** csc under the full parallel gate measured 25 s on the windows-latest legs (2026-09-09, the Add-Type compile). */
export const JOB_WRAPPER_COMPILE_TIMEOUT_MS = 60_000;
/** The isolation probes' bound. */
export const JOB_WRAPPER_PROBE_TIMEOUT_MS = 5_000;
/** How long an unavailable verdict stands before it is re-resolved. */
export const JOB_WRAPPER_RETRY_MS = 60_000;
export const JOB_WRAPPER_STDERR_MARKER = "harpoc-job: ";
/** 9009 CreateProcess failed, 9010 job object failed, 9011 assignment failed — the payload never ran. */
export const JOB_WRAPPER_FAILURE_EXIT_CODES: ReadonlySet<number> = new Set([9009, 9010, 9011]);

export type TreeKillMechanism = "job" | "taskkill";

/** The normal-exit semantics a wrap is asked for (D2, 2026-09-10): `keep` leaves survivors as before, `strict` closes the job on them. */
export type JobWrapMode = "keep" | "strict";

export interface JobWrap {
  command: string;
  args: string[];
  mechanism: "job";
  mode: JobWrapMode;
}

/** The tier is unavailable on this host, or the platform has none; `reason` is the resolver's verdict. */
export interface JobWrapMiss {
  mechanism: null;
  reason: string;
}

export type JobWrapperResolution = { exe: string } | { unavailable: string };

/** Injectable seams for unit tests; production callers pass nothing. */
export interface JobWrapperSeams {
  platform?: NodeJS.Platform;
  compilerCandidates?: readonly string[];
  cacheDirs?: readonly string[];
  probeBinary?: (path: string) => boolean;
  runHelper?: (
    command: string,
    args: string[],
    timeoutMs: number,
  ) => Promise<{ code: number | null }>;
  restrictDir?: (dir: string) => void;
  now?: () => number;
}

export function jobWrapperCompilerCandidates(): string[] {
  const root = process.env["SystemRoot"] ?? "C:\\Windows";
  return [
    join(root, "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe"),
    join(root, "Microsoft.NET", "Framework", "v4.0.30319", "csc.exe"),
  ];
}

/** Two levels above this file is the package root, from `src/injection` and from `dist/injection` alike. */
export function jobWrapperCacheDirs(): string[] {
  const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
  return [join(packageRoot, "dist", "win32"), join(homedir(), ".harpoc", "helpers")];
}

export function jobWrapperExePath(cacheDir: string): string {
  return join(
    cacheDir,
    JOB_WRAPPER_DIR_NAME,
    JOB_WRAPPER_SOURCE_SHA256.slice(0, 16),
    JOB_WRAPPER_EXE,
  );
}

/** The wrapper's own failure: one of its reserved codes AND its marker as the first stderr bytes. */
export function isJobWrapperFailure(code: number | null, stderr: string): boolean {
  return (
    code !== null &&
    JOB_WRAPPER_FAILURE_EXIT_CODES.has(code) &&
    stderr.startsWith(JOB_WRAPPER_STDERR_MARKER)
  );
}

/** Rejects only when the helper could not be run to completion (spawn error, timeout). */
function defaultRunHelper(
  command: string,
  args: string[],
  timeoutMs: number,
): Promise<{ code: number | null }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { shell: false, windowsHide: true, stdio: "ignore" });
    let settled = false;
    const finish = (err: Error | null, code: number | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve({ code });
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(new Error("job wrapper helper timed out"), null);
    }, timeoutMs);
    if (timer.unref) timer.unref();
    child.on("error", (err) => finish(err, null));
    child.on("close", (code) => finish(null, code));
  });
}

/** The test seam of `restrictToOwner`; production callers pass nothing. */
export interface RestrictSeams {
  account?: string;
  spawnSync?: typeof spawnSync;
}

/**
 * The session file's icacls step (`session-manager.ts`'s `restrictWindowsAcl`), for a
 * directory: owner-only, inherited by what is created inside. The outcome is thrown, never
 * swallowed — the source is written, compiled and then *executed* from this directory, and an
 * adopted exe is re-restricted on every process (note 4, 2026-09-10), so one silently failed
 * restriction is never permanent. The caller's catch records it as a failed candidate, skips the
 * directory and leaves the tier behind the wrapper to run. Exported for its pins (note 3).
 */
export function restrictToOwner(dir: string, seams: RestrictSeams = {}): void {
  const account = seams.account ?? userInfo().username;
  if (!account) throw new Error("could not determine the current account name");
  const res = (seams.spawnSync ?? spawnSync)(
    system32Path("icacls.exe"),
    [dir, "/inheritance:r", "/grant:r", `${account}:(OI)(CI)F`],
    {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 15_000,
    },
  );
  if (res.error) throw res.error;
  if (res.status !== 0) {
    const detail = (res.stderr?.toString() || res.stdout?.toString() || "").trim().slice(0, 200);
    throw new Error(`icacls exited ${String(res.status)}${detail ? `: ${detail}` : ""}`);
  }
}

/** A compiler that ran and failed, or did not complete: host-wide, so the candidate loop stops (minor 2). */
class CompilerFailure extends Error {}

/** EPERM-tolerant: a tmp exe still mapped by a rejected helper's process cannot be unlinked on win32 (minor 1). */
function removeQuietly(path: string): void {
  try {
    rmSync(path, { force: true });
  } catch {
    // Left behind under a per-process name; the next compile in this directory is unaffected.
  }
}

async function compileInto(
  exe: string,
  csc: string,
  runHelper: NonNullable<JobWrapperSeams["runHelper"]>,
): Promise<void> {
  const dir = dirname(exe);
  mkdirSync(dir, { recursive: true });
  // Per-process names (note 5, 2026-09-10): a concurrent first use never
  // truncates a source a running csc is reading. The source write doubles as
  // the writability probe — past it, a compiler failure is host-wide.
  const source = join(dir, `harpoc-job.${String(process.pid)}.cs`);
  const tmp = join(dir, `harpoc-job.${String(process.pid)}.tmp.exe`);
  writeFileSync(source, JOB_WRAPPER_SOURCE, "utf8");
  let code: number | null;
  try {
    ({ code } = await runHelper(
      csc,
      ["-nologo", "-optimize", "-target:exe", "-platform:anycpu", `-out:${tmp}`, source],
      JOB_WRAPPER_COMPILE_TIMEOUT_MS,
    ));
  } catch (err) {
    removeQuietly(tmp);
    removeQuietly(source);
    throw new CompilerFailure(
      `csc did not complete: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (code !== 0) {
    removeQuietly(tmp);
    removeQuietly(source);
    throw new CompilerFailure(`csc exited ${String(code)}`);
  }
  try {
    renameSync(tmp, exe);
  } catch (err) {
    // A concurrent compile won the rename, or its exe is already running: use the winner.
    removeQuietly(tmp);
    if (!existsSync(exe)) {
      removeQuietly(source);
      throw err;
    }
  }
  // The record beside the exe: the winner's source stands, ours is dropped.
  const record = join(dir, "harpoc-job.cs");
  if (!existsSync(record)) {
    try {
      renameSync(source, record);
      return;
    } catch {
      // The winner's rename landed first.
    }
  }
  removeQuietly(source);
}

async function resolve(seams: JobWrapperSeams): Promise<JobWrapperResolution> {
  const platform = seams.platform ?? process.platform;
  if (platform !== "win32") return { unavailable: `unsupported platform: ${platform}` };
  const probeBinary = seams.probeBinary ?? existsSync;
  const runHelper = seams.runHelper ?? defaultRunHelper;
  const restrictDir = seams.restrictDir ?? restrictToOwner;
  const dirs = seams.cacheDirs ?? jobWrapperCacheDirs();

  let exe: string | undefined;
  let lastError = "no cache directory";
  for (const [index, dir] of dirs.entries()) {
    const candidate = jobWrapperExePath(dir);
    if (!probeBinary(candidate)) continue;
    if (index > 0) {
      // An exe outside the package's own dist is executed from that directory
      // on every later process: re-apply the owner-only ACL before trusting it
      // (note 4, 2026-09-10) — idempotent, one icacls per process.
      try {
        restrictDir(dir);
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        continue;
      }
    }
    exe = candidate;
    break;
  }
  if (exe === undefined) {
    const csc = (seams.compilerCandidates ?? jobWrapperCompilerCandidates()).find((p) =>
      probeBinary(p),
    );
    if (csc === undefined) {
      return { unavailable: "csc.exe not found under Microsoft.NET Framework v4.0.30319" };
    }
    for (const [index, dir] of dirs.entries()) {
      const candidate = jobWrapperExePath(dir);
      try {
        if (index > 0) {
          mkdirSync(dir, { recursive: true });
          restrictDir(dir);
        }
        await compileInto(candidate, csc, runHelper);
        exe = candidate;
        break;
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        // The source was written, so this directory is writable: a compiler
        // that then fails or hangs is the host's, not the directory's.
        if (err instanceof CompilerFailure) break;
      }
    }
    if (exe === undefined) return { unavailable: `compile failed: ${lastError}` };
  }

  let probeCode: number | null;
  try {
    probeCode = (
      await runHelper(
        exe,
        [JOB_WRAPPER_KEEP_FLAG, system32Path("cmd.exe"), "/c", "exit"],
        JOB_WRAPPER_PROBE_TIMEOUT_MS,
      )
    ).code;
  } catch (err) {
    return { unavailable: `probe run failed: ${err instanceof Error ? err.message : String(err)}` };
  }
  if (probeCode !== 0) return { unavailable: `probe run exited ${String(probeCode)}` };
  return { exe };
}

let cachedResolution: Promise<JobWrapperResolution> | null = null;
let unavailableUntil = 0;
let lastUnavailable = "";
let forcedUnavailableForTests: string | null = null;
let unavailableHandler: ((reason: string) => void) | null = null;
let unavailableWarned = false;

/**
 * Install the host's warning for an unavailable wrapper (note 2, 2026-09-10):
 * the engine forwards `VaultEngineOptions.onJobWrapperUnavailable` here from
 * its constructor (the last engine constructed wins — one engine per host
 * process). Fires at most once per process, on the first win32 verdict, never
 * off win32 and never under the forced test seam; the latch resets with
 * `resetJobWrapperProbeForTests`. A throwing handler never fails a spawn.
 */
export function setJobWrapperUnavailableHandler(handler: ((reason: string) => void) | null): void {
  unavailableHandler = handler;
}

function notifyUnavailable(reason: string, platform: NodeJS.Platform): void {
  if (unavailableWarned || platform !== "win32" || unavailableHandler === null) return;
  unavailableWarned = true;
  try {
    unavailableHandler(reason);
  } catch {
    // The host's warning sink is not the vault's concern.
  }
}

/**
 * Resolve the wrapper: an existing or freshly compiled exe that passed its
 * probe run, or the reason it is unavailable. Never rejects. A success is
 * cached for the process lifetime (genuine capability does not change under
 * the vault); an unavailable verdict stands for JOB_WRAPPER_RETRY_MS — long
 * enough that a permanent cause never costs a compile per spawn, short
 * enough that a transient one under load does not disable the tier for a
 * long-lived server. Concurrent callers coalesce on the in-flight promise.
 */
export async function resolveJobWrapper(
  seams: JobWrapperSeams = {},
): Promise<JobWrapperResolution> {
  if (forcedUnavailableForTests !== null) return { unavailable: forcedUnavailableForTests };
  const now = seams.now ?? Date.now;
  if (!cachedResolution) {
    if (now() < unavailableUntil) return { unavailable: lastUnavailable };
    const attempt: Promise<JobWrapperResolution> = resolve(seams)
      .catch(
        (err: unknown): JobWrapperResolution => ({
          unavailable: `resolution failed: ${err instanceof Error ? err.message : String(err)}`,
        }),
      )
      .then((result) => {
        if ("unavailable" in result && cachedResolution === attempt) {
          cachedResolution = null;
          lastUnavailable = result.unavailable;
          unavailableUntil = now() + JOB_WRAPPER_RETRY_MS;
          notifyUnavailable(result.unavailable, seams.platform ?? process.platform);
        }
        return result;
      });
    cachedResolution = attempt;
  }
  return cachedResolution;
}

/**
 * Wrap an already-resolved command in the job wrapper in the requested
 * normal-exit mode, or report the miss with the resolver's reason (the caller
 * runs today's taskkill + sweep path — or, for a strict spawn on win32,
 * refuses: D2, 2026-09-10).
 */
export async function wrapInJob(
  command: string,
  args: readonly string[],
  mode: JobWrapMode,
  seams?: JobWrapperSeams,
): Promise<JobWrap | JobWrapMiss> {
  const resolved = await resolveJobWrapper(seams);
  if ("unavailable" in resolved) return { mechanism: null, reason: resolved.unavailable };
  return {
    command: resolved.exe,
    args: [mode === "strict" ? JOB_WRAPPER_STRICT_FLAG : JOB_WRAPPER_KEEP_FLAG, command, ...args],
    mechanism: "job",
    mode,
  };
}

export function resetJobWrapperProbeForTests(): void {
  cachedResolution = null;
  unavailableUntil = 0;
  lastUnavailable = "";
  unavailableWarned = false;
}

/** Force the fallback tier regardless of platform. Only unavailability can be forced (tightening). */
export function forceJobWrapperUnavailableForTests(reason: string | null): void {
  forcedUnavailableForTests = reason;
}
