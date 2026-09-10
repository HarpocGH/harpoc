import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { afterEach, describe, it } from "vitest";
import { recordSeriesLine } from "@harpoc/test-utils";
import { system32Path } from "../win32-paths.js";

// Diagnostics only (D2 of docs/implementation-plan-win32-job-wrapper-2026-09-10.md):
// the job-object wrapper compiled by the inbox csc and exercised on the
// windows-latest legs — compile time, added wall time per spawn, the kill
// through the wrapper, argv fidelity. Prints one stderr line, asserts nothing,
// and is removed by the tranche commit either way.

/** The D1 program. Task 1 ships this text byte-identical as JOB_WRAPPER_SOURCE. */
export const PROBE_WRAPPER_SOURCE = `// harpoc-job: the vault's win32 lifecycle wrapper (thesis 4.5.3 layer 4; D1 of
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

interface RunOutcome {
  code: number | null;
  stdout: string;
  stderr: string;
  ms: number;
}

/** The product's spawn shape (spawn-captured.ts) — shell:false, windowsHide, piped output. */
function run(command: string, args: string[], timeoutMs = 60_000): Promise<RunOutcome> {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(command, args, {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
    child.stderr?.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
    const timer = setTimeout(() => child.kill(), timeoutMs);
    const finish = (code: number | null, err?: Error): void => {
      clearTimeout(timer);
      resolve({
        code,
        stdout,
        stderr: err ? `${err.message}\n${stderr}` : stderr,
        ms: Date.now() - started,
      });
    };
    child.on("error", (err) => finish(null, err));
    child.on("close", (code) => finish(code));
  });
}

function firstLine(child: ChildProcess): Promise<string> {
  return new Promise((resolve) => {
    if (!child.stdout) {
      resolve("");
      return;
    }
    createInterface({ input: child.stdout }).once("line", resolve);
  });
}

const isAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== "ESRCH";
  }
};

const TRICKY_ARGS = [
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

describe.runIf(process.platform === "win32")(
  "job wrapper probe — diagnostics only (2026-09-10)",
  () => {
    const probePids: number[] = [];
    let dir: string;

    afterEach(() => {
      for (const pid of probePids.splice(0)) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // Already gone.
        }
      }
      if (dir) rmSync(dir, { recursive: true, force: true });
    });

    it("compiles, spawns, kills and echoes through the wrapper, and prints one line", async () => {
      dir = mkdtempSync(join(tmpdir(), "harpoc-job-probe-"));
      const root = process.env["SystemRoot"] ?? "C:\\Windows";
      const csc = join(root, "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe");
      const cmd = system32Path("cmd.exe");
      const ps = system32Path("WindowsPowerShell", "v1.0", "powershell.exe");
      const source = join(dir, "harpoc-job.cs");
      const exe = join(dir, "harpoc-job.exe");
      writeFileSync(source, PROBE_WRAPPER_SOURCE, "utf8");

      const compile = await run(csc, [
        "-nologo",
        "-optimize",
        "-target:exe",
        "-platform:anycpu",
        `-out:${exe}`,
        source,
      ]);
      const parts: string[] = [`csc=${String(compile.ms)}ms (exit ${String(compile.code)})`];
      let policy = "ok";
      let addedMax = 0;

      if (compile.code === 0) {
        const probe = await run(exe, ["--keep", cmd, "/c", "exit"], 10_000);
        parts.push(`probe=${String(probe.ms)}ms (exit ${String(probe.code)})`);
        if (probe.code !== 0)
          policy = probe.stderr.trim().split(/\r?\n/)[0] ?? `exit ${String(probe.code)}`;

        const direct: number[] = [];
        const wrapped: number[] = [];
        for (let i = 0; i < 5; i++) {
          direct.push((await run(cmd, ["/c", "exit"], 10_000)).ms);
          wrapped.push((await run(exe, ["--keep", cmd, "/c", "exit"], 10_000)).ms);
          addedMax = Math.max(addedMax, (wrapped[i] as number) - (direct[i] as number));
        }
        parts.push(
          `direct=${direct.join("/")}ms wrapped=${wrapped.join("/")}ms added max=${String(addedMax)}`,
        );

        // A PowerShell child that starts a PowerShell grandchild: no libuv job anywhere in that tree.
        const childScript =
          `$p = Start-Process -FilePath '${ps}' -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep 120' -PassThru -WindowStyle Hidden; ` +
          "[Console]::Out.WriteLine('G ' + $p.Id); [Console]::Out.Flush(); Start-Sleep 120";
        const tree = spawn(
          exe,
          ["--strict", ps, "-NoProfile", "-NonInteractive", "-Command", childScript],
          {
            shell: false,
            windowsHide: true,
            stdio: ["ignore", "pipe", "ignore"],
          },
        );
        if (tree.pid !== undefined) probePids.push(tree.pid);
        const grandchild = Number((await firstLine(tree)).split(" ")[1]);
        if (Number.isInteger(grandchild) && grandchild > 0) probePids.push(grandchild);
        const closed = new Promise<void>((resolve) => tree.once("close", () => resolve()));
        const killedAt = Date.now();
        tree.kill();
        await closed;
        const closedInMs = Date.now() - killedAt;
        await new Promise((r) => setTimeout(r, 500));
        parts.push(
          `kill: closed in ${String(closedInMs)}ms, grandchild alive=${String(isAlive(grandchild))}`,
        );

        const echo = [
          "-e",
          "console.log(JSON.stringify(process.argv.slice(1)))",
          "--",
          ...TRICKY_ARGS,
        ];
        const d = await run(process.execPath, echo, 20_000);
        const w = await run(exe, ["--keep", process.execPath, ...echo], 20_000);
        parts.push(`argv identical=${String(d.stdout === w.stdout && d.stdout.length > 0)}`);
      } else {
        policy = compile.stderr.trim().split(/\r?\n/)[0] ?? "compile failed";
      }
      parts.push(`policy=${policy}`);
      recordSeriesLine(`[job-wrapper probe] ${parts.join("; ")}`, { judgedMs: addedMax });
    }, 180_000);
  },
);
