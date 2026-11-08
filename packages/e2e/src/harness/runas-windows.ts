import { spawn } from "node:child_process";
import { win32 } from "node:path";
import { CHILD_TIMEOUT_MS, KILL_GRACE_MS, STOP_GRACE_MS } from "./child.js";
import type { ChildRun } from "./child.js";
import { runCommand } from "./sudo.js";
import type { AsUserOptions, StartedChild } from "./sudo.js";

const VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const PID_LINE = /^\[runas\] pid=(\d+)\r?\n/;
const START_FAILED = /^\[runas\] start failed: native=(-?\d+)/m;

/** Exit code of the launcher when the account's process could not be started at all. */
export const LAUNCH_FAILED_EXIT = 125;
/** `ERROR_LOGON_FAILURE`: the account's name or password was refused. */
export const ERROR_LOGON_FAILURE = 1326;

/**
 * The names the child inherits from the runner: the system's own, never the
 * runner's job variables (the passwords the job exports, `GITHUB_*`,
 * `ACTIONS_*`), which a child of another account must not see. The comparison
 * is case-insensitive, as Windows' is.
 */
const INHERITED_NAMES: readonly string[] = [
  "ALLUSERSPROFILE",
  "CommonProgramFiles",
  "ComSpec",
  "NUMBER_OF_PROCESSORS",
  "OS",
  "PATH",
  "PATHEXT",
  "PROCESSOR_ARCHITECTURE",
  "ProgramData",
  "ProgramFiles",
  "ProgramFiles(x86)",
  "ProgramW6432",
  "PUBLIC",
  "SystemDrive",
  "SystemRoot",
  "windir",
];

/**
 * The launcher: a Windows PowerShell 5.1 script that reads one JSON object
 * `{ file, arguments, cwd?, env, stdin, user?, password?, domain? }` from its
 * stdin — the password therefore reaches neither a command line nor the
 * environment of any process — starts `file` through
 * `System.Diagnostics.Process` (`UserName`, `Password` as a `SecureString`,
 * `LoadUserProfile`, `UseShellExecute = false`, all three streams redirected),
 * prints `[runas] pid=<n>` as the first line of its own stderr, copies the
 * child's stdout and stderr byte for byte to its own, and exits with the
 * child's code. A start the system refuses prints
 * `[runas] start failed: native=<Win32 error>` and exits `LAUNCH_FAILED_EXIT`.
 */
export const RUNAS_LAUNCHER = [
  "$ErrorActionPreference = 'Stop'",
  "$ProgressPreference = 'SilentlyContinue'",
  "$reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), (New-Object System.Text.UTF8Encoding($false)))",
  "$spec = $reader.ReadToEnd() | ConvertFrom-Json",
  "$psi = New-Object System.Diagnostics.ProcessStartInfo",
  "$psi.FileName = [string]$spec.file",
  "$psi.Arguments = [string]$spec.arguments",
  "$psi.UseShellExecute = $false",
  "$psi.CreateNoWindow = $true",
  "$psi.RedirectStandardInput = $true",
  "$psi.RedirectStandardOutput = $true",
  "$psi.RedirectStandardError = $true",
  "if ($spec.cwd) { $psi.WorkingDirectory = [string]$spec.cwd }",
  "if ($spec.user) {",
  "  $psi.UserName = [string]$spec.user",
  "  $psi.Domain = if ($spec.domain) { [string]$spec.domain } else { '.' }",
  "  $secure = New-Object System.Security.SecureString",
  "  foreach ($c in ([string]$spec.password).ToCharArray()) { $secure.AppendChar($c) }",
  "  $psi.Password = $secure",
  "  $psi.LoadUserProfile = $true",
  "}",
  "$psi.EnvironmentVariables.Clear()",
  "foreach ($v in $spec.env.PSObject.Properties) { $psi.EnvironmentVariables[$v.Name] = [string]$v.Value }",
  "try {",
  "  $proc = [System.Diagnostics.Process]::Start($psi)",
  "} catch {",
  "  $native = 0; $cause = $_.Exception",
  "  while ($null -ne $cause -and -not ($cause -is [System.ComponentModel.Win32Exception])) { $cause = $cause.InnerException }",
  "  if ($null -ne $cause) { $native = $cause.NativeErrorCode; $text = $cause.Message } else { $text = $_.Exception.Message }",
  "  [Console]::Error.WriteLine('[runas] start failed: native=' + $native + ' ' + $text)",
  `  exit ${String(LAUNCH_FAILED_EXIT)}`,
  "}",
  "[Console]::Error.WriteLine('[runas] pid=' + $proc.Id)",
  "$copyOut = $proc.StandardOutput.BaseStream.CopyToAsync([Console]::OpenStandardOutput())",
  "$copyErr = $proc.StandardError.BaseStream.CopyToAsync([Console]::OpenStandardError())",
  "$bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$spec.stdin)",
  "try {",
  "  if ($bytes.Length -gt 0) { $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length); $proc.StandardInput.BaseStream.Flush() }",
  "  $proc.StandardInput.Close()",
  "} catch { }",
  "$proc.WaitForExit()",
  "[System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($copyOut, $copyErr))",
  "exit $proc.ExitCode",
].join("\n");

export interface LauncherSpec {
  file: string;
  arguments: string;
  cwd?: string;
  env: Record<string, string>;
  stdin: string;
  user?: string;
  password?: string;
  domain?: string;
}

export interface WindowsAccount {
  user: string;
  /** Handed to the launcher on its stdin only. */
  password: string;
}

export interface WindowsRunOptions extends AsUserOptions {
  cwd?: string;
  /** The directory the child's `TEMP` and `TMP` name; by default `%SystemRoot%\Temp`. */
  tempDir?: string;
}

/** The pinned `%SystemRoot%\System32` paths the harness runs; `systemRoot` is the runner's `SystemRoot`. */
export function systemPaths(systemRoot: string | undefined = process.env["SystemRoot"]): {
  powershell: string;
  taskkill: string;
  curl: string;
  ssh: string;
  tasklist: string;
  icacls: string;
} {
  if (systemRoot === undefined || systemRoot === "") {
    throw new Error("systemPaths: SystemRoot is not set (this harness runs on Windows)");
  }
  const system32 = win32.join(systemRoot, "System32");
  return {
    powershell: win32.join(system32, "WindowsPowerShell", "v1.0", "powershell.exe"),
    taskkill: win32.join(system32, "taskkill.exe"),
    tasklist: win32.join(system32, "tasklist.exe"),
    curl: win32.join(system32, "curl.exe"),
    ssh: win32.join(system32, "OpenSSH", "ssh.exe"),
    icacls: win32.join(system32, "icacls.exe"),
  };
}

/**
 * One argument as `CommandLineToArgvW` (and Node's own parser) reads it back
 * (Microsoft Learn, "Parsing C++ command-line arguments"): wrapped in quotes
 * when empty or holding a space, tab, newline or quote; every quote preceded by
 * a backslash, and the backslashes before a quote — or before the closing
 * quote — doubled.
 */
export function windowsArgument(arg: string): string {
  if (arg !== "" && !/[\s"]/.test(arg)) return arg;
  let out = '"';
  let slashes = 0;
  for (const ch of arg) {
    if (ch === "\\") {
      slashes += 1;
      continue;
    }
    if (ch === '"') {
      out += "\\".repeat(2 * slashes + 1) + '"';
    } else {
      out += "\\".repeat(slashes) + ch;
    }
    slashes = 0;
  }
  return `${out}${"\\".repeat(2 * slashes)}"`;
}

export function windowsCommandLine(argv: string[]): string {
  return argv.map(windowsArgument).join(" ");
}

/** `CreateProcessWithLogonW`'s `lpCommandLine` holds at most 1024 characters (Microsoft Learn, "CreateProcessWithLogonW function"). */
export const LOGON_COMMAND_LINE_LIMIT = 1024;

/**
 * The length of the command line the launcher's `Process.Start` hands
 * `CreateProcessWithLogonW` (.NET Framework's `BuildCommandLine`): `FileName`
 * trimmed and wrapped in quotes unless it already starts and ends with one,
 * then a space and `Arguments` when there are any.
 */
export function launcherCommandLineLength(spec: Pick<LauncherSpec, "file" | "arguments">): number {
  const file = spec.file.trim();
  const quoted = file.startsWith('"') && file.endsWith('"') ? file.length : file.length + 2;
  return quoted + (spec.arguments === "" ? 0 : 1 + spec.arguments.length);
}

/** Refuses a spec whose command line is over `LOGON_COMMAND_LINE_LIMIT`, naming its length and the limit, never its text. */
export function assertLauncherCommandLine(spec: Pick<LauncherSpec, "file" | "arguments">): void {
  const length = launcherCommandLineLength(spec);
  if (length > LOGON_COMMAND_LINE_LIMIT) {
    throw new Error(
      `runAsWindows: the command line is ${String(length)} characters, over the ${String(LOGON_COMMAND_LINE_LIMIT)} CreateProcessWithLogonW takes`,
    );
  }
}

/**
 * The environment the child gets: the system's names from `base`, the
 * account's `USERNAME`, `TEMP` and `TMP`, then `extra` — never the runner's own
 * variables. `extra` holds paths and placeholders only (`deployment-models.md`
 * Rules: a command line or an environment is readable beyond its owner).
 */
export function childEnvironment(
  user: string,
  extra: Record<string, string> = {},
  base: NodeJS.ProcessEnv = process.env,
  tempDir?: string,
): Record<string, string> {
  const lower = new Map(Object.entries(base).map(([name, value]) => [name.toLowerCase(), value]));
  const env: Record<string, string> = {};
  for (const name of INHERITED_NAMES) {
    const value = lower.get(name.toLowerCase());
    if (value !== undefined) env[name] = value;
  }
  const temp = tempDir ?? win32.join(lower.get("systemroot") ?? "C:\\Windows", "Temp");
  env["USERNAME"] = user;
  env["TEMP"] = temp;
  env["TMP"] = temp;
  for (const [name, value] of Object.entries(extra)) {
    if (!VARIABLE_NAME.test(name)) {
      throw new Error(`childEnvironment: ${JSON.stringify(name)} is not a variable name`);
    }
    env[name] = value;
  }
  return env;
}

export function launcherSpec(
  account: WindowsAccount,
  argv: string[],
  opts: WindowsRunOptions = {},
): LauncherSpec {
  const [file, ...rest] = argv;
  if (file === undefined || !win32.isAbsolute(file)) {
    throw new Error(
      "runAsWindows: argv[0] must be an absolute path (the launcher resolves no PATH)",
    );
  }
  return {
    file,
    arguments: windowsCommandLine(rest),
    cwd: opts.cwd,
    env: childEnvironment(account.user, opts.env, process.env, opts.tempDir),
    stdin: opts.stdin ?? "",
    user: account.user,
    password: account.password,
  };
}

function launcherArgv(): string[] {
  const encoded = Buffer.from(RUNAS_LAUNCHER, "utf16le").toString("base64");
  return [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-EncodedCommand",
    encoded,
  ];
}

/** The launcher's pid line removed from the child's stderr, and the pid it named. */
export function splitLauncherStderr(stderr: string): { pid: number | undefined; stderr: string } {
  const match = PID_LINE.exec(stderr);
  if (match === null) return { pid: undefined, stderr };
  return { pid: Number(match[1]), stderr: stderr.slice(match[0].length) };
}

/** The Win32 error of a refused start, `undefined` for any other run. */
export function launchFailure(run: ChildRun): number | undefined {
  if (run.code !== LAUNCH_FAILED_EXIT) return undefined;
  const match = START_FAILED.exec(run.stderr);
  return match === null ? undefined : Number(match[1]);
}

/** The launcher run on a spec as it stands: `runAsWindows`'s core, and the unit suite's seam for a spec with no account. */
export async function runLauncher(
  spec: LauncherSpec,
  opts: { timeoutMs?: number; label: string },
): Promise<ChildRun> {
  const run = await runCommand(systemPaths().powershell, launcherArgv(), {
    stdin: JSON.stringify(spec),
    timeoutMs: opts.timeoutMs,
    label: opts.label,
  });
  return { ...run, stderr: splitLauncherStderr(run.stderr).stderr };
}

/**
 * `argv` run as the local account `account.user`, no shell, under the deadline
 * of `runCommand`; `argv[0]` is an absolute path. The deadline's signals end
 * the launcher only when the child has exited with it; a child that outlives
 * the deadline is the teardown's to stop (`stopAs`).
 */
export async function runAsWindows(
  account: WindowsAccount,
  argv: string[],
  opts: WindowsRunOptions = {},
): Promise<ChildRun> {
  const spec = launcherSpec(account, argv, opts);
  assertLauncherCommandLine(spec);
  return runLauncher(spec, {
    timeoutMs: opts.timeoutMs ?? CHILD_TIMEOUT_MS,
    label: opts.label ?? `runas ${account.user} ${win32.basename(argv[0] ?? "")}`,
  });
}

/**
 * Stops `pid` and its tree as `account` — `taskkill /pid <pid> /t /f` run
 * through the same launcher, so the call needs no privilege of the runner
 * beyond the account's own right over its own process (the `sudo -n -u kill`
 * mirror). Exit 128 is "no such process": already gone.
 */
export async function stopAs(account: WindowsAccount, pid: number): Promise<void> {
  const run = await runAsWindows(
    account,
    [systemPaths().taskkill, "/pid", String(pid), "/t", "/f"],
    { label: `taskkill ${String(pid)} as ${account.user}` },
  );
  if (run.code !== 0 && run.code !== 128) {
    throw new Error(`taskkill /pid ${String(pid)} as ${account.user} exited ${String(run.code)}`);
  }
}

/**
 * A long-running command as `account`: the launcher outlives the call and
 * relays the child's streams; `stop` ends the child's tree as the account and
 * waits for the launcher to close. Windows has no SIGTERM for a console
 * process — the stop is `taskkill /f`, so the stopped command's exit code is
 * not 0 and no caller asserts one.
 */
export function startAsWindows(
  account: WindowsAccount,
  argv: string[],
  opts: { env?: Record<string, string>; cwd?: string; tempDir?: string; label: string },
): StartedChild & { pid(): number | undefined } {
  const spec = launcherSpec(account, argv, opts);
  assertLauncherCommandLine(spec);
  const child = spawn(systemPaths().powershell, launcherArgv(), {
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  let stdout = "";
  let rawStderr = "";
  let exited = false;
  let spawnError: Error | undefined;
  const closed = new Promise<number | null>((resolve) => {
    child.once("close", (code: number | null) => {
      exited = true;
      resolve(code);
    });
  });
  child.on("error", (err) => {
    spawnError = err;
  });
  child.stdin.on("error", () => undefined);
  child.stdin.end(JSON.stringify(spec));
  child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString("utf8")));
  child.stderr.on("data", (chunk: Buffer) => (rawStderr += chunk.toString("utf8")));
  const stderrSoFar = (): string => splitLauncherStderr(rawStderr).stderr;

  const settlesWithin = async (ms: number): Promise<boolean> => {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), ms);
    });
    const settled = await Promise.race([closed.then(() => true), timeout]);
    clearTimeout(timer);
    return settled;
  };

  return {
    child,
    exited: () => exited,
    stdoutSoFar: () => stdout,
    stderrSoFar,
    pid: () => splitLauncherStderr(rawStderr).pid,
    waitForStderr(pattern: RegExp, timeoutMs = CHILD_TIMEOUT_MS): Promise<RegExpMatchArray> {
      return new Promise((resolve, reject) => {
        const exitedFirst = (): Error =>
          new Error(
            `${opts.label} exited (code ${String(child.exitCode)}) before ${String(pattern)} matched` +
              (spawnError ? `: ${spawnError.message}` : ""),
          );
        const already = stderrSoFar().match(pattern);
        if (already) {
          resolve(already);
          return;
        }
        if (exited) {
          reject(exitedFirst());
          return;
        }
        const finish = (): void => {
          clearTimeout(timer);
          child.stderr.off("data", onData);
          child.off("close", onClose);
        };
        const timer = setTimeout(() => {
          finish();
          reject(
            new Error(
              `${opts.label}: ${String(pattern)} did not match within ${String(timeoutMs)} ms`,
            ),
          );
        }, timeoutMs);
        const onData = (): void => {
          const match = stderrSoFar().match(pattern);
          if (match) {
            finish();
            resolve(match);
          }
        };
        const onClose = (): void => {
          finish();
          reject(exitedFirst());
        };
        child.stderr.on("data", onData);
        child.once("close", onClose);
      });
    },
    async stop(graceMs = STOP_GRACE_MS): Promise<number | null> {
      if (exited) return child.exitCode;
      const pid = splitLauncherStderr(rawStderr).pid;
      if (pid === undefined) {
        child.kill();
        if (await settlesWithin(KILL_GRACE_MS)) return child.exitCode;
        throw new Error(`${opts.label}: the launcher printed no pid and did not close`);
      }
      await stopAs(account, pid);
      if (await settlesWithin(graceMs)) return child.exitCode;
      throw new Error(
        `${opts.label} pid ${String(pid)} did not close within ${String(graceMs)} ms of taskkill /f`,
      );
    },
  };
}
