import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { CHILD_TIMEOUT_MS, KILL_GRACE_MS, STOP_GRACE_MS } from "./child.js";
import type { ChildRun } from "./child.js";

const VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

export interface RunOptions {
  stdin?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  label: string;
  /** How each of the deadline's signals reaches the command; by default `child.kill(signal)`. */
  deliver?: (signal: "SIGTERM" | "SIGKILL", child: ChildProcess) => void | Promise<void>;
}

export interface AsUserOptions {
  stdin?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  label?: string;
}

/**
 * The `sudo` argv that runs `argv` as `user`: `-n` (never prompt), `--`, then
 * each variable as a `NAME=value` argument of `/usr/bin/env` — never a shell
 * string, and never `--preserve-env`, which needs the variable in the runner's
 * own environment and a sudoers SETENV grant (`deployment-models.md` Rules).
 * No value handed here may be a secret: `sudo`'s argv stays world-readable in
 * `/proc/<pid>/cmdline` for as long as the command runs.
 */
export function sudoArgv(user: string, argv: string[], env: Record<string, string> = {}): string[] {
  const assignments = Object.entries(env).map(([name, value]) => {
    if (!VARIABLE_NAME.test(name)) {
      throw new Error(`sudoArgv: ${JSON.stringify(name)} is not a variable name`);
    }
    return `${name}=${value}`;
  });
  if (assignments.length > 0 && (argv[0] ?? "").includes("=")) {
    throw new Error("sudoArgv: env would read a command containing '=' as one more assignment");
  }
  return [
    "-n",
    "-u",
    user,
    "--",
    ...(assignments.length > 0 ? ["/usr/bin/env", ...assignments] : []),
    ...argv,
  ];
}

/**
 * `command` with `argv`, no shell, `stdin` written and closed, settled after
 * `close` with both streams decoded once — `runNodeChild`'s deadline for any
 * command: killed at `timeoutMs`, SIGKILLed after a grace, rejected naming the
 * label (never the child's output) once it has closed.
 */
export function runCommand(command: string, argv: string[], opts: RunOptions): Promise<ChildRun> {
  const timeoutMs = opts.timeoutMs ?? CHILD_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    const child = spawn(command, argv, {
      env: opts.env,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let timedOut = false;
    let killError: Error | undefined;
    const timers: NodeJS.Timeout[] = [];
    const clearTimers = (): void => timers.forEach(clearTimeout);
    const deliver =
      opts.deliver ??
      ((signal: "SIGTERM" | "SIGKILL"): void => {
        if (!child.kill(signal) && child.exitCode === null && child.signalCode === null) {
          throw killError ?? new Error(`kill ${signal} was not delivered`);
        }
      });
    const send = (signal: "SIGTERM" | "SIGKILL"): void => {
      Promise.resolve()
        .then(() => deliver(signal, child))
        .catch((cause: unknown) => {
          clearTimers();
          reject(
            new Error(
              `${opts.label} pid ${String(child.pid)}: the deadline's ${signal} could not be delivered`,
              { cause },
            ),
          );
        });
    };
    timers.push(
      setTimeout(() => {
        timedOut = true;
        send("SIGTERM");
        timers.push(
          setTimeout(() => {
            send("SIGKILL");
            timers.push(
              setTimeout(
                () =>
                  reject(
                    new Error(`${opts.label} pid ${String(child.pid)} did not close after SIGKILL`),
                  ),
                KILL_GRACE_MS,
              ),
            );
          }, KILL_GRACE_MS),
        );
      }, timeoutMs),
    );
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    // A child that exits without reading its input raises EPIPE here; its exit code answers.
    child.stdin.on("error", () => undefined);
    child.on("error", (err: NodeJS.ErrnoException) => {
      if (timedOut && err.syscall === "kill") {
        killError = err;
        return;
      }
      clearTimers();
      reject(err);
    });
    child.on("close", (code) => {
      clearTimers();
      if (timedOut) {
        reject(
          new Error(
            `${opts.label} pid ${String(child.pid)} timed out after ${String(timeoutMs)} ms and was killed`,
          ),
        );
        return;
      }
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
    child.stdin.end(opts.stdin ?? "");
  });
}

/**
 * `argv` run as `user` through `sudo -n -u`, under `runCommand`'s deadline. The deadline's signals
 * are delivered to the command as `user` through `sudo -n -u <user> kill`, because the setuid
 * `sudo` process is not the invoking user's to signal (integration's `spawn-cli.ts:215–216`
 * precedent); a command that outlives both is swept by the deployment's teardown
 * (`pkill -KILL -u <user> -f harpoc-b6`).
 */
export function runAs(user: string, argv: string[], opts: AsUserOptions = {}): Promise<ChildRun> {
  return runCommand("sudo", sudoArgv(user, argv, opts.env), {
    stdin: opts.stdin,
    timeoutMs: opts.timeoutMs,
    label: opts.label ?? `sudo -u ${user} ${argv[0] ?? ""}`,
    deliver: async (signal, child) => {
      if (child.pid !== undefined) await signalCommandAs(user, child.pid, signal);
    },
  });
}

export interface StartedChild {
  readonly child: ChildProcess;
  exited(): boolean;
  stdoutSoFar(): string;
  stderrSoFar(): string;
  waitForStderr(pattern: RegExp, timeoutMs?: number): Promise<RegExpMatchArray>;
  /** SIGTERM as the user, SIGKILL after `graceMs`; resolves sudo's exit code once it has closed. */
  stop(graceMs?: number): Promise<number | null>;
}

/**
 * A long-running command as `user`. sudo forks the command and waits for it;
 * a signal goes to that command — found as `user`'s child of the sudo process,
 * or of sudo's monitor where sudo runs one — through `kill` run as `user`,
 * never to the setuid sudo process (integration's `startNodeAs` precedent).
 */
export function startAs(
  user: string,
  argv: string[],
  opts: { env?: Record<string, string>; label: string },
): StartedChild {
  const child = spawn("sudo", sudoArgv(user, argv, opts.env), {
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
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
  child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString("utf8")));
  child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));

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
    stderrSoFar: () => stderr,
    waitForStderr(pattern: RegExp, timeoutMs = CHILD_TIMEOUT_MS): Promise<RegExpMatchArray> {
      return new Promise((resolve, reject) => {
        const exitedFirst = (): Error =>
          new Error(
            `${opts.label} exited (code ${String(child.exitCode)}) before ${String(pattern)} matched` +
              (spawnError ? `: ${spawnError.message}` : ""),
          );
        const already = stderr.match(pattern);
        if (already) {
          resolve(already);
          return;
        }
        if (exited) {
          reject(exitedFirst());
          return;
        }
        const timer = setTimeout(() => {
          finish();
          reject(
            new Error(
              `${opts.label}: ${String(pattern)} did not match within ${String(timeoutMs)} ms`,
            ),
          );
        }, timeoutMs);
        const onData = (): void => {
          const match = stderr.match(pattern);
          if (match) {
            finish();
            resolve(match);
          }
        };
        const onClose = (): void => {
          finish();
          reject(exitedFirst());
        };
        const finish = (): void => {
          clearTimeout(timer);
          child.stderr.off("data", onData);
          child.off("close", onClose);
        };
        child.stderr.on("data", onData);
        child.once("close", onClose);
      });
    },
    async stop(graceMs = STOP_GRACE_MS): Promise<number | null> {
      if (exited) return child.exitCode;
      if (child.pid === undefined) return null;
      await signalCommandAs(user, child.pid, "SIGTERM");
      if (await settlesWithin(graceMs)) return child.exitCode;
      await signalCommandAs(user, child.pid, "SIGKILL");
      if (await settlesWithin(graceMs)) return child.exitCode;
      throw new Error(
        `${opts.label} pid ${String(child.pid)} did not close within ${String(2 * graceMs)} ms of SIGTERM and SIGKILL`,
      );
    },
  };
}

async function childPids(parent: number, user?: string): Promise<string[]> {
  const listed = await runCommand(
    "pgrep",
    [...(user === undefined ? [] : ["-u", user]), "-P", String(parent)],
    { label: `pgrep -P ${String(parent)}` },
  );
  if (listed.code !== 0 && listed.code !== 1) {
    throw new Error(`pgrep -P ${String(parent)} exited ${String(listed.code)}`);
  }
  return listed.stdout.split("\n").filter((line) => line.trim() !== "");
}

async function signalCommandAs(
  user: string,
  sudoPid: number,
  signal: NodeJS.Signals,
): Promise<void> {
  const targets = await childPids(sudoPid, user);
  if (targets.length === 0) {
    for (const monitor of await childPids(sudoPid)) {
      targets.push(...(await childPids(Number(monitor), user)));
    }
  }
  for (const pid of targets) {
    await runAs(user, ["kill", "-s", signal.replace(/^SIG/, ""), pid], { label: `kill ${pid}` });
  }
}
