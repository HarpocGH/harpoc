import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";

/** Below the 120 s testTimeout, above every product action budget but git's. */
export const CHILD_TIMEOUT_MS = 110_000;
export const KILL_GRACE_MS = 2_000;
export const STOP_GRACE_MS = 5_000;

export interface ChildRun {
  code: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Spawn `node <argv>`, end its stdin, and settle after `close`. On the deadline
 * the child is killed, then SIGKILLed after a grace, and the promise rejects
 * naming it once it has closed — or, if it still has not closed `KILL_GRACE_MS`
 * after the SIGKILL, rejects saying so.
 */
export function runNodeChild(
  argv: string[],
  opts: { env?: NodeJS.ProcessEnv; timeoutMs?: number; label: string },
): Promise<ChildRun> {
  const timeoutMs = opts.timeoutMs ?? CHILD_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, argv, { env: opts.env, windowsHide: true });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timers: NodeJS.Timeout[] = [];
    const clearTimers = (): void => timers.forEach(clearTimeout);
    timers.push(
      setTimeout(() => {
        timedOut = true;
        child.kill();
        timers.push(
          setTimeout(() => {
            child.kill("SIGKILL");
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
    child.stdout.on("data", (c: Buffer) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
    child.on("error", (err) => {
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
      resolve({ code, stdout, stderr });
    });
    // Always close stdin: the hidden-prompt reader resolves on end, and an
    // open stdin hangs the child until the suite times out.
    child.stdin.end();
  });
}

/** `kill()`, SIGKILL after `graceMs`, reject if it still does not exit. */
export function stopChild(
  child: ChildProcess,
  label: string,
  graceMs = STOP_GRACE_MS,
): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let giveUp: NodeJS.Timeout | undefined;
    const escalate = setTimeout(() => {
      child.kill("SIGKILL");
      giveUp = setTimeout(
        () => reject(new Error(`${label} pid ${String(child.pid)} did not exit after SIGKILL`)),
        KILL_GRACE_MS,
      );
    }, graceMs);
    child.once("exit", () => {
      clearTimeout(escalate);
      if (giveUp !== undefined) clearTimeout(giveUp);
      resolve();
    });
    child.kill();
  });
}
