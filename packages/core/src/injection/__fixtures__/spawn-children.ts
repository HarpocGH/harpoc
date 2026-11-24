import { existsSync, watch } from "node:fs";
import { dirname } from "node:path";

export const STDIN_ECHO_SCRIPT = "process.stdin.pipe(process.stdout)";

export const STDIN_OPEN_PIPE_SCRIPT =
  'let seen = "open"; process.stdin.on("data", () => { seen = "data"; }); process.stdin.on("end", () => { seen = "end"; }); setTimeout(() => { process.stdout.write(seen); process.exit(0); }, 500);';

/**
 * The child's marker — the empty file its stdout write's callback creates, so "before" is in the
 * pipe, or the pid file renamed into place whole — rejected when the spawn settles first or after
 * `boundMs` on `setInterval`, which no row fakes.
 */
export function untilWritten(
  path: string,
  spawned: Promise<unknown>,
  boundMs: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const watcher = watch(dirname(path), () => {
      if (existsSync(path)) end();
    });
    const bound = setInterval(() => {
      if (existsSync(path)) end();
      else end(new Error(`the child's marker did not appear within ${String(boundMs)} ms`));
    }, boundMs);
    const end = (err?: Error): void => {
      watcher.close();
      clearInterval(bound);
      if (err) reject(err);
      else resolve();
    };
    const settled = (): void => {
      if (existsSync(path)) end();
      else end(new Error("the spawn settled before the child's marker appeared"));
    };
    void spawned.then(settled, settled);
    if (existsSync(path)) end();
  });
}
