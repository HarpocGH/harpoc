import { spawn, type ChildProcess } from "node:child_process";
import { createRequire } from "node:module";
import { createServer, type AddressInfo } from "node:net";
import { dirname, join } from "node:path";

const require_ = createRequire(import.meta.url);
export const CLI_ENTRY = join(
  dirname(require_.resolve("@harpoc/cli/package.json")),
  "dist",
  "index.js",
);

// Global option, so it must precede the subcommand.
const withVaultDir = (args: string[], vaultDir: string): string[] => [
  CLI_ENTRY,
  "--vault-dir",
  vaultDir,
  ...args,
];

export const CHILD_TIMEOUT_MS = 25_000;
export const KILL_GRACE_MS = 2_000;
export const STOP_GRACE_MS = 5_000;
export const RAW_GET_TIMEOUT_MS = 10_000;

export function runNode(
  argv: string[],
  opts: { stdin?: string; timeoutMs?: number } = {},
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const timeoutMs = opts.timeoutMs ?? CHILD_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, argv, {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timers: NodeJS.Timeout[] = [];
    const clearTimers = (): void => {
      for (const timer of timers) clearTimeout(timer);
    };
    timers.push(
      setTimeout(() => {
        timedOut = true;
        child.kill();
        timers.push(
          setTimeout(() => {
            child.kill("SIGKILL");
            timers.push(
              setTimeout(() => {
                reject(new Error(`child pid ${String(child.pid)} did not close after SIGKILL`));
              }, KILL_GRACE_MS),
            );
          }, KILL_GRACE_MS),
        );
      }, timeoutMs),
    );
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
    child.on("error", (err: Error) => {
      clearTimers();
      reject(err);
    });
    child.on("close", (code) => {
      clearTimers();
      if (timedOut) {
        reject(
          new Error(
            `child pid ${String(child.pid)} timed out after ${String(timeoutMs)} ms and was killed (${String(child.signalCode)}); stdout so far:\n${stdout}\nstderr so far:\n${stderr}`,
          ),
        );
        return;
      }
      resolve({ code, stdout, stderr });
    });
    if (opts.stdin !== undefined) child.stdin.write(opts.stdin);
    child.stdin.end();
  });
}

export function runCli(
  args: string[],
  opts: { vaultDir: string; stdin?: string; timeoutMs?: number },
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return runNode(withVaultDir(args, opts.vaultDir), {
    stdin: opts.stdin,
    timeoutMs: opts.timeoutMs,
  });
}

export interface CliServer {
  child: ChildProcess;
  exited(): boolean;
  stdoutSoFar(): string;
  stderrSoFar(): string;
  waitForStderr(pattern: RegExp, timeoutMs?: number): Promise<RegExpMatchArray>;
  closed(timeoutMs?: number): Promise<ChildClose>;
  stop(graceMs?: number): Promise<void>;
}

export interface ChildClose {
  code: number | null;
  signal: NodeJS.Signals | null;
}

export interface StartNodeOptions {
  stdin?: "ignore" | "pipe";
  env?: NodeJS.ProcessEnv;
}

export function startCliServer(
  args: string[],
  opts: { vaultDir: string } & StartNodeOptions,
): CliServer {
  return startNode(withVaultDir(args, opts.vaultDir), { stdin: opts.stdin, env: opts.env });
}

export function startNode(argv: string[], opts: StartNodeOptions = {}): CliServer {
  const child = spawn(process.execPath, argv, {
    stdio: [opts.stdin ?? "ignore", "pipe", "pipe"],
    env: opts.env,
  });
  let stdout = "";
  let stderr = "";
  let spawnError: Error | undefined;
  let exited = false;
  child.on("error", (err: Error) => {
    spawnError = err;
  });
  child.once("close", () => {
    exited = true;
  });
  child.stdout?.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
  child.stderr?.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
  const server: CliServer = {
    child,
    exited: () => exited,
    stdoutSoFar: () => stdout,
    stderrSoFar: () => stderr,
    waitForStderr(pattern: RegExp, timeoutMs = 30_000): Promise<RegExpMatchArray> {
      return new Promise((resolve, reject) => {
        const started = Date.now();
        const poll = setInterval(() => {
          if (spawnError) {
            clearInterval(poll);
            reject(new Error(`CLI spawn failed: ${spawnError.message}; stderr so far:\n${stderr}`));
            return;
          }
          const match = stderr.match(pattern);
          if (match) {
            clearInterval(poll);
            resolve(match);
            return;
          }
          if (exited) {
            clearInterval(poll);
            reject(
              new Error(
                `CLI exited before ${String(pattern)} matched; stdout:\n${stdout}\nstderr:\n${stderr}`,
              ),
            );
            return;
          }
          if (Date.now() - started > timeoutMs) {
            clearInterval(poll);
            reject(
              new Error(`Timed out waiting for ${String(pattern)}; stderr so far:\n${stderr}`),
            );
          }
        }, 50);
      });
    },
    closed(timeoutMs = CHILD_TIMEOUT_MS): Promise<ChildClose> {
      return new Promise((resolve, reject) => {
        if (exited) {
          resolve({ code: child.exitCode, signal: child.signalCode });
          return;
        }
        let timedOut = false;
        let exitedFirst = false;
        let pipeGrace: NodeJS.Timeout | undefined;
        const deadline = setTimeout(() => {
          timedOut = true;
          exitedFirst = child.exitCode !== null || child.signalCode !== null;
          server.stop(KILL_GRACE_MS).then(() => {
            if (exited) return;
            pipeGrace = setTimeout(() => {
              reject(
                new Error(
                  `CLI child pid ${String(child.pid)} exited but its pipes did not close within ${String(KILL_GRACE_MS)} ms of the ${String(timeoutMs)} ms deadline; stderr so far:\n${stderr}`,
                ),
              );
            }, KILL_GRACE_MS);
          }, reject);
        }, timeoutMs);
        child.once("close", (code: number | null, signal: NodeJS.Signals | null) => {
          clearTimeout(deadline);
          clearTimeout(pipeGrace);
          if (timedOut && exitedFirst) {
            reject(
              new Error(
                `CLI child pid ${String(child.pid)} exited with code ${String(code)} but its pipes closed only after the ${String(timeoutMs)} ms deadline; stderr so far:\n${stderr}`,
              ),
            );
            return;
          }
          if (timedOut) {
            reject(
              new Error(
                `CLI child pid ${String(child.pid)} did not close within ${String(timeoutMs)} ms and was killed (${String(signal)}); stderr so far:\n${stderr}`,
              ),
            );
            return;
          }
          resolve({ code, signal });
        });
      });
    },
    stop(graceMs = STOP_GRACE_MS): Promise<void> {
      return new Promise((resolve, reject) => {
        if (child.exitCode !== null || child.signalCode !== null) {
          resolve();
          return;
        }
        // No pid: the spawn itself failed and there is no process to wait for.
        if (child.pid === undefined) {
          child.kill();
          resolve();
          return;
        }
        const timers: NodeJS.Timeout[] = [];
        child.once("close", () => {
          for (const timer of timers) clearTimeout(timer);
          resolve();
        });
        child.kill();
        timers.push(
          setTimeout(() => {
            child.kill("SIGKILL");
            timers.push(
              setTimeout(() => {
                reject(
                  new Error(
                    `CLI child pid ${String(child.pid)} did not close within ${String(2 * graceMs)} ms of kill() and SIGKILL`,
                  ),
                );
              }, graceMs),
            );
          }, graceMs),
        );
      });
    },
  };
  return server;
}

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as AddressInfo;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

// The startup banner is printed before the bind resolves, so it is not a
// readiness signal; the unauthenticated health route is.
async function waitForHealth(port: number, server: CliServer, timeoutMs = 30_000): Promise<void> {
  const started = Date.now();
  for (;;) {
    if (server.exited()) {
      throw new Error(
        `CLI exited before /api/v1/health answered on port ${String(port)}; stdout:\n${server.stdoutSoFar()}\nstderr:\n${server.stderrSoFar()}`,
      );
    }
    const res = await fetch(`http://127.0.0.1:${String(port)}/api/v1/health`, {
      signal: AbortSignal.timeout(2_000),
    }).catch(() => undefined);
    if (res) {
      await res.text();
      if (res.ok) return;
    }
    if (Date.now() - started > timeoutMs) {
      throw new Error(
        `health probe timed out on port ${String(port)}; stderr so far:\n${server.stderrSoFar()}`,
      );
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 50));
  }
}

export async function startCliServerOnFreePort(
  buildArgs: (port: number) => string[],
  opts: { vaultDir: string; attempts?: number; pickPort?: () => Promise<number> },
): Promise<{ server: CliServer; port: number }> {
  const attempts = opts.attempts ?? 3;
  const pickPort = opts.pickPort ?? freePort;
  let last = "";
  for (let attempt = 0; attempt < attempts; attempt++) {
    const port = await pickPort();
    const server = startCliServer(buildArgs(port), { vaultDir: opts.vaultDir });
    try {
      await waitForHealth(port, server);
      return { server, port };
    } catch (err) {
      // Read before stop(): stop() kills the child, so only a child that had
      // already died on its own — and died on the bind — is worth retrying.
      const collided = server.exited() && /EADDRINUSE/.test(server.stderrSoFar());
      last = err instanceof Error ? err.message : String(err);
      await server.stop();
      if (!collided) throw err;
    }
  }
  throw new Error(`server failed to bind after ${String(attempts)} attempts: ${last}`);
}
