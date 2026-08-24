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

export function runCli(
  args: string[],
  opts: { vaultDir: string; stdin?: string },
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, withVaultDir(args, opts.vaultDir), {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
    if (opts.stdin !== undefined) child.stdin.write(opts.stdin);
    child.stdin.end();
  });
}

export interface CliServer {
  child: ChildProcess;
  exited(): boolean;
  stdoutSoFar(): string;
  stderrSoFar(): string;
  waitForStderr(pattern: RegExp, timeoutMs?: number): Promise<RegExpMatchArray>;
  stop(): Promise<void>;
}

export function startCliServer(args: string[], opts: { vaultDir: string }): CliServer {
  const child = spawn(process.execPath, withVaultDir(args, opts.vaultDir), {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let spawnError: Error | undefined;
  let exited = false;
  child.on("error", (err: Error) => {
    spawnError = err;
  });
  child.once("exit", () => {
    exited = true;
  });
  child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
  child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
  return {
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
    stop(): Promise<void> {
      return new Promise((resolve) => {
        if (child.exitCode !== null || child.signalCode !== null) {
          resolve();
          return;
        }
        if (spawnError) {
          child.kill();
          resolve();
          return;
        }
        child.once("close", () => {
          resolve();
        });
        child.kill();
      });
    },
  };
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
      // already died on its own is the bind collision worth retrying.
      const died = server.exited();
      last = err instanceof Error ? err.message : String(err);
      await server.stop();
      if (!died) throw err;
    }
  }
  throw new Error(`server failed to bind after ${String(attempts)} attempts: ${last}`);
}
