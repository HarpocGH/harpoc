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
  waitForStderr(pattern: RegExp, timeoutMs?: number): Promise<RegExpMatchArray>;
  stop(): Promise<void>;
}

export function startCliServer(args: string[], opts: { vaultDir: string }): CliServer {
  const child = spawn(process.execPath, withVaultDir(args, opts.vaultDir), {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
  return {
    child,
    waitForStderr(pattern: RegExp, timeoutMs = 30_000): Promise<RegExpMatchArray> {
      return new Promise((resolve, reject) => {
        const started = Date.now();
        const poll = setInterval(() => {
          const match = stderr.match(pattern);
          if (match) {
            clearInterval(poll);
            resolve(match);
          } else if (Date.now() - started > timeoutMs) {
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
