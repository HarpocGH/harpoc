import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir, userInfo } from "node:os";
import { delimiter, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, onTestFinished, vi } from "vitest";
import { VaultEngine } from "@harpoc/core";
import { SESSION_FILE_NAME, VAULT_DB_NAME } from "@harpoc/shared";
import {
  CLI_ENTRY,
  freePort,
  runCli,
  runCliAs,
  runNode,
  startCliServer,
  startCliServerOnFreePort,
  startNode,
  startNodeAs,
  sudoArgv,
  type CliServer,
} from "./spawn-cli.js";

const PASSWORD = "spawn-cli-helper-pw-1";

let vaultDir: string;

beforeAll(async () => {
  vaultDir = mkdtempSync(join(tmpdir(), "harpoc-spawn-cli-"));
  const engine = new VaultEngine({
    dbPath: join(vaultDir, VAULT_DB_NAME),
    sessionPath: join(vaultDir, SESSION_FILE_NAME),
  });
  await engine.initVault(PASSWORD);
  await engine.destroy();
  const unlock = await runCli(["unlock"], { vaultDir, stdin: `${PASSWORD}\n`, timeoutMs: 110_000 });
  expect(unlock.code).toBe(0);
}, 120_000);

afterAll(() => {
  rmSync(vaultDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("startCliServer", () => {
  it("a spawn failure rejects waitForStderr instead of crashing the worker", async () => {
    const server = startCliServer(["server", "start", "--rest"], { vaultDir: "/nonexistent" });
    server.child.emit("error", new Error("spawn ENOENT"));
    await expect(server.waitForStderr(/never matches/, 500)).rejects.toThrow("spawn ENOENT");
    await server.stop();
    expect(server.child.exitCode !== null || server.child.signalCode !== null).toBe(true);
  });
});

describe("startCliServerOnFreePort", () => {
  it("retries onto a fresh port when the picked one is already taken", async () => {
    const taken = await freePort();
    const blocker = createServer((socket) => {
      socket.destroy();
    });
    await new Promise<void>((resolve, reject) => {
      blocker.once("error", reject);
      blocker.listen(taken, "127.0.0.1", resolve);
    });
    const picks = [taken];
    let started: { server: CliServer; port: number } | undefined;
    try {
      started = await startCliServerOnFreePort(
        (p) => ["server", "start", "--rest", "--port", String(p)],
        { vaultDir, pickPort: async () => picks.shift() ?? (await freePort()) },
      );
      expect(started.port).not.toBe(taken);
      const res = await fetch(`http://127.0.0.1:${String(started.port)}/api/v1/health`);
      await res.text();
      expect(res.status).toBe(200);
    } finally {
      if (started) await started.server.stop();
      await new Promise<void>((resolve) => blocker.close(() => resolve()));
    }
  }, 120_000);

  // RED before the EADDRINUSE discrimination: a child that dies for any other
  // reason was retried on fresh ports as if the port were the problem.
  it("does not retry a child that died for a reason other than EADDRINUSE", async () => {
    const pickPort = vi.fn(freePort);
    await expect(
      startCliServerOnFreePort(
        (port) => ["server", "start", "--rest", "--port", String(port), "--no-such-flag"],
        { vaultDir, pickPort },
      ),
    ).rejects.toThrow(/exited before \/api\/v1\/health/);
    expect(pickPort).toHaveBeenCalledTimes(1);
  });
});

describe("child deadlines (SG-33, W1-11, DM26-11)", () => {
  it("runNode kills a hanging child at its deadline and rejects naming it", async () => {
    const started = Date.now();
    const err = await runNode(["-e", "setInterval(() => {}, 1e6)"], { timeoutMs: 200 }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/timed out after 200 ms and was killed \(SIGTERM\)/);
    const pid = Number(/pid (\d+)/.exec((err as Error).message)?.[1]);
    expect(() => process.kill(pid, 0)).toThrow();
    expect(Date.now() - started).toBeLessThan(5_000);
  }, 10_000);

  it("runCli threads its deadline to the CLI child", async () => {
    const port = await freePort();
    await expect(
      runCli(["server", "start", "--rest", "--port", String(port)], { vaultDir, timeoutMs: 500 }),
    ).rejects.toThrow(/timed out after 500 ms/);
  }, 10_000);

  it("closed() kills a child that ignores stdin EOF at its deadline and rejects naming it", async () => {
    const started = Date.now();
    const s = startNode(["-e", "process.stdin.resume(); setInterval(() => {}, 1e6)"], {
      stdin: "pipe",
    });
    s.child.stdin?.end();
    const err = await s.closed(200).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(
      /did not close within 200 ms and was killed \(SIGTERM\)/,
    );
    const pid = Number(/pid (\d+)/.exec((err as Error).message)?.[1]);
    expect(pid).toBe(s.child.pid);
    expect(() => process.kill(pid, 0)).toThrow();
    expect(Date.now() - started).toBeLessThan(5_000);
  }, 10_000);

  it("closed() resolves the exit of a child that reads its piped stdin to EOF", async () => {
    const s = startNode(
      [
        "-e",
        "process.stdin.on('data', (d) => process.stderr.write(d)); process.stdin.on('end', () => process.exit(3))",
      ],
      { stdin: "pipe" },
    );
    s.child.stdin?.end("ping\n");
    await expect(s.closed(5_000)).resolves.toEqual({ code: 3, signal: null });
    expect(s.stderrSoFar()).toBe("ping\n");
    await expect(s.closed(5_000)).resolves.toEqual({ code: 3, signal: null });
  }, 10_000);

  it("closed() rejects naming a child that exited while a descendant holds its pipes", async () => {
    const started = Date.now();
    const s = startNode([
      "-e",
      "const g = require('node:child_process').spawn(process.execPath, ['-e', 'setTimeout(() => {}, 30_000)'], { stdio: ['ignore', 'inherit', 'inherit'], detached: true, windowsHide: true }); g.unref(); process.stderr.write('grandchild ' + g.pid + '\\n');",
    ]);
    const grand: { pid?: number } = {};
    onTestFinished(async () => {
      if (grand.pid !== undefined) {
        try {
          process.kill(grand.pid);
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== "ESRCH") throw err;
        }
      }
      await s.stop();
    });
    const match = await s.waitForStderr(/grandchild (\d+)/, 5_000);
    const grandPid = Number(match[1]);
    grand.pid = grandPid;
    await vi.waitFor(() => expect(s.child.exitCode).toBe(0), { timeout: 3_000 });
    const err = await s.closed(200).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(
      /exited but its pipes did not close within 2000 ms of the 200 ms deadline/,
    );
    expect(Number(/pid (\d+)/.exec((err as Error).message)?.[1])).toBe(s.child.pid);
    expect(Date.now() - started).toBeLessThan(5_000);
    process.kill(grandPid);
    await expect(s.closed(5_000)).resolves.toEqual({ code: 0, signal: null });
    await vi.waitFor(() => expect(() => process.kill(grandPid, 0)).toThrow(), { timeout: 3_000 });
  }, 10_000);

  it("closed() forwards stop()'s rejection when a killed child's descendant holds its pipes", async () => {
    const s = startNode([
      "-e",
      "const g = require('node:child_process').spawn(process.execPath, ['-e', 'setTimeout(() => {}, 30_000)'], { stdio: ['ignore', 'inherit', 'inherit'], detached: true, windowsHide: true }); g.unref(); process.stderr.write('grandchild ' + g.pid + '\\n'); setInterval(() => {}, 1e6);",
    ]);
    const grand: { pid?: number } = {};
    onTestFinished(async () => {
      if (grand.pid !== undefined) {
        try {
          process.kill(grand.pid);
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== "ESRCH") throw err;
        }
      }
      await s.stop();
    });
    const match = await s.waitForStderr(/grandchild (\d+)/, 5_000);
    const grandPid = Number(match[1]);
    grand.pid = grandPid;
    const called = Date.now();
    const err = await s.closed(200).then(
      () => undefined,
      (e: unknown) => e,
    );
    const elapsed = Date.now() - called;
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/did not close within 4000 ms of kill\(\) and SIGKILL/);
    expect(Number(/pid (\d+)/.exec((err as Error).message)?.[1])).toBe(s.child.pid);
    expect(elapsed).toBeGreaterThanOrEqual(4_000);
    expect(elapsed).toBeLessThan(9_000);
    process.kill(grandPid);
    await expect(s.closed(5_000)).resolves.toBeDefined();
    await vi.waitFor(() => expect(() => process.kill(grandPid, 0)).toThrow(), { timeout: 3_000 });
  }, 15_000);

  it.runIf(process.platform !== "win32")(
    "stop() escalates to SIGKILL when the child ignores SIGTERM",
    async () => {
      const s = startNode([
        "-e",
        "process.on('SIGTERM', () => { process.stderr.write('term\\n'); }); process.stderr.write('ready\\n'); setInterval(() => {}, 1e6)",
      ]);
      try {
        await s.waitForStderr(/ready/, 5_000);
        await s.stop(200);
        expect(s.child.signalCode).toBe("SIGKILL");
        expect(s.stderrSoFar()).toMatch(/term/);
      } finally {
        await s.stop(200);
      }
    },
    10_000,
  );

  it.runIf(process.platform === "win32")(
    "stop() on win32: kill() alone ends a SIGTERM-ignoring child",
    async () => {
      const s = startNode([
        "-e",
        "process.on('SIGTERM', () => {}); process.stderr.write('ready\\n'); setInterval(() => {}, 1e6)",
      ]);
      try {
        await s.waitForStderr(/ready/, 5_000);
        await s.stop(200);
        expect(s.child.signalCode).toBe("SIGTERM");
      } finally {
        await s.stop(200);
      }
    },
    10_000,
  );
});

describe("sudo -n -u children (the two-UID suite)", () => {
  it("sudoArgv runs the argv as the user, non-interactively, with no shell and no assignment", () => {
    expect(sudoArgv("vault", ["/usr/bin/id", "-u"])).toEqual([
      "-n",
      "-u",
      "vault",
      "--",
      "/usr/bin/id",
      "-u",
    ]);
  });

  it("sudoArgv carries named variables through /usr/bin/env, past sudo's env_reset", () => {
    expect(sudoArgv("vault", ["/bin/true"], { HARPOC_SESSION_KEYSTORE: "off" })).toEqual([
      "-n",
      "-u",
      "vault",
      "--",
      "/usr/bin/env",
      "HARPOC_SESSION_KEYSTORE=off",
      "/bin/true",
    ]);
  });

  describe.skipIf(process.platform === "win32")(
    "through a fake sudo on PATH (POSIX: spawn runs the script without a shell)",
    () => {
      let fakeDir: string;
      const savedPath = process.env["PATH"];

      beforeAll(() => {
        fakeDir = mkdtempSync(join(tmpdir(), "harpoc-fake-sudo-"));
      });

      afterAll(() => {
        process.env["PATH"] = savedPath;
        rmSync(fakeDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      });

      function installFakeSudo(lines: string[]): void {
        const path = join(fakeDir, "sudo");
        writeFileSync(path, `${lines.join("\n")}\n`);
        chmodSync(path, 0o755);
        process.env["PATH"] = `${fakeDir}${delimiter}${savedPath ?? ""}`;
      }

      it("runCliAs spawns sudo with node, the CLI entry and the forwarded keystore switch", async () => {
        installFakeSudo(["#!/bin/sh", `for a in "$@"; do printf '%s\\n' "$a"; done`]);
        const run = await runCliAs("vault", ["--version"], { vaultDir: "/v" });
        expect(run.code).toBe(0);
        expect(run.stdout.split("\n").slice(0, -1)).toEqual([
          "-n",
          "-u",
          "vault",
          "--",
          "/usr/bin/env",
          "HARPOC_SESSION_KEYSTORE=off",
          process.execPath,
          CLI_ENTRY,
          "--vault-dir",
          "/v",
          "--version",
        ]);
      });

      it("startNodeAs' stop() signals the command as its user, not the sudo process", async () => {
        installFakeSudo([
          "#!/bin/sh",
          'trap "" TERM',
          "shift 4",
          '"$@" &',
          "child=$!",
          'wait "$child"',
          "exit $?",
        ]);
        const s = startNodeAs(userInfo().username, [
          "-e",
          "process.on('SIGTERM', () => { process.stderr.write('term\\n'); process.exit(0); }); process.stderr.write('ready ' + process.pid + '\\n'); setInterval(() => {}, 1e6)",
        ]);
        const command: { pid?: number } = {};
        onTestFinished(async () => {
          if (command.pid !== undefined) {
            try {
              process.kill(command.pid, "SIGKILL");
            } catch (err) {
              if ((err as NodeJS.ErrnoException).code !== "ESRCH") throw err;
            }
          }
          await s.stop(200);
        });
        command.pid = Number((await s.waitForStderr(/ready (\d+)/, 5_000))[1]);
        await s.stop(2_000);
        expect(s.stderrSoFar()).toMatch(/term/);
        expect(s.child.exitCode).toBe(0);
      }, 15_000);
    },
  );
});
