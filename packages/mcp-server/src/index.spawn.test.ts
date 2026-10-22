import { spawn } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

/**
 * I35 (test-review-2026-10-09): `harpoc-mcp`'s own `--allow-tokenless` conflict
 * checks (`index.ts`; `mcp.md` — "`--allow-tokenless` ... conflicts with a
 * supplied token (`--token-file` or ambient `HARPOC_TOKEN`) — both refused",
 * and it has no `--http` mode) driven on the built binary: the documented
 * message and exit 1 before any vault is opened. `cli-options.test.ts` pins the
 * option parsers in-process; this file spawns `dist/index.js`, which
 * `turbo.json`'s `test` task builds first (the `cli-binary.e2e.test.ts`
 * precedent; integration's `mcp-port-refusal.test.ts` is the same pattern for
 * the port and token-file refusals).
 */
const MCP_ENTRY = resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");
const CHILD_TIMEOUT_MS = 25_000;
const KILL_GRACE_MS = 2_000;

interface McpResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** The child is killed at the deadline (SIGKILL after the grace) and the promise rejects after its `close`. */
function spawnMcp(args: string[], env: NodeJS.ProcessEnv, cwd?: string): Promise<McpResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [MCP_ENTRY, ...args], { env, cwd, windowsHide: true });
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
                rejectPromise(
                  new Error(`harpoc-mcp (pid ${String(child.pid)}) did not close after SIGKILL`),
                );
              }, KILL_GRACE_MS),
            );
          }, KILL_GRACE_MS),
        );
      }, CHILD_TIMEOUT_MS),
    );
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (err: Error) => {
      clearTimers();
      rejectPromise(err);
    });
    child.on("close", (code) => {
      clearTimers();
      if (timedOut) {
        rejectPromise(
          new Error(
            `harpoc-mcp (pid ${String(child.pid)}) timed out after ${String(CHILD_TIMEOUT_MS)} ms and was killed (${String(child.signalCode)}); stderr so far:\n${stderr}`,
          ),
        );
        return;
      }
      resolvePromise({ code, stdout, stderr });
    });
    child.stdin.end();
  });
}

let vaultDir: string;

beforeEach(() => {
  vaultDir = mkdtempSync(join(tmpdir(), "harpoc-mcp-spawn-"));
});

afterEach(() => {
  rmSync(vaultDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

/** The parent's environment without an ambient launch token, plus the case's own variables. */
function childEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.HARPOC_TOKEN;
  return { ...env, ...extra };
}

function runMcp(args: string[], env: NodeJS.ProcessEnv): Promise<McpResult> {
  return spawnMcp(["--vault-dir", vaultDir, ...args], env);
}

/** Exit 1 with the message, and nothing of a vault: no locked-vault refusal, no waiver, the directory untouched. */
function expectRefusedBeforeAnyVault(result: McpResult, message: string): void {
  expect(result.code).toBe(1);
  expect(result.stderr).toContain(message);
  expect(result.stderr).not.toContain("Vault is locked");
  expect(result.stderr).not.toContain("WARNING: --allow-tokenless");
  expect(result.stdout).toBe("");
  expect(readdirSync(vaultDir)).toEqual([]);
}

const CONFLICTS_WITH_A_TOKEN =
  "Error: --allow-tokenless conflicts with a launch token (--token-file / HARPOC_TOKEN). Provide one or the other.";

describe("harpoc-mcp --allow-tokenless conflicts (spawned binary, I35)", () => {
  it("refuses --allow-tokenless with --http before any vault is opened", async () => {
    const result = await runMcp(["--allow-tokenless", "--http"], childEnv());
    expectRefusedBeforeAnyVault(
      result,
      "Error: --allow-tokenless is not supported with --http. The Streamable HTTP transport has no tokenless mode.",
    );
  }, 30_000);

  it("refuses --allow-tokenless with an ambient HARPOC_TOKEN before any vault is opened", async () => {
    const result = await runMcp(
      ["--allow-tokenless"],
      childEnv({ HARPOC_TOKEN: "i35.ambient.launch-token" }),
    );
    expectRefusedBeforeAnyVault(result, CONFLICTS_WITH_A_TOKEN);
    expect(result.stderr).not.toContain("i35.ambient.launch-token");
  }, 30_000);

  it("refuses --allow-tokenless with --token-file before the file is read or any vault is opened", async () => {
    const tokenFile = join(vaultDir, "no-such-token");
    const result = await runMcp(["--allow-tokenless", "--token-file", tokenFile], childEnv());
    expectRefusedBeforeAnyVault(result, CONFLICTS_WITH_A_TOKEN);
    expect(result.stderr).not.toContain("Cannot read --token-file");
  }, 30_000);
});

describe("harpoc-mcp --vault-dir without a path (spawned binary, Q4)", () => {
  it.each([
    { label: 'an empty --vault-dir ""', args: ["--vault-dir", ""] },
    { label: "a blank --vault-dir", args: ["--vault-dir", "  "] },
    { label: "a value-less --vault-dir as the last argument", args: ["--vault-dir"] },
    { label: 'an empty --vault-dir "" with --http', args: ["--http", "--vault-dir", ""] },
    { label: "a flag consumed as the path (--vault-dir --http)", args: ["--vault-dir", "--http"] },
  ])(
    "refuses $label before any vault is opened, the working directory and home untouched",
    async ({ args }) => {
      const result = await spawnMcp(
        args,
        childEnv({ HOME: vaultDir, USERPROFILE: vaultDir }),
        vaultDir,
      );
      expectRefusedBeforeAnyVault(result, "Error: --vault-dir requires a path.");
    },
    30_000,
  );
});
