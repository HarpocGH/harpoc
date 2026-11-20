import { spawn } from "node:child_process";
import { mkdtempSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  expectAbsent,
  FORBIDDEN_MODULE_MARKER,
  resolveTripwireImportUrl,
} from "@harpoc/test-utils";

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
function spawnMcp(
  args: string[],
  env: NodeJS.ProcessEnv,
  cwd?: string,
  nodeArgs: string[] = [],
): Promise<McpResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [...nodeArgs, MCP_ENTRY, ...args], {
      env,
      cwd,
      windowsHide: true,
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
const TOKENLESS_AMBIENT_TOKEN = "i35.ambient.launch-token";
const URL_PASSWORD = "s3cret";
const BRIDGE_AMBIENT_TOKEN = "b1.ambient.launch-token";
const BRIDGE_FILE_TOKEN = "b1.bridge.token";

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
      childEnv({ HARPOC_TOKEN: TOKENLESS_AMBIENT_TOKEN }),
    );
    expectAbsent(result.stderr, TOKENLESS_AMBIENT_TOKEN);
    expectRefusedBeforeAnyVault(result, CONFLICTS_WITH_A_TOKEN);
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

/**
 * B1: `harpoc-mcp --url` is the stdio→REST bridge. Its refusals, like the
 * stdio ones, land before the token file is read or any vault is opened; each
 * runs from an empty working directory and home, so a binary that ignored
 * `--url` would meet no vault either. An ambient HARPOC_TOKEN rides along and
 * is no channel for `--url`.
 */
describe("harpoc-mcp --url refusals (spawned binary, B1)", () => {
  it.each([
    {
      label: "--http",
      args: ["--url", "http://127.0.0.1:3000", "--http", "--token-file", "TOKEN"],
      message:
        "Error: --url is not supported with --http. The bridge serves stdio only; the Streamable HTTP listener runs in the vault's own process.",
    },
    {
      label: "--vault-dir",
      args: ["--url", "http://127.0.0.1:3000", "--vault-dir", "VAULT", "--token-file", "TOKEN"],
      message:
        "Error: --url conflicts with --vault-dir. The bridge opens no vault; the REST server at --url holds it.",
    },
    {
      label: "--allow-tokenless",
      args: ["--url", "http://127.0.0.1:3000", "--allow-tokenless"],
      message:
        "Error: --allow-tokenless is not supported with --url. The bridge holds no engine; the REST server verifies the token on every request.",
    },
    {
      label: "no --token-file",
      args: ["--url", "http://127.0.0.1:3000"],
      message:
        "Error: --url requires --token-file <path>. The REST server verifies that token on every request.",
    },
    {
      label: "a scheme other than http(s)",
      args: ["--url", "ftp://127.0.0.1:3000", "--token-file", "TOKEN"],
      message: "Error: --url must use http: or https:.",
    },
    {
      label: "credentials in the URL",
      args: ["--url", "http://agent:s3cret@127.0.0.1:3000", "--token-file", "TOKEN"],
      message: "Error: --url must not carry credentials; pass the token with --token-file.",
    },
  ])(
    "refuses --url with $label before the token file is read or any vault is opened",
    async ({ args, message }) => {
      const tokenFile = join(vaultDir, "no-such-token");
      const result = await spawnMcp(
        args.map((arg) => (arg === "TOKEN" ? tokenFile : arg === "VAULT" ? vaultDir : arg)),
        childEnv({
          HARPOC_TOKEN: "b1.ambient.launch-token",
          HOME: vaultDir,
          USERPROFILE: vaultDir,
        }),
        vaultDir,
      );
      expectAbsent(result.stderr, URL_PASSWORD);
      expectAbsent(result.stderr, BRIDGE_AMBIENT_TOKEN);
      expectRefusedBeforeAnyVault(result, message);
      expect(result.stderr).not.toContain("Cannot read --token-file");
    },
    30_000,
  );
});

/**
 * B1: the bridge process never resolves `@harpoc/core` — the confinement
 * test's resolve hook (`@harpoc/test-utils`), preloaded with `--import` so
 * the binary stays its own entry. The REST server is never contacted: the
 * bridge forwards nothing until a tool is called, and stdin's EOF (the
 * spawner ends it at once) is its graceful stop.
 */
describe("harpoc-mcp --url holds no engine (spawned binary under the resolve-hook tripwire, B1)", () => {
  const tripwire = resolveTripwireImportUrl(["@harpoc/core"]);

  it("serves stdio as the bridge without resolving @harpoc/core and stops at stdin EOF", async () => {
    const tokenFile = join(vaultDir, "token.jwt");
    writeFileSync(tokenFile, "b1.bridge.token\n", "utf8");
    const result = await spawnMcp(
      ["--url", "http://127.0.0.1:1", "--token-file", tokenFile],
      childEnv({ HOME: vaultDir, USERPROFILE: vaultDir }),
      vaultDir,
      ["--import", tripwire],
    );
    expectAbsent(result.stderr, BRIDGE_FILE_TOKEN);
    expect(result.stderr).not.toContain(FORBIDDEN_MODULE_MARKER);
    expect(result.stderr).toContain("Harpoc MCP bridge → http://127.0.0.1:1 (stdio)");
    expect(result.stdout).toBe("");
    expect(result.code).toBe(0);
    expect(readdirSync(vaultDir)).toEqual(["token.jwt"]);
  }, 30_000);

  it("control: the engine path resolves @harpoc/core under the same hook", async () => {
    const result = await spawnMcp(
      [],
      childEnv({ HARPOC_TOKEN: "b1.control.token", HOME: vaultDir, USERPROFILE: vaultDir }),
      vaultDir,
      ["--import", tripwire],
    );
    expect(result.stderr).toContain(`${FORBIDDEN_MODULE_MARKER} @harpoc/core`);
    expect(result.stderr).toContain("Error: Vault is locked.");
    expect(result.code).toBe(1);
  }, 30_000);
});

/**
 * The listener's engine is a daemon's: `--http` declares it, with no path of its own, once the
 * engine is built; on its standard input alone the server declares nothing. A preload wraps
 * `declareDaemon` on the engine module the binary itself resolves (core's entry through
 * mcp-server's own link, with links followed as Node's resolver follows them) and writes each call
 * to fd 2; both starts then meet the empty directory's locked vault.
 */
describe("harpoc-mcp declares the daemon under --http alone (spawned binary)", () => {
  const DECLARED = "DAEMON_DECLARED";
  const coreEntry = pathToFileURL(
    realpathSync(
      resolve(dirname(MCP_ENTRY), "..", "node_modules", "@harpoc", "core", "dist", "index.js"),
    ),
  ).href;
  const preload = `data:text/javascript,${encodeURIComponent(
    'import { writeSync } from "node:fs";\n' +
      `import { VaultEngine } from ${JSON.stringify(coreEntry)};\n` +
      "const declare = VaultEngine.prototype.declareDaemon;\n" +
      "VaultEngine.prototype.declareDaemon = function (paths) {\n" +
      `  writeSync(2, "${DECLARED} " + JSON.stringify(paths) + "\\n");\n` +
      "  return declare.call(this, paths);\n" +
      "};\n",
  )}`;

  it("harpoc-mcp --http declares the daemon with no path, once, before the vault is found locked", async () => {
    const result = await spawnMcp(
      ["--vault-dir", vaultDir, "--http"],
      childEnv({ HOME: vaultDir, USERPROFILE: vaultDir }),
      vaultDir,
      ["--import", preload],
    );
    expect(result.stderr).toContain(`${DECLARED} {"protectedDirs":[],"protectedFiles":[]}\n`);
    expect(result.stderr.split(DECLARED).length - 1).toBe(1);
    expect(result.stderr).toContain("Error: Vault is locked.");
    expect(result.code).toBe(1);
  }, 30_000);

  it("harpoc-mcp on its standard input alone declares no daemon", async () => {
    const result = await spawnMcp(
      ["--vault-dir", vaultDir],
      childEnv({ HOME: vaultDir, USERPROFILE: vaultDir }),
      vaultDir,
      ["--import", preload],
    );
    expect(result.stderr).not.toContain(DECLARED);
    expect(result.stderr).toContain("Error: Vault is locked.");
    expect(result.code).toBe(1);
  }, 30_000);
});
