import { spawn } from "node:child_process";
import type { Permission } from "@harpoc/shared";
import type { HarnessVault } from "../vault.js";
import { resolveCliEntry } from "../fixtures.js";
import type { CallOutcome, Surface } from "./surface.js";

export interface CliSurface extends Surface {
  name: "cli";
}

interface CliRun {
  code: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Map a `use_secret` action back onto the CLI flags that build it — the inverse
 * of the command's own `buildAction`. Every context is spelled out: a missing
 * arm would silently produce an action the schema rejects, and the cell would
 * read as a vault failure.
 */
export function actionToFlags(action: unknown): string[] {
  const a = action as Record<string, unknown>;
  const type = String(a["type"] ?? "");
  const flags = ["--action", type];
  const push = (flag: string, value: unknown): void => {
    if (value !== undefined && value !== null) flags.push(flag, String(value));
  };
  const pushEach = (flag: string, values: unknown): void => {
    if (Array.isArray(values)) for (const v of values) flags.push(flag, String(v));
  };

  switch (type) {
    case "http": {
      push("--method", a["method"]);
      push("--url", a["url"]);
      const injection = (a["injection"] ?? {}) as Record<string, unknown>;
      push("--injection", injection["type"]);
      push("--header-name", injection["header_name"]);
      push("--query-param", injection["query_param"]);
      push("--body", a["body"]);
      const headers = (a["headers"] ?? {}) as Record<string, unknown>;
      for (const [key, value] of Object.entries(headers)) {
        flags.push("--header", `${key}: ${String(value)}`);
      }
      push("--follow-redirects", a["follow_redirects"]);
      push("--response-mode", a["response_mode"]);
      break;
    }
    case "process": {
      push("--command", a["command"]);
      pushEach("--arg", a["args"]);
      push("--env-var", a["env_var"]);
      push("--cwd", a["working_directory"]);
      break;
    }
    case "mcp": {
      push("--server", a["server"]);
      push("--tool", a["tool"]);
      if (a["arguments"] !== undefined) flags.push("--arguments", JSON.stringify(a["arguments"]));
      break;
    }
    case "database": {
      push("--engine", a["engine"]);
      push("--host", a["host"]);
      push("--port", a["port"]);
      push("--database", a["database"]);
      push("--query", a["query"]);
      pushEach("--param", a["params"]);
      break;
    }
    case "git": {
      push("--operation", a["operation"]);
      push("--repository", a["repository"]);
      pushEach("--arg", a["args"]);
      push("--cwd", a["working_directory"]);
      break;
    }
    case "ssh": {
      push("--host", a["host"]);
      push("--user", a["user"]);
      push("--command", a["command"]);
      break;
    }
    default:
      throw new Error(`actionToFlags: unsupported action type ${JSON.stringify(type)}`);
  }

  push("--timeout-ms", a["timeout_ms"]);
  return flags;
}

/**
 * The CLI access interface: the real compiled `harpoc` binary, one process per
 * call, over the unlocked session the harness vault wrote.
 *
 * The scoped token rides in the child's ENVIRONMENT rather than argv (argv is
 * readable by other local processes), and it is what makes this surface satisfy
 * C-2 like the other four: the CLI verifies it, enforces its scope and
 * attributes the call to its principal. Passing no token would fall back to the
 * trusted local path, which is a different claim.
 *
 * `--json` is passed explicitly: without it the command prints a human summary,
 * so the surface would be parsing a rendering rather than the result.
 */
export async function startCliSurface(
  vault: HarnessVault,
  principal: string,
  scopes: Permission[],
): Promise<CliSurface> {
  const entry = resolveCliEntry();
  const token = vault.engine.createToken(principal, scopes);

  function run(args: string[]): Promise<CliRun> {
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [entry, "--vault-dir", vault.tmpDir, ...args], {
        env: { ...process.env, HARPOC_TOKEN: token },
        windowsHide: true,
      });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString("utf8")));
      child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, stdout, stderr }));
      // Always close stdin: the hidden-prompt reader resolves on end, and an
      // open stdin hangs the child until the suite times out.
      child.stdin.end();
    });
  }

  return {
    name: "cli",
    interfaceId: "cli",
    auditInterface: "cli",
    principal,
    async callUseSecret(handle, action): Promise<CallOutcome> {
      const result = await run(["secret", "use", handle, ...actionToFlags(action), "--json"]);
      const base = { stdout: result.stdout, stderr: result.stderr };

      if (result.code !== 0) {
        return {
          ok: false,
          text: result.stdout,
          errorText: result.stderr.trim(),
          ...base,
        };
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(result.stdout);
      } catch {
        throw new Error(
          `cli surface: could not parse stdout as JSON (exit 0)\nstdout: ${result.stdout}\nstderr: ${result.stderr}`,
        );
      }
      return { ok: true, result: parsed, text: result.stdout, ...base };
    },
    async close() {
      // One process per call: nothing outlives a call to tear down.
    },
  };
}
