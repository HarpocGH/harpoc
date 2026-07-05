import type { Command } from "commander";
import { useSecretActionSchema } from "@harpoc/shared";
import type { UseSecretAction } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson } from "../../utils/output.js";

function collect(value: string, acc: string[]): string[] {
  acc.push(value);
  return acc;
}

interface UseOptions {
  action?: string;
  method?: string;
  url?: string;
  injection?: string;
  headerName?: string;
  queryParam?: string;
  body?: string;
  header?: string[];
  followRedirects?: string;
  command?: string;
  arg?: string[];
  envVar?: string;
  cwd?: string;
  json?: boolean;
}

export function registerSecretUseCommand(secret: Command): void {
  secret
    .command("use <handle>")
    .description("Use a secret via an HTTP request or process execution (value never exposed)")
    .option("--action <type>", "Action type: http | process", "http")
    // HTTP action
    .option("--method <method>", "HTTP method", "GET")
    .option("--url <url>", "Target URL (http action)")
    .option("--injection <type>", "Injection: bearer | header | query | basic_auth", "bearer")
    .option("--header-name <name>", "Header name (injection=header)")
    .option("--query-param <name>", "Query parameter (injection=query)")
    .option("--body <body>", "Request body (http action)")
    .option("--header <kv>", "Extra request header 'Key: Value' (repeatable)", collect, [])
    .option("--follow-redirects <policy>", "Redirect policy: same-origin | none | any")
    // Process action
    .option("--command <command>", "Command to run (process action)")
    .option("--arg <arg>", "Command argument (repeatable)", collect, [])
    .option("--env-var <name>", "Env var to inject the secret into (process action)")
    .option("--cwd <dir>", "Working directory (process action)")
    .option("--json", "Output as JSON")
    .action(async (handle: string, options: UseOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const parsed = useSecretActionSchema.safeParse(buildAction(options));
        if (!parsed.success) {
          throw new Error(parsed.error.issues.map((i) => i.message).join(", "));
        }

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const result = await engine.useSecret(handle, parsed.data as UseSecretAction);
          printJson(result);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}

function buildAction(options: UseOptions): Record<string, unknown> {
  if (options.action === "process") {
    return {
      type: "process",
      command: options.command,
      args: options.arg ?? [],
      env_var: options.envVar,
      working_directory: options.cwd,
    };
  }

  const headers: Record<string, string> = {};
  for (const entry of options.header ?? []) {
    const idx = entry.indexOf(":");
    if (idx === -1) continue;
    headers[entry.slice(0, idx).trim()] = entry.slice(idx + 1).trim();
  }

  const injection: Record<string, unknown> = { type: options.injection };
  if (options.headerName) injection.header_name = options.headerName;
  if (options.queryParam) injection.query_param = options.queryParam;

  return {
    type: "http",
    method: options.method,
    url: options.url,
    headers: Object.keys(headers).length > 0 ? headers : undefined,
    body: options.body,
    injection,
    follow_redirects: options.followRedirects,
  };
}
