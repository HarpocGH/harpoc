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
  server?: string;
  tool?: string;
  arguments?: string;
  engine?: string;
  host?: string;
  port?: string;
  database?: string;
  query?: string;
  param?: string[];
  operation?: string;
  repository?: string;
  user?: string;
  json?: boolean;
}

export function registerSecretUseCommand(secret: Command): void {
  secret
    .command("use <handle>")
    .description(
      "Use a secret via an HTTP request, process, MCP tool call, database query, Git operation or SSH command (value never exposed)",
    )
    .option("--action <type>", "Action type: http | process | mcp | database | git | ssh", "http")
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
    // MCP action
    .option("--server <name>", "Configured downstream MCP server name (mcp action)")
    .option("--tool <name>", "Downstream tool to call (mcp action)")
    .option("--arguments <json>", "Tool arguments as a JSON object (mcp action)")
    // Database action
    .option("--engine <engine>", "Database engine: postgresql | mysql (database action)")
    .option("--host <host>", "Host (database/ssh action)")
    .option("--port <port>", "Port (database action)")
    .option("--database <name>", "Database name (database action)")
    .option("--query <sql>", "SQL query (database action)")
    .option("--param <value>", "Query parameter (repeatable, database action)", collect, [])
    // Git action
    .option("--operation <op>", "Git operation: clone | pull | push (git action)")
    .option("--repository <url>", "Git repository URL (git action)")
    // SSH action
    .option("--user <name>", "Remote user (ssh action)")
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

  if (options.action === "mcp") {
    let toolArguments: unknown;
    if (options.arguments !== undefined) {
      try {
        toolArguments = JSON.parse(options.arguments);
      } catch {
        throw new Error("--arguments must be a valid JSON object");
      }
    }
    return {
      type: "mcp",
      server: options.server,
      tool: options.tool,
      arguments: toolArguments,
    };
  }

  if (options.action === "database") {
    return {
      type: "database",
      engine: options.engine,
      host: options.host,
      port: options.port !== undefined ? Number(options.port) : undefined,
      database: options.database,
      query: options.query,
      params: options.param && options.param.length > 0 ? options.param : undefined,
    };
  }

  if (options.action === "git") {
    return {
      type: "git",
      operation: options.operation,
      repository: options.repository,
      args: options.arg ?? [],
      working_directory: options.cwd,
    };
  }

  if (options.action === "ssh") {
    return {
      type: "ssh",
      host: options.host,
      user: options.user,
      command: options.command,
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
