import type { Command } from "commander";
import type { VaultEngine } from "@harpoc/core";
import { InjectionGuard, sanitizeUseSecretResult } from "@harpoc/core";
import type { CallerContext, UseSecretResponse } from "@harpoc/shared";
import {
  callerFromToken,
  checkTokenScope,
  parseHandle,
  useSecretActionSchema,
} from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord } from "../../utils/output.js";

function collect(value: string, acc: string[]): string[] {
  acc.push(value);
  return acc;
}

const ACTION_TYPES = ["http", "process", "mcp", "database", "git", "ssh"] as const;
type ActionTypeName = (typeof ACTION_TYPES)[number];

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
  responseMode?: string;
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
  timeoutMs?: string;
  token?: string;
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
    .option(
      "--response-mode <mode>",
      "Response mode override: full | filtered | status_only (may only tighten the policy)",
    )
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
    // Any action
    .option("--timeout-ms <ms>", "Execution timeout in milliseconds (1..300000)")
    .option(
      "--token <jwt>",
      "Scoped API token: enforces token scope and per-secret access policies, and attributes the call (omit for the trusted local path); prefer the HARPOC_TOKEN environment variable — command-line arguments are visible to other local processes",
    )
    .option("--json", "Output the full result as JSON")
    .action(async (handle: string, options: UseOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const actionType = parseActionType(options.action);
        const parsed = useSecretActionSchema.safeParse(buildAction(actionType, options));
        if (!parsed.success) {
          throw new Error(parsed.error.issues.map((i) => i.message).join(", "));
        }

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const caller = resolveCaller(engine, handle, options.token ?? process.env.HARPOC_TOKEN);
          const result = await engine.useSecret(handle, parsed.data, caller);
          // Boundary sanitization, as applied by the REST route and the MCP
          // tool: the pattern guard runs atop the engine's exact-value
          // redaction on every interface, this one included.
          sanitizeUseSecretResult(result, new InjectionGuard());
          printResult(result, options.json);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}

/**
 * A supplied token *attenuates* the unlocked session (thesis §4.7): its scope is
 * enforced with the same predicate the REST route uses, and the call is
 * attributed to the token's principal, so per-secret access policies apply as
 * they do on every other token-bearing interface. No token = the trusted local
 * path, unchanged: no caller, no policy check, unattributed audit rows.
 *
 * A token that is *present but empty* is refused rather than treated as absent.
 * Every other direction in this codebase fails closed on an unusable token; here
 * the fallback direction is the more privileged one, so silently ignoring an
 * empty `--token ""` or an exported-but-empty `HARPOC_TOKEN` would run the call
 * on the trusted local path — no scope check, no per-secret policy, no
 * attribution — while the operator believes the session was attenuated.
 */
export function resolveCaller(
  engine: VaultEngine,
  handle: string,
  token: string | undefined,
): CallerContext | undefined {
  if (token === undefined) return undefined;
  if (token.trim() === "") {
    throw new Error(
      "--token (or HARPOC_TOKEN) was supplied but empty. Provide a token, or omit it entirely to use the trusted local path.",
    );
  }
  const payload = engine.verifyToken(token);
  const { project, name } = parseHandle(handle);
  checkTokenScope(payload, "use", project, name);
  return callerFromToken(payload, "cli");
}

/**
 * An unrecognized --action used to fall through to the HTTP builder, so a typo
 * failed as a confusing complaint about a missing URL instead of naming the
 * flag that was wrong.
 */
export function parseActionType(action: string | undefined): ActionTypeName {
  const value = action ?? "http";
  const known = ACTION_TYPES.find((candidate) => candidate === value);
  if (!known) {
    throw new Error(`--action must be one of: ${ACTION_TYPES.join(" | ")} (got "${value}")`);
  }
  return known;
}

function parseNumericOption(value: string | undefined, flag: string): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) {
    throw new Error(`${flag} must be an integer (got "${value}")`);
  }
  return parsed;
}

export function buildAction(
  actionType: ActionTypeName,
  options: UseOptions,
): Record<string, unknown> {
  const timeout_ms = parseNumericOption(options.timeoutMs, "--timeout-ms");

  if (actionType === "process") {
    return {
      type: "process",
      command: options.command,
      args: options.arg ?? [],
      env_var: options.envVar,
      working_directory: options.cwd,
      timeout_ms,
    };
  }

  if (actionType === "mcp") {
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
      timeout_ms,
    };
  }

  if (actionType === "database") {
    return {
      type: "database",
      engine: options.engine,
      host: options.host,
      port: parseNumericOption(options.port, "--port"),
      database: options.database,
      query: options.query,
      params: options.param && options.param.length > 0 ? options.param : undefined,
      timeout_ms,
    };
  }

  if (actionType === "git") {
    return {
      type: "git",
      operation: options.operation,
      repository: options.repository,
      args: options.arg ?? [],
      working_directory: options.cwd,
      timeout_ms,
    };
  }

  if (actionType === "ssh") {
    return {
      type: "ssh",
      host: options.host,
      user: options.user,
      command: options.command,
      timeout_ms,
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
    response_mode: options.responseMode,
    timeout_ms,
  };
}

function printResult(result: UseSecretResponse, json?: boolean): void {
  if (json) {
    printJson(result);
    return;
  }
  printRecord(summarizeResult(result));
}

/**
 * The human rendering: outcome fields first, output channels previewed. `--json`
 * remains the exact machine shape.
 */
export function summarizeResult(result: UseSecretResponse): Record<string, unknown> {
  switch (result.type) {
    case "http":
      return compact({
        type: result.type,
        status: result.status,
        error: result.error,
        redirect_warning: result.redirect_warning,
        body: preview(result.body),
      });
    case "process":
      return compact({
        type: result.type,
        exit_code: result.exit_code,
        signal: result.signal,
        timed_out: result.timed_out,
        truncated: result.truncated,
        error: result.error,
        stdout: preview(result.stdout),
        stderr: preview(result.stderr),
      });
    case "mcp":
      return compact({
        type: result.type,
        is_error: result.is_error,
        truncated: result.truncated,
        content_items: result.content.length,
        content: preview(JSON.stringify(result.content)),
        structured_content: preview(
          result.structured_content === undefined
            ? undefined
            : JSON.stringify(result.structured_content),
        ),
      });
    case "database":
      return compact({
        type: result.type,
        row_count: result.row_count,
        command: result.command,
        truncated: result.truncated,
        error: result.error,
        fields: result.fields?.map((f) => f.name).join(", "),
        rows: preview(JSON.stringify(result.rows)),
      });
    case "git":
      return compact({
        type: result.type,
        operation: result.operation,
        exit_code: result.exit_code,
        signal: result.signal,
        timed_out: result.timed_out,
        truncated: result.truncated,
        error: result.error,
        stdout: preview(result.stdout),
        stderr: preview(result.stderr),
      });
    case "ssh":
      return compact({
        type: result.type,
        exit_code: result.exit_code,
        signal: result.signal,
        timed_out: result.timed_out,
        truncated: result.truncated,
        error: result.error,
        stdout: preview(result.stdout),
        stderr: preview(result.stderr),
      });
    default: {
      const unhandled: never = result;
      return { ...(unhandled as object) };
    }
  }
}

const PREVIEW_LIMIT = 200;

function preview(text: string | undefined): string | undefined {
  if (text === undefined || text === "") return undefined;
  const flat = text.replace(/\s+/g, " ").trim();
  if (flat === "") return undefined;
  return flat.length <= PREVIEW_LIMIT
    ? flat
    : `${flat.slice(0, PREVIEW_LIMIT)}... (${String(text.length)} chars total)`;
}

function compact(record: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined));
}
