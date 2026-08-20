import { readFileSync } from "node:fs";
import type { Command } from "commander";
import type { VaultEngine } from "@harpoc/core";
import { InjectionGuard, sanitizeUseSecretResult } from "@harpoc/core";
import type { CallerContext, UseSecretResponse } from "@harpoc/shared";
import { useSecretActionSchema, VaultError } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

function collect(value: string, acc: string[]): string[] {
  acc.push(value);
  return acc;
}

const ACTION_TYPES = [
  "http",
  "process",
  "mcp",
  "database",
  "git",
  "ssh",
  "smtp",
  "imap",
  "websocket",
  "sftp",
  "docker_registry",
] as const;
type ActionTypeName = (typeof ACTION_TYPES)[number];

/**
 * Options `--action-file` is exempt from its own conflict check (it selects
 * the file path itself; conflicting with itself would be nonsensical), plus
 * the two cross-cutting flags that never shape an action.
 */
const ACTION_FILE_EXEMPT_OPTIONS = new Set(["actionFile", "token", "json"]);

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
  // SMTP action
  from?: string;
  to?: string[];
  cc?: string[];
  bcc?: string[];
  subject?: string;
  text?: string;
  html?: string;
  attachment?: string[];
  security?: string;
  // IMAP action (also shares --host/--port/--operation above)
  mailbox?: string;
  account?: string;
  uid?: string[];
  parts?: string;
  searchUnseen?: boolean;
  searchSince?: string;
  searchFrom?: string;
  searchSubject?: string;
  searchText?: string;
  addFlag?: string[];
  removeFlag?: string[];
  targetMailbox?: string;
  // WebSocket action (also shares --url/--injection/--header-name/--query-param above)
  message?: string;
  collectMax?: string;
  collectWindow?: string;
  subprotocol?: string[];
  // SFTP action (also shares --host/--user/--operation above)
  remote?: string;
  local?: string;
  // Docker registry action (also shares --operation above)
  image?: string;
  // Complete action document, bypassing every flag above
  actionFile?: string;
  timeoutMs?: string;
  token?: string;
  json?: boolean;
}

export function registerSecretUseCommand(secret: Command): void {
  secret
    .command("use <handle>")
    .description(
      "Use a secret via an HTTP request, process, MCP tool call, database query, Git operation, SSH command, SMTP send, IMAP operation, WebSocket message, SFTP transfer or Docker registry operation (value never exposed)",
    )
    .option(
      "--action <type>",
      "Action type: http | process | mcp | database | git | ssh | smtp | imap | websocket | sftp | docker_registry",
      "http",
    )
    // HTTP action
    .option("--method <method>", "HTTP method", "GET")
    .option("--url <url>", "Target URL (http/websocket action)")
    .option("--injection <type>", "Injection: bearer | header | query | basic_auth", "bearer")
    .option("--header-name <name>", "Header name (injection=header)")
    .option("--query-param <name>", "Query parameter (injection=query)")
    .option("--body <body>", "Request body (http action)")
    .option("--header <kv>", "Extra request header 'Key: Value' (repeatable)", collect, [])
    .option("--follow-redirects <policy>", "Redirect policy: same-origin | none | any")
    .option(
      "--response-mode <mode>",
      "Response mode override: full | filtered | status_only (may only tighten the policy; http/websocket action)",
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
    .option("--host <host>", "Host (database/ssh/smtp/imap/sftp action)")
    .option("--port <port>", "Port (database/smtp/imap action)")
    .option("--database <name>", "Database name (database action)")
    .option("--query <sql>", "SQL query (database action)")
    .option("--param <value>", "Query parameter (repeatable, database action)", collect, [])
    // Git action (--operation is reused by imap/sftp/docker_registry below)
    .option(
      "--operation <op>",
      "Operation: clone|pull|push (git); search|fetch|store|move|copy|expunge (imap); upload|download|list (sftp); pull|push (docker_registry)",
    )
    .option("--repository <url>", "Git repository URL (git action)")
    // SSH action
    .option("--user <name>", "Remote user (ssh/sftp action)")
    // SMTP action
    .option("--from <addr>", "Sender address (smtp action)")
    .option("--to <addr>", "Recipient address (repeatable, smtp action)", collect, [])
    .option("--cc <addr>", "Cc address (repeatable, smtp action)", collect, [])
    .option("--bcc <addr>", "Bcc address (repeatable, smtp action)", collect, [])
    .option("--subject <text>", "Message subject (smtp action)")
    .option("--text <body>", "Plain-text body (smtp action)")
    .option("--html <body>", "HTML body (smtp action)")
    .option("--attachment <path>", "Attachment file path (repeatable, smtp action)", collect, [])
    .option("--security <mode>", "Transport security: tls | starttls (smtp action)")
    // IMAP action
    .option("--mailbox <name>", "Mailbox to select (imap action, default INBOX)")
    .option(
      "--account <addr>",
      "Mailbox account name for XOAUTH2 (imap action with an OAuth secret)",
    )
    .option("--uid <n>", "Message UID (repeatable, imap action)", collect, [])
    .option("--parts <mode>", "Fetch parts: envelope | headers | text | full (imap fetch)")
    .option("--search-unseen", "Search: only unseen messages (imap search)")
    .option("--search-since <date>", "Search: since date, YYYY-MM-DD (imap search)")
    .option("--search-from <addr>", "Search: From address (imap search)")
    .option("--search-subject <text>", "Search: Subject contains (imap search)")
    .option("--search-text <text>", "Search: body/text contains (imap search)")
    .option("--add-flag <flag>", "Flag to add (repeatable, imap store)", collect, [])
    .option("--remove-flag <flag>", "Flag to remove (repeatable, imap store)", collect, [])
    .option("--target-mailbox <name>", "Destination mailbox (imap move/copy)")
    // WebSocket action (--url/--injection/--header-name/--query-param/--response-mode above)
    .option("--message <text>", "Message to send after connecting (websocket action)")
    .option("--collect-max <n>", "Max frames to collect (websocket action)")
    .option("--collect-window <ms>", "Collection window in milliseconds (websocket action)")
    .option(
      "--subprotocol <name>",
      "WebSocket subprotocol to offer (repeatable, websocket action)",
      collect,
      [],
    )
    // SFTP action (--host/--user/--operation above)
    .option("--remote <path>", "Remote file path (sftp action)")
    .option("--local <path>", "Local file path (sftp action)")
    // Docker registry action (--operation above)
    .option("--image <ref>", "Image reference (docker_registry action)")
    // Complete action document, bypassing every action-shaping flag above
    .option(
      "--action-file <path>",
      "Read the complete action document from a JSON file, validated the same way as the flag-built action; conflicts with every action-shaping flag",
    )
    // Any action
    .option("--timeout-ms <ms>", "Execution timeout in milliseconds")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output the full result as JSON")
    .action(async (handle: string, options: UseOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        let actionInput: Record<string, unknown>;
        if (options.actionFile !== undefined) {
          assertNoActionShapingFlags(cmd);
          actionInput = readActionFile(options.actionFile);
        } else {
          const actionType = parseActionType(options.action);
          actionInput = buildAction(actionType, options);
        }
        const parsed = useSecretActionSchema.safeParse(actionInput);
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

/** Token semantics live in resolveTokenCallerForHandle (utils/token-caller.ts). */
export function resolveCaller(
  engine: VaultEngine,
  handle: string,
  token: string | undefined,
): CallerContext | undefined {
  return resolveTokenCallerForHandle(engine, "use", handle, token)?.caller;
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

/**
 * `--action-file` supplies the complete action document itself, so any flag
 * that would otherwise shape one is ambiguous input, not a silently-ignored
 * extra. Walks every option Commander registered on this command (so a
 * future flag can't be forgotten) and reports every one the caller actually
 * passed on argv — `getOptionValueSource` distinguishes that from a flag's
 * own default (`--action` defaults to "http", `--method` to "GET", the
 * repeatable flags default to `[]`), so a bare `--action-file` alone never
 * false-positives.
 */
function assertNoActionShapingFlags(cmd: Command): void {
  const conflicting = cmd.options
    .filter((option) => !ACTION_FILE_EXEMPT_OPTIONS.has(option.attributeName()))
    .filter((option) => cmd.getOptionValueSource(option.attributeName()) === "cli")
    .map((option) => option.long ?? option.flags);
  if (conflicting.length > 0) {
    throw VaultError.invalidInput(
      `--action-file conflicts with ${conflicting.join(", ")} — supply the action via the file or the flags, not both.`,
    );
  }
}

/** Parses and returns the file's contents; schema validation happens at the one shared call site. */
function readActionFile(path: string): Record<string, unknown> {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw VaultError.invalidInput(
      `--action-file could not be read: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw VaultError.invalidInput("--action-file must contain valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw VaultError.invalidInput("--action-file must contain a JSON object");
  }
  return parsed as Record<string, unknown>;
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

  if (actionType === "smtp") {
    return {
      type: "smtp",
      host: options.host,
      port: parseNumericOption(options.port, "--port"),
      security: options.security,
      from: options.from,
      to: options.to ?? [],
      cc: options.cc && options.cc.length > 0 ? options.cc : undefined,
      bcc: options.bcc && options.bcc.length > 0 ? options.bcc : undefined,
      subject: options.subject,
      text: options.text,
      html: options.html,
      attachments:
        options.attachment && options.attachment.length > 0
          ? options.attachment.map((path) => ({ path }))
          : undefined,
      timeout_ms,
    };
  }

  if (actionType === "imap") {
    return {
      type: "imap",
      host: options.host,
      port: parseNumericOption(options.port, "--port"),
      mailbox: options.mailbox,
      account: options.account,
      operation: buildImapOperation(options),
      timeout_ms,
    };
  }

  if (actionType === "websocket") {
    const collectMax = parseNumericOption(options.collectMax, "--collect-max");
    const collectWindow = parseNumericOption(options.collectWindow, "--collect-window");
    return {
      type: "websocket",
      url: options.url,
      injection: buildInjectionConfig(options),
      message: options.message,
      subprotocols:
        options.subprotocol && options.subprotocol.length > 0 ? options.subprotocol : undefined,
      collect:
        collectMax !== undefined || collectWindow !== undefined
          ? { max_messages: collectMax, window_ms: collectWindow }
          : undefined,
      response_mode: options.responseMode,
      timeout_ms,
    };
  }

  if (actionType === "sftp") {
    return {
      type: "sftp",
      host: options.host,
      user: options.user,
      operation: options.operation,
      remote_path: options.remote,
      local_path: options.local,
      timeout_ms,
    };
  }

  if (actionType === "docker_registry") {
    return {
      type: "docker_registry",
      operation: options.operation,
      image: options.image,
      timeout_ms,
    };
  }

  const headers: Record<string, string> = {};
  for (const entry of options.header ?? []) {
    const idx = entry.indexOf(":");
    if (idx === -1) continue;
    headers[entry.slice(0, idx).trim()] = entry.slice(idx + 1).trim();
  }

  return {
    type: "http",
    method: options.method,
    url: options.url,
    headers: Object.keys(headers).length > 0 ? headers : undefined,
    body: options.body,
    injection: buildInjectionConfig(options),
    follow_redirects: options.followRedirects,
    response_mode: options.responseMode,
    timeout_ms,
  };
}

/**
 * The secret-injection config shared by http and websocket (the same
 * bearer/header/query/basic_auth vocabulary, applied at the request or the
 * upgrade handshake respectively) — one mapping, both callers.
 */
function buildInjectionConfig(options: UseOptions): Record<string, unknown> {
  const injection: Record<string, unknown> = { type: options.injection };
  if (options.headerName) injection.header_name = options.headerName;
  if (options.queryParam) injection.query_param = options.queryParam;
  return injection;
}

function parseUidList(values: string[] | undefined, flag: string): number[] {
  return (values ?? []).map((value) => {
    const parsed = Number(value);
    if (!Number.isInteger(parsed)) {
      throw new Error(`${flag} must be an integer (got "${value}")`);
    }
    return parsed;
  });
}

/**
 * IMAP's operation is a discriminated union keyed by `--operation`'s value
 * (search | fetch | store | move | copy | expunge); the kind-specific fields
 * all come from the flags scoped to that kind. An unrecognized kind is left
 * for the schema to name, matching every other enum flag in this file.
 */
function buildImapOperation(options: UseOptions): Record<string, unknown> {
  const kind = options.operation;
  switch (kind) {
    case "search":
      return {
        kind,
        unseen: options.searchUnseen,
        since: options.searchSince,
        from: options.searchFrom,
        subject: options.searchSubject,
        text: options.searchText,
      };
    case "fetch":
      return {
        kind,
        uids: parseUidList(options.uid, "--uid"),
        parts: options.parts,
      };
    case "store":
      return {
        kind,
        uids: parseUidList(options.uid, "--uid"),
        add_flags: options.addFlag && options.addFlag.length > 0 ? options.addFlag : undefined,
        remove_flags:
          options.removeFlag && options.removeFlag.length > 0 ? options.removeFlag : undefined,
      };
    case "move":
    case "copy":
      return {
        kind,
        uids: parseUidList(options.uid, "--uid"),
        target_mailbox: options.targetMailbox,
      };
    case "expunge":
      return { kind };
    default:
      return { kind };
  }
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
    case "smtp":
      return compact({
        type: result.type,
        accepted: result.accepted,
        message_id: result.message_id,
      });
    case "imap":
      return compact({
        type: result.type,
        operation: result.operation,
        uids: result.uids?.join(", "),
        affected: result.affected,
        message_count: result.messages?.length,
        messages: preview(
          result.messages === undefined ? undefined : JSON.stringify(result.messages),
        ),
      });
    case "websocket":
      return compact({
        type: result.type,
        close_code: result.close_code,
        message_count: result.messages.length,
        messages: preview(JSON.stringify(result.messages)),
      });
    case "sftp":
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
    case "docker_registry":
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
