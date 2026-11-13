import type { Command } from "commander";
import type { McpServerConfig } from "@harpoc/shared";
import { mcpServerConfigSchema, renderSchemaIssues, VaultError } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";
import { restModeOf, runRestMode } from "../../utils/rest-mode.js";

function collect(value: string, acc: string[]): string[] {
  acc.push(value);
  return acc;
}

interface McpServerOptions {
  name?: string;
  transport?: string;
  command?: string;
  arg?: string[];
  envVar?: string;
  cwd?: string;
  url?: string;
  protocol?: string;
  show?: boolean;
  delete?: boolean;
  token?: string;
  json?: boolean;
}

/** The config the flags name, through its schema; a refusal is `SCHEMA_VALIDATION_ERROR`. */
function parseMcpConfig(options: McpServerOptions): McpServerConfig {
  const parsed = mcpServerConfigSchema.safeParse({
    server_name: options.name,
    transport: options.transport,
    command: options.command,
    args: options.arg && options.arg.length > 0 ? options.arg : undefined,
    env_var: options.envVar,
    working_directory: options.cwd,
    url: options.url,
    protocol: options.protocol,
  });
  if (!parsed.success) {
    throw VaultError.schemaValidation(renderSchemaIssues(parsed.error));
  }
  return parsed.data;
}

export function registerSecretMcpServerCommand(secret: Command): void {
  secret
    .command("mcp-server <handle>")
    .description(
      "Configure the downstream MCP server this secret authenticates (trusted admin path)",
    )
    .option("--name <name>", "Server name referenced by use_secret's action.server")
    .option("--transport <type>", "Transport: stdio | http")
    .option("--command <command>", "Launch command (stdio transport)")
    .option("--arg <arg>", "Launch argument (repeatable, stdio transport)", collect, [])
    .option("--env-var <name>", "Env var to inject the secret into (stdio transport)")
    .option("--cwd <dir>", "Working directory (stdio transport)")
    .option("--url <url>", "Downstream Streamable HTTP endpoint (http transport)")
    .option(
      "--protocol <revision>",
      "MCP protocol revision spoken to the downstream server: 2025-11-25 (default) | 2026-07-28",
    )
    .option("--show", "Show the current config instead of setting it")
    .option("--delete", "Remove the config")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(async (handle: string, options: McpServerOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const rest = restModeOf(cmd);
        if (rest) {
          await runRestMode(rest, async (client) => {
            if (options.delete) {
              const deleted = await client.deleteMcpServerConfig(handle);
              printSuccess(
                deleted
                  ? `MCP server config removed (${handle})`
                  : `No MCP server config set (${handle})`,
              );
              return;
            }
            if (options.show || (!options.name && !options.transport)) {
              printJson((await client.getMcpServerConfig(handle)) ?? null);
              return;
            }
            const parsed = parseMcpConfig(options);
            await client.setMcpServerConfig(handle, parsed);
            printSuccess(`MCP server config updated (${handle})`);
          });
          return;
        }
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const tokenValue = options.token ?? process.env.HARPOC_TOKEN;

          if (options.delete) {
            const resolved = resolveTokenCallerForHandle(
              engine,
              "rotate",
              handle,
              tokenValue,
              "secret mcp-server",
            );
            const deleted = await engine.deleteMcpServerConfig(handle, resolved?.caller);
            printSuccess(
              deleted
                ? `MCP server config removed (${handle})`
                : `No MCP server config set (${handle})`,
            );
            return;
          }

          if (options.show || (!options.name && !options.transport)) {
            const resolved = resolveTokenCallerForHandle(
              engine,
              "read",
              handle,
              tokenValue,
              "secret mcp-server",
            );
            const config = await engine.getMcpServerConfig(handle, resolved?.caller);
            printJson(config ?? null);
            return;
          }

          const resolved = resolveTokenCallerForHandle(
            engine,
            "rotate",
            handle,
            tokenValue,
            "secret mcp-server",
          );

          const parsed = parseMcpConfig(options);

          await engine.setMcpServerConfig(handle, parsed, resolved?.caller);
          printSuccess(`MCP server config updated (${handle})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
