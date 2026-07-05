#!/usr/bin/env node

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { VaultEngine } from "@harpoc/core";
import { VAULT_DB_NAME, VAULT_DIR_NAME, SESSION_FILE_NAME } from "@harpoc/shared";
import { DEFAULT_MCP_HTTP_PORT, startMcpHttpServer } from "./http.js";
import { createMcpServer } from "./server.js";

export { createMcpServer } from "./server.js";
export type { CreateMcpServerOptions } from "./server.js";
export { startMcpHttpServer, DEFAULT_MCP_HTTP_PORT } from "./http.js";
export type { McpHttpServer, McpHttpServerOptions } from "./http.js";
export { RateLimiter } from "./guards/rate-limiter.js";
export { ScopeGuard } from "./guards/scope-guard.js";
export { InjectionGuard } from "./guards/injection-guard.js";

function resolveVaultDir(vaultDirOption?: string): string {
  if (vaultDirOption) return vaultDirOption;
  const cwdVault = join(process.cwd(), VAULT_DIR_NAME);
  if (existsSync(cwdVault)) return cwdVault;
  return join(homedir(), VAULT_DIR_NAME);
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      token: { type: "string" },
      "vault-dir": { type: "string" },
      http: { type: "boolean" },
      port: { type: "string" },
      host: { type: "string" },
    },
    strict: false,
  });

  if (values.http && values.token !== undefined) {
    process.stderr.write(
      "Error: --token is not supported with --http. HTTP clients authenticate per request via Authorization: Bearer.\n",
    );
    process.exit(1);
  }

  const port = values.port !== undefined ? Number(values.port) : DEFAULT_MCP_HTTP_PORT;
  if (values.http && (!Number.isInteger(port) || port < 1 || port > 65535)) {
    process.stderr.write(`Error: Invalid port "${String(values.port)}". Must be 1-65535.\n`);
    process.exit(1);
  }

  const vaultDir = resolveVaultDir(values["vault-dir"] as string | undefined);
  const dbPath = join(vaultDir, VAULT_DB_NAME);
  const sessionPath = join(vaultDir, SESSION_FILE_NAME);

  const engine = new VaultEngine({ dbPath, sessionPath });

  const loaded = await engine.loadSession();
  if (!loaded) {
    process.stderr.write("Error: Vault is locked. Run `harpoc unlock` first.\n");
    process.exit(1);
  }

  let close: () => Promise<void>;

  if (values.http) {
    const host = (values.host as string | undefined) ?? "127.0.0.1";
    const httpServer = await startMcpHttpServer({ engine, port, host });
    close = httpServer.close;
    process.stderr.write(
      `Harpoc MCP server listening on http://${host}:${httpServer.port}${httpServer.endpoint} (Streamable HTTP)\n`,
    );
  } else {
    const server = createMcpServer({
      engine,
      launchToken: values.token as string | undefined,
      enableTtyPrompt: true,
    });
    const transport = new StdioServerTransport();
    await server.connect(transport);
    close = () => server.close();
    process.stderr.write("Harpoc MCP server running on stdio\n");
  }

  const shutdown = async (): Promise<void> => {
    await close();
    await engine.destroy();
    process.exit(0);
  };

  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}

// Only run main when executed directly (not imported)
const isDirectRun =
  process.argv[1]?.endsWith("/mcp-server/dist/index.js") ||
  process.argv[1]?.endsWith("\\mcp-server\\dist\\index.js") ||
  process.argv[1]?.endsWith("harpoc-mcp");
if (isDirectRun) {
  main().catch((err: unknown) => {
    process.stderr.write(`Fatal: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
