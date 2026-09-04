#!/usr/bin/env node

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { VaultEngine } from "@harpoc/core";
import { VAULT_DB_NAME, VAULT_DIR_NAME, SESSION_FILE_NAME } from "@harpoc/shared";
import { DEFAULT_MCP_HTTP_PORT, startMcpHttpServer } from "./http.js";
import { parseHttpPortOption } from "./cli-options.js";
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
      "allow-tokenless": { type: "boolean" },
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

  if (values.http && values["allow-tokenless"]) {
    process.stderr.write(
      "Error: --allow-tokenless is not supported with --http. The Streamable HTTP transport has no tokenless mode.\n",
    );
    process.exit(1);
  }

  if (values["allow-tokenless"] && (values.token !== undefined || process.env.HARPOC_TOKEN)) {
    process.stderr.write(
      "Error: --allow-tokenless conflicts with a launch token (--token / HARPOC_TOKEN). Provide one or the other.\n",
    );
    process.exit(1);
  }

  const parsedPort = parseHttpPortOption(values.port as string | undefined);
  if (values.http && !parsedPort.ok) {
    process.stderr.write(parsedPort.message);
    process.exit(1);
  }
  const port = parsedPort.ok ? parsedPort.port : DEFAULT_MCP_HTTP_PORT;

  const vaultDir = resolveVaultDir(values["vault-dir"] as string | undefined);
  const dbPath = join(vaultDir, VAULT_DB_NAME);
  const sessionPath = join(vaultDir, SESSION_FILE_NAME);

  const engine = new VaultEngine({ dbPath, sessionPath });

  const loaded = await engine.loadSession();
  if (!loaded) {
    process.stderr.write("Error: Vault is locked. Run `harpoc unlock` first.\n");
    process.exit(1);
  }

  const startedAt = Date.now();
  const tokenless = values["allow-tokenless"] === true;
  let close: () => Promise<void>;
  let transport: "stdio" | "http";
  let boundPort: number | undefined;
  let shuttingDown = false;

  // The stop row mirrors the start row (R4/D67). A sealed vault cannot take
  // it, and a stop that cannot be recorded must not block the stop.
  const shutdown = async (trigger: "SIGINT" | "SIGTERM" | "transport_closed"): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    try {
      engine.auditServerStop({
        transport,
        tokenless,
        ...(boundPort !== undefined ? { port: boundPort } : {}),
        uptimeMs: Date.now() - startedAt,
        trigger,
      });
    } catch {
      // Best-effort on the sealed path.
    }
    await close();
    await engine.destroy();
    process.exit(0);
  };

  if (values.http) {
    const host = (values.host as string | undefined) ?? "127.0.0.1";
    const httpServer = await startMcpHttpServer({ engine, port, host });
    close = httpServer.close;
    transport = "http";
    boundPort = httpServer.port;
    process.stderr.write(
      `Harpoc MCP server listening on http://${host}:${httpServer.port}${httpServer.endpoint} (Streamable HTTP)\n`,
    );
  } else {
    // An ambient HARPOC_TOKEN is the preferred non-argv channel for the stdio
    // launch token; an explicit --token wins. It is only read for stdio — a
    // profile-set variable must not affect --http, which authenticates per
    // request.
    const server = createMcpServer({
      engine,
      launchToken: (values.token as string | undefined) ?? (process.env.HARPOC_TOKEN || undefined),
      allowTokenless: values["allow-tokenless"] as boolean | undefined,
      enableTtyPrompt: true,
    });
    const stdio = new StdioServerTransport();
    await server.connect(stdio);
    close = () => server.close();
    transport = "stdio";
    // The SDK transport listens for data and error only: an MCP host that
    // hangs up (stdin EOF) closes nothing. That hang-up is this server's
    // graceful stop.
    process.stdin.once("end", () => void shutdown("transport_closed"));
    process.stderr.write("Harpoc MCP server running on stdio\n");
  }

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
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
