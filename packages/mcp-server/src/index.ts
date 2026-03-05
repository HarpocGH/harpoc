#!/usr/bin/env node

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { VaultEngine } from "@harpoc/core";
import { VAULT_DB_NAME, VAULT_DIR_NAME, SESSION_FILE_NAME } from "@harpoc/shared";
import { createMcpServer } from "./server.js";

export { createMcpServer } from "./server.js";
export type { CreateMcpServerOptions } from "./server.js";
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
    },
    strict: false,
  });

  const vaultDir = resolveVaultDir(values["vault-dir"] as string | undefined);
  const dbPath = join(vaultDir, VAULT_DB_NAME);
  const sessionPath = join(vaultDir, SESSION_FILE_NAME);

  const engine = new VaultEngine({ dbPath, sessionPath });

  const loaded = await engine.loadSession();
  if (!loaded) {
    process.stderr.write("Error: Vault is locked. Run `harpoc unlock` first.\n");
    process.exit(1);
  }

  const server = createMcpServer({
    engine,
    launchToken: values.token as string | undefined,
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  process.stderr.write("Harpoc MCP server running on stdio\n");

  const shutdown = async (): Promise<void> => {
    await server.close();
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
