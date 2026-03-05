import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../utils/vault-loader.js";
import { handleError } from "../utils/output.js";

export function registerServerCommand(program: Command): void {
  program
    .command("server")
    .description("Start the harpoc server")
    .command("start")
    .description("Start MCP and/or REST server")
    .option("--mcp", "Start MCP server (stdio)")
    .option("--rest", "Start REST API server")
    .option("--port <port>", "REST API port", "3000")
    .option("--token <jwt>", "Launch token for MCP scope enforcement")
    .action(
      async (
        opts: { mcp?: boolean; rest?: boolean; port: string; token?: string },
        cmd: Command,
      ) => {
        let engine: Awaited<ReturnType<typeof loadUnlockedEngine>> | undefined;
        try {
          if (!opts.mcp && !opts.rest) {
            console.error("Error: At least one of --mcp or --rest is required.");
            process.exit(1);
          }

          const port = Number(opts.port);
          if (!Number.isInteger(port) || port < 1 || port > 65535) {
            console.error(`Error: Invalid port "${opts.port}". Must be 1-65535.`);
            process.exit(1);
          }

          if (opts.token && !opts.mcp) {
            console.error("Error: --token requires --mcp.");
            process.exit(1);
          }

          const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir as string | undefined);
          engine = await loadUnlockedEngine(vaultDir);

          let mcpServer: { close(): Promise<void> } | undefined;
          let restServer: { close(): void } | undefined;
          let shuttingDown = false;

          const shutdown = async (): Promise<void> => {
            if (shuttingDown) return;
            shuttingDown = true;
            if (mcpServer) await mcpServer.close();
            if (restServer) restServer.close();
            await engine?.destroy();
            process.exit(0);
          };

          process.on("SIGINT", () => void shutdown());
          process.on("SIGTERM", () => void shutdown());

          // When both MCP and REST run together, MCP owns stdout for JSON-RPC.
          // Redirect console.log to stderr so REST startup messages don't corrupt the stream.
          if (opts.mcp && opts.rest) {
            console.log = console.error;
          }

          if (opts.mcp) {
            const { createMcpServer } = await import("@harpoc/mcp-server");
            const { StdioServerTransport } =
              await import("@modelcontextprotocol/sdk/server/stdio.js");
            const server = createMcpServer({ engine, launchToken: opts.token });
            const transport = new StdioServerTransport();
            await server.connect(transport);
            mcpServer = server;
            console.error("[harpoc] MCP server running on stdio");
          }

          if (opts.rest) {
            const { startServer } = await import("@harpoc/rest-api");
            restServer = startServer({ engine, port });
          }
        } catch (err: unknown) {
          await engine?.destroy();
          handleError(err);
        }
      },
    );
}
