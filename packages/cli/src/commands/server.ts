import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../utils/vault-loader.js";
import { handleError } from "../utils/output.js";

function parsePort(value: string, label: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error(`Error: Invalid ${label} "${value}". Must be 1-65535.`);
    process.exit(1);
  }
  return port;
}

export function registerServerCommand(program: Command): void {
  program
    .command("server")
    .description("Start the harpoc server")
    .command("start")
    .description("Start MCP (stdio and/or Streamable HTTP) and/or REST server")
    .option("--mcp", "Start MCP server (stdio)")
    .option("--mcp-http", "Start MCP server (Streamable HTTP, requires per-request Bearer token)")
    .option("--mcp-http-port <port>", "MCP Streamable HTTP port", "3001")
    .option("--rest", "Start REST API server")
    .option("--port <port>", "REST API port", "3000")
    .option("--token <jwt>", "Launch token for MCP scope enforcement (stdio only)")
    .action(
      async (
        opts: {
          mcp?: boolean;
          mcpHttp?: boolean;
          mcpHttpPort: string;
          rest?: boolean;
          port: string;
          token?: string;
        },
        cmd: Command,
      ) => {
        let engine: Awaited<ReturnType<typeof loadUnlockedEngine>> | undefined;
        try {
          if (!opts.mcp && !opts.mcpHttp && !opts.rest) {
            console.error("Error: At least one of --mcp, --mcp-http or --rest is required.");
            process.exit(1);
          }

          const port = parsePort(opts.port, "port");
          const mcpHttpPort = parsePort(opts.mcpHttpPort, "MCP HTTP port");

          if (opts.token && !opts.mcp) {
            console.error(
              "Error: --token requires --mcp. The Streamable HTTP transport authenticates per request via Authorization: Bearer.",
            );
            process.exit(1);
          }

          if (opts.rest && opts.mcpHttp && port === mcpHttpPort) {
            console.error(
              `Error: --port and --mcp-http-port must differ (both are ${String(port)}).`,
            );
            process.exit(1);
          }

          const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir as string | undefined);
          engine = await loadUnlockedEngine(vaultDir);

          let mcpServer: { close(): Promise<void> } | undefined;
          let mcpHttpServer: { close(): Promise<void> } | undefined;
          let restServer: { close(): void } | undefined;
          let shuttingDown = false;

          const shutdown = async (): Promise<void> => {
            if (shuttingDown) return;
            shuttingDown = true;
            if (mcpServer) await mcpServer.close();
            if (mcpHttpServer) await mcpHttpServer.close();
            if (restServer) restServer.close();
            await engine?.destroy();
            process.exit(0);
          };

          process.on("SIGINT", () => void shutdown());
          process.on("SIGTERM", () => void shutdown());

          // When stdio MCP runs alongside an HTTP server, MCP owns stdout for JSON-RPC.
          // Redirect console.log to stderr so HTTP startup messages don't corrupt the stream.
          if (opts.mcp && (opts.rest || opts.mcpHttp)) {
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

          if (opts.mcpHttp) {
            const { startMcpHttpServer } = await import("@harpoc/mcp-server");
            const server = await startMcpHttpServer({ engine, port: mcpHttpPort });
            mcpHttpServer = server;
            console.error(
              `[harpoc] MCP server (Streamable HTTP) listening on http://127.0.0.1:${server.port}${server.endpoint}`,
            );
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
