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
    .option("--host <address>", "REST API bind address (loopback by default)", "127.0.0.1")
    .option(
      "--token <jwt>",
      "Launch token for MCP scope enforcement (stdio only); prefer the HARPOC_TOKEN environment variable — command-line arguments are visible to other local processes",
    )
    .option("--oauth-refresh", "Refresh expiring OAuth tokens in the background (60s interval)")
    .action(
      async (
        opts: {
          mcp?: boolean;
          mcpHttp?: boolean;
          mcpHttpPort: string;
          rest?: boolean;
          port: string;
          host: string;
          token?: string;
          oauthRefresh?: boolean;
        },
        cmd: Command,
      ) => {
        let engine: Awaited<ReturnType<typeof loadUnlockedEngine>> | undefined;
        try {
          if (!opts.mcp && !opts.mcpHttp && !opts.rest && !opts.oauthRefresh) {
            console.error(
              "Error: At least one of --mcp, --mcp-http, --rest or --oauth-refresh is required.",
            );
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
          let refreshScheduler: { stop(): Promise<void> } | undefined;
          let shuttingDown = false;

          const shutdown = async (): Promise<void> => {
            if (shuttingDown) return;
            shuttingDown = true;
            // Drain an in-flight refresh tick before the store closes — a
            // rotated refresh_token arriving on a closed database is lost
            // permanently (the provider already invalidated the old one).
            if (refreshScheduler) await refreshScheduler.stop();
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
            // An ambient HARPOC_TOKEN only applies to the stdio launch token; an
            // explicit --token wins. (A profile-set variable must not error out
            // --rest-only starts, so the env var is never checked without --mcp.)
            const server = createMcpServer({
              engine,
              launchToken: opts.token ?? process.env.HARPOC_TOKEN,
              enableTtyPrompt: true,
            });
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
            restServer = startServer({ engine, port, hostname: opts.host });
          }

          if (opts.oauthRefresh) {
            const { TokenRefreshScheduler } = await import("@harpoc/oauth-proxy");
            const scheduler = new TokenRefreshScheduler(engine, {
              onRefreshError: (secretId, err) => {
                // A refresh racing shutdown fails with vaultLocked — not operator-actionable.
                if (shuttingDown) return;
                console.error(
                  `Warning: OAuth token refresh failed (${secretId}): ${err instanceof Error ? err.message : String(err)}`,
                );
              },
            });
            scheduler.start();
            refreshScheduler = scheduler;
            console.error("[harpoc] OAuth token refresh scheduler running (60s interval)");
          }
        } catch (err: unknown) {
          await engine?.destroy();
          handleError(err);
        }
      },
    );
}
