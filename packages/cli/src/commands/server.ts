import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import type { Command } from "commander";
import { MAX_TOKEN_TTL_MS, Permission } from "@harpoc/shared";
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

function resolveUiDistDir(): string {
  const require = createRequire(import.meta.url);
  return join(dirname(require.resolve("@harpoc/web-ui/package.json")), "dist");
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
    .option("--ui", "Serve the Web UI at /ui (requires --rest); prints a one-time admin launch URL")
    .option(
      "--token <jwt>",
      "Launch token for MCP scope enforcement (stdio only); prefer the HARPOC_TOKEN environment variable — command-line arguments are visible to other local processes",
    )
    .option(
      "--allow-tokenless",
      "Explicitly run the stdio MCP server without a launch token — all tools and resources are unrestricted (local full-access mode)",
    )
    .option("--oauth-refresh", "Refresh expiring OAuth tokens in the background (60s interval)")
    .option(
      "--cert-renew",
      "Renew expiring auto-renew certificates in the background (hourly check)",
    )
    .option(
      "--cert-renew-port <port>",
      "HTTP port for the http-01 challenge responder during renewal",
      "80",
    )
    .action(
      async (
        opts: {
          mcp?: boolean;
          mcpHttp?: boolean;
          mcpHttpPort: string;
          rest?: boolean;
          port: string;
          host: string;
          ui?: boolean;
          token?: string;
          allowTokenless?: boolean;
          oauthRefresh?: boolean;
          certRenew?: boolean;
          certRenewPort: string;
        },
        cmd: Command,
      ) => {
        let engine: Awaited<ReturnType<typeof loadUnlockedEngine>> | undefined;
        try {
          if (opts.ui && !opts.rest) {
            console.error("Error: --ui requires --rest.");
            process.exit(1);
          }

          if (!opts.mcp && !opts.mcpHttp && !opts.rest && !opts.oauthRefresh && !opts.certRenew) {
            console.error(
              "Error: At least one of --mcp, --mcp-http, --rest, --oauth-refresh or --cert-renew is required.",
            );
            process.exit(1);
          }

          if (cmd.getOptionValueSource("certRenewPort") === "cli" && !opts.certRenew) {
            console.error("Error: --cert-renew-port requires --cert-renew.");
            process.exit(1);
          }

          const port = parsePort(opts.port, "port");
          const mcpHttpPort = parsePort(opts.mcpHttpPort, "MCP HTTP port");
          const certRenewPort = parsePort(opts.certRenewPort, "cert renewal port");

          if (opts.token && !opts.mcp) {
            console.error(
              "Error: --token requires --mcp. The Streamable HTTP transport authenticates per request via Authorization: Bearer.",
            );
            process.exit(1);
          }

          if (opts.allowTokenless && !opts.mcp) {
            console.error(
              "Error: --allow-tokenless requires --mcp. The Streamable HTTP transport has no tokenless mode.",
            );
            process.exit(1);
          }

          if (opts.allowTokenless && (opts.token ?? process.env.HARPOC_TOKEN)) {
            console.error(
              "Error: --allow-tokenless conflicts with a launch token (--token / HARPOC_TOKEN). Provide one or the other.",
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
          let restOAuthManager: { cancelPendingFlows(): void } | undefined;
          let refreshScheduler: { stop(): Promise<void> } | undefined;
          let renewalScheduler: { stop(): Promise<void> } | undefined;
          let shuttingDown = false;

          const shutdown = async (): Promise<void> => {
            if (shuttingDown) return;
            shuttingDown = true;
            // Drain an in-flight refresh tick before the store closes — a
            // rotated refresh_token arriving on a closed database is lost
            // permanently (the provider already invalidated the old one).
            if (refreshScheduler) await refreshScheduler.stop();
            // Same reasoning for certificate renewal: an order abandoned
            // between issuance and storage is lost for good.
            if (renewalScheduler) await renewalScheduler.stop();
            if (mcpServer) await mcpServer.close();
            if (mcpHttpServer) await mcpHttpServer.close();
            if (restServer) restServer.close();
            // Abort the REST app's pending background OAuth flows before the
            // store closes: each authorization-code flow pins a loopback
            // listener and a 5-minute timer, and its completion writes to the
            // vault. Cancellation is a synchronous abort fan-out — nothing to
            // drain, unlike the schedulers above.
            restOAuthManager?.cancelPendingFlows();
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
              allowTokenless: opts.allowTokenless,
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
            const { startServer, createDefaultOAuthManager } = await import("@harpoc/rest-api");
            // Constructed here, not inside createApp: the shutdown path needs a
            // handle on the manager to cancel its pending flows (D4).
            const oauthManager = createDefaultOAuthManager(engine);
            restOAuthManager = oauthManager;
            const uiDir = opts.ui ? resolveUiDistDir() : undefined;
            restServer = startServer({ engine, port, hostname: opts.host, oauthManager, uiDir });
            if (opts.ui) {
              // Fragment, not query: the token must never appear in a request
              // line a server or proxy could log.
              const launchToken = engine.createToken(
                "web-ui",
                [Permission.ADMIN],
                MAX_TOKEN_TTL_MS,
                {
                  principalType: "user",
                },
              );
              console.error(
                `[harpoc] Web UI: http://${opts.host}:${String(port)}/ui#token=${launchToken}`,
              );
              console.error(
                "[harpoc] The link grants admin access until the token expires (24 h cap). Do not share it.",
              );
            }
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

          if (opts.certRenew) {
            const { CertManager, RenewalScheduler } = await import("@harpoc/cert-manager");
            const certManager = new CertManager(engine);
            const scheduler = new RenewalScheduler(
              engine,
              {
                renewCertificate: (secretId) =>
                  certManager.renewCertificate(secretId, { httpPort: certRenewPort }),
              },
              {
                onRenewError: (secretId, err) => {
                  if (shuttingDown) return;
                  console.error(
                    `Warning: certificate renewal failed (${secretId}): ${err instanceof Error ? err.message : String(err)}`,
                  );
                },
              },
            );
            scheduler.start();
            renewalScheduler = scheduler;
            console.error(
              "[harpoc] certificate renewal scheduler running (checks hourly, first check in ~1 h; auto-renew certificates only)",
            );
          }
        } catch (err: unknown) {
          await engine?.destroy();
          handleError(err);
        }
      },
    );
}
