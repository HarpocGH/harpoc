import { createRequire } from "node:module";
import { basename, dirname, join } from "node:path";
import { Option } from "commander";
import type { Command } from "commander";
import {
  MAX_TOKEN_TTL_MS,
  Permission,
  VaultError,
  assertBindAllowed,
  isDecimalInteger,
} from "@harpoc/shared";
import type { ServerStopTrigger, ServerTransport } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine, unlockEngineWithKey } from "../utils/vault-loader.js";
import { handleError } from "../utils/output.js";
import { parseIntOption } from "../utils/options.js";
import { DEFAULT_PROXY_PORT, MAX_PORT, MIN_PORT } from "../utils/option-bounds.js";
import { assertRuntimeDir, consumerSocketPaths, resolveRuntimeDir } from "../utils/runtime-dir.js";

function resolveUiDistDir(): string {
  const require = createRequire(import.meta.url);
  return join(dirname(require.resolve("@harpoc/web-ui/package.json")), "dist");
}

function collect(value: string, acc: string[]): string[] {
  return [...acc, value];
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
      "--allowed-host <name>",
      "Host name or IP clients use to reach the REST listener (repeatable; required for a non-loopback --host, additive on loopback, where 127.0.0.1, ::1 and localhost are always allowed)",
      collect,
      [],
    )
    .option("--ui", "Serve the Web UI at /ui (requires --rest); prints a one-time admin launch URL")
    .option(
      "--ui-token-ttl <minutes>",
      "Web UI launch-token validity in minutes (requires --ui; 1-1440, default 24 h)",
    )
    .option(
      "--token-file <path>",
      "File holding the launch token for MCP scope enforcement (stdio only); the HARPOC_TOKEN environment variable is the other channel — command-line arguments are visible to other local processes",
    )
    .addOption(new Option("--token <jwt>").hideHelp())
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
    .option(
      "--runtime-dir <path>",
      "Runtime directory holding one subdirectory per consumer (owned by this user, mode 0750 or stricter; created by deploy/linux/install-two-identity.sh and recreated at boot by its tmpfiles.d entry — never a unit's RuntimeDirectory=, which systemd empties at every stop); checked before the vault opens",
    )
    .option(
      "--proxy",
      "Start the egress credential proxy (plain-HTTP rewrite mode) on 127.0.0.1:<--proxy-port>, and one proxy.sock per consumer directory under --runtime-dir (default $RUNTIME_DIRECTORY)",
    )
    .option("--proxy-port <port>", "Egress proxy port (loopback)", String(DEFAULT_PROXY_PORT))
    .option(
      "--ssh-agent",
      "Serve one ssh-agent.sock per consumer directory under --runtime-dir (default $RUNTIME_DIRECTORY): signatures with the keys each consumer is granted, host-bound by session-bind",
    )
    .option(
      "--unlock-key-file <path>",
      "Unlock the vault at start from the 32-byte unlock key in <path> (owner-only mode required; written by harpoc unlock-key enroll) — a password file by another name: prefer --unlock-credential under a systemd sealer",
    )
    .option(
      "--unlock-credential <name>",
      "Unlock the vault at start from the systemd credential <name> in $CREDENTIALS_DIRECTORY (LoadCredentialEncrypted= in deploy/systemd/harpoc.service)",
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
          allowedHost: string[];
          ui?: boolean;
          uiTokenTtl?: string;
          token?: string;
          tokenFile?: string;
          allowTokenless?: boolean;
          oauthRefresh?: boolean;
          certRenew?: boolean;
          certRenewPort: string;
          runtimeDir?: string;
          proxy?: boolean;
          proxyPort: string;
          sshAgent?: boolean;
          unlockKeyFile?: string;
          unlockCredential?: string;
        },
        cmd: Command,
      ) => {
        let engine: Awaited<ReturnType<typeof loadUnlockedEngine>> | undefined;
        try {
          // Commander takes the next flag as the path (`--token-file
          // --allow-tokenless`, `--token-file --mcp`); a dash-led path is given
          // as ./-name (2026-10-22).
          if (opts.tokenFile?.startsWith("-")) {
            console.error(
              "Error: --token-file requires a path (give a path that starts with a dash as ./-name).",
            );
            process.exit(1);
          }
          // The same slip for the unlock key's two sources (`--unlock-key-file --rest`), refused
          // before the transport check reads the flag it swallowed as missing.
          if (opts.unlockKeyFile !== undefined) {
            if (opts.unlockKeyFile.trim() === "") {
              throw VaultError.invalidInput("--unlock-key-file: empty path");
            }
            if (opts.unlockKeyFile.startsWith("-")) {
              throw VaultError.invalidInput(
                "--unlock-key-file: a flag, not a path (give a path that starts with a dash as ./-name)",
              );
            }
          }
          if (opts.unlockCredential !== undefined) {
            if (opts.unlockCredential.trim() === "") {
              throw VaultError.invalidInput("--unlock-credential: empty name");
            }
            if (opts.unlockCredential.startsWith("-")) {
              throw VaultError.invalidInput("--unlock-credential: a flag, not a credential name");
            }
          }
          if (opts.unlockKeyFile !== undefined && opts.unlockCredential !== undefined) {
            console.error(
              "Error: --unlock-key-file and --unlock-credential exclude each other: one unlock key source per start.",
            );
            process.exit(1);
          }
          // An ambient $RUNTIME_DIRECTORY is the default only for a
          // per-consumer feature (--proxy's and --ssh-agent's sockets): a unit's
          // RuntimeDirectory= (0755 by default) must not refuse a start that
          // asked for none.
          const runtimeDir = resolveRuntimeDir(
            opts.runtimeDir,
            opts.proxy || opts.sshAgent ? process.env : {},
          );

          if (opts.ui && !opts.rest) {
            console.error("Error: --ui requires --rest.");
            process.exit(1);
          }

          if (cmd.getOptionValueSource("uiTokenTtl") === "cli" && !opts.ui) {
            console.error("Error: --ui-token-ttl requires --ui.");
            process.exit(1);
          }
          let uiTokenTtlMs: number | undefined;
          if (opts.uiTokenTtl !== undefined) {
            const minutes = Number(opts.uiTokenTtl);
            if (!isDecimalInteger(opts.uiTokenTtl) || minutes < 1) {
              console.error("Error: --ui-token-ttl must be a whole number of minutes (>= 1).");
              process.exit(1);
            }
            if (minutes * 60_000 > MAX_TOKEN_TTL_MS) {
              console.error("Error: --ui-token-ttl exceeds the 24 h token cap (1440).");
              process.exit(1);
            }
            uiTokenTtlMs = minutes * 60_000;
          }

          if (
            !opts.mcp &&
            !opts.mcpHttp &&
            !opts.rest &&
            !opts.proxy &&
            !opts.sshAgent &&
            !opts.oauthRefresh &&
            !opts.certRenew
          ) {
            console.error(
              "Error: At least one of --mcp, --mcp-http, --rest, --oauth-refresh or --cert-renew is required.",
            );
            process.exit(1);
          }

          if (cmd.getOptionValueSource("certRenewPort") === "cli" && !opts.certRenew) {
            console.error("Error: --cert-renew-port requires --cert-renew.");
            process.exit(1);
          }

          if (cmd.getOptionValueSource("proxyPort") === "cli" && !opts.proxy) {
            console.error("Error: --proxy-port requires --proxy.");
            process.exit(1);
          }

          // The agent socket has no TCP half: it is served in the consumer directories only.
          if (opts.sshAgent && runtimeDir === undefined) {
            console.error(
              "Error: --ssh-agent requires --runtime-dir (or systemd's $RUNTIME_DIRECTORY): one ssh-agent.sock per consumer directory.",
            );
            process.exit(1);
          }

          const port = parseIntOption(opts.port, "port", MIN_PORT, MAX_PORT);
          const mcpHttpPort = parseIntOption(opts.mcpHttpPort, "MCP HTTP port", MIN_PORT, MAX_PORT);
          const certRenewPort = parseIntOption(
            opts.certRenewPort,
            "cert renewal port",
            MIN_PORT,
            MAX_PORT,
          );
          const proxyPort = parseIntOption(opts.proxyPort, "proxy port", MIN_PORT, MAX_PORT);

          if (opts.token !== undefined) {
            console.error(
              "Error: --token was removed: pass the launch token via the HARPOC_TOKEN environment variable or --token-file <path> — command-line arguments are visible to other local processes.",
            );
            process.exit(1);
          }

          if (opts.allowedHost.length > 0 && !opts.rest) {
            console.error("Error: --allowed-host requires --rest.");
            process.exit(1);
          }
          if (opts.rest) {
            // Refused before the vault opens, like every other launch typo:
            // a misconfigured listener must not cost a session (R11/D61).
            try {
              assertBindAllowed(opts.host, opts.allowedHost);
            } catch (err) {
              console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
              process.exit(1);
            }
          }

          if (opts.tokenFile !== undefined && !opts.mcp) {
            console.error(
              "Error: --token-file requires --mcp. The Streamable HTTP transport authenticates per request via Authorization: Bearer.",
            );
            process.exit(1);
          }

          if (opts.allowTokenless && !opts.mcp) {
            console.error(
              "Error: --allow-tokenless requires --mcp. The Streamable HTTP transport has no tokenless mode.",
            );
            process.exit(1);
          }

          if (opts.allowTokenless && (opts.tokenFile !== undefined || process.env.HARPOC_TOKEN)) {
            console.error(
              "Error: --allow-tokenless conflicts with a launch token (--token-file / HARPOC_TOKEN). Provide one or the other.",
            );
            process.exit(1);
          }

          if (opts.rest && opts.mcpHttp && port === mcpHttpPort) {
            console.error(
              `Error: --port and --mcp-http-port must differ (both are ${String(port)}).`,
            );
            process.exit(1);
          }

          if (opts.rest && opts.certRenew && port === certRenewPort) {
            console.error(
              `Error: --port and --cert-renew-port must differ (both are ${String(port)}).`,
            );
            process.exit(1);
          }
          if (opts.mcpHttp && opts.certRenew && mcpHttpPort === certRenewPort) {
            console.error(
              `Error: --mcp-http-port and --cert-renew-port must differ (both are ${String(mcpHttpPort)}).`,
            );
            process.exit(1);
          }
          for (const [flag, enabled, other] of [
            ["--port", opts.rest, port],
            ["--mcp-http-port", opts.mcpHttp, mcpHttpPort],
            ["--cert-renew-port", opts.certRenew, certRenewPort],
          ] as const) {
            if (opts.proxy && enabled && other === proxyPort) {
              console.error(
                `Error: ${flag} and --proxy-port must differ (both are ${String(proxyPort)}).`,
              );
              process.exit(1);
            }
          }

          // Read before the vault is loaded, like every other refusal above: a
          // bad file never touches the session.
          let fileToken: string | undefined;
          if (opts.tokenFile !== undefined) {
            const { readLaunchTokenFile } = await import("@harpoc/mcp-server");
            const read = readLaunchTokenFile(opts.tokenFile);
            if (!read.ok) {
              console.error(read.message.trimEnd());
              process.exit(1);
            }
            fileToken = read.token;
          }
          if (runtimeDir !== undefined) assertRuntimeDir(runtimeDir);
          // One proxy.sock per consumer directory present: each directory is an
          // enrolment, and a misconfigured one refuses the start (R-A1).
          const proxySockets =
            opts.proxy && runtimeDir !== undefined
              ? consumerSocketPaths(runtimeDir, "proxy.sock")
              : [];
          // One ssh-agent.sock per consumer directory; a --ssh-agent that serves no consumer
          // refuses the start (a consumer directory named as the runtime directory lists none).
          const sshAgentSockets =
            opts.sshAgent && runtimeDir !== undefined
              ? consumerSocketPaths(runtimeDir, "ssh-agent.sock")
              : [];
          if (opts.sshAgent && runtimeDir !== undefined && sshAgentSockets.length === 0) {
            throw VaultError.invalidInput(
              `${runtimeDir.source}: --ssh-agent found no consumer directory under ${runtimeDir.path} (one per agent user: deploy/linux/install-two-identity.sh)`,
            );
          }

          const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir as string | undefined);
          // The unlock key is read last, after every refusal above — a bad source never costs a
          // session — and handed to the engine, which wipes it (B4). Without either option the
          // daemon loads the session as before.
          let unlockKey: Uint8Array | undefined;
          if (opts.unlockKeyFile !== undefined) {
            const { readUnlockKeyFile } = await import("@harpoc/core");
            const warnings: string[] = [];
            unlockKey = await readUnlockKeyFile(opts.unlockKeyFile, {
              onWarning: (warning) => warnings.push(warning),
            });
            console.error(
              `Warning: --unlock-key-file is a password file by another name: without a sealer, whoever can read ${opts.unlockKeyFile} unlocks the vault.`,
            );
            for (const warning of warnings) console.error(`Warning: --unlock-key-file: ${warning}`);
          } else if (opts.unlockCredential !== undefined) {
            const { readUnlockCredential } = await import("@harpoc/core");
            unlockKey = await readUnlockCredential(opts.unlockCredential, process.env);
          }
          engine =
            unlockKey === undefined
              ? await loadUnlockedEngine(vaultDir)
              : await unlockEngineWithKey(vaultDir, unlockKey);

          let mcpServer: { close(): Promise<void> } | undefined;
          let mcpHttpServer: { close(): Promise<void> } | undefined;
          let restServer: { close(): void } | undefined;
          let restOAuthManager: { cancelPendingFlows(): void } | undefined;
          let refreshScheduler: { stop(): Promise<void> } | undefined;
          let renewalScheduler: { stop(): Promise<void> } | undefined;
          let egressProxy: { close(): Promise<void> } | undefined;
          let proxyBoundPort: number | undefined;
          const agentSockets: { readonly consumer: string; stop(): Promise<void> }[] = [];
          let shuttingDown = false;

          const startedAt = Date.now();
          let mcpHttpBoundPort: number | undefined;
          let stdioClosed = false;

          // The stop row mirrors the start row (R4/D67): one per started
          // listener, before its close. A sealed vault cannot take the row,
          // and a stop that cannot be recorded must not block the stop.
          const auditStop = (
            transport: ServerTransport,
            tokenless: boolean,
            listenerPort: number | undefined,
            trigger: ServerStopTrigger,
            consumer?: string,
          ): void => {
            try {
              engine?.auditServerStop({
                transport,
                tokenless,
                ...(listenerPort !== undefined ? { port: listenerPort } : {}),
                ...(consumer !== undefined ? { consumer } : {}),
                uptimeMs: Date.now() - startedAt,
                trigger,
              });
            } catch {
              // Best-effort on the sealed path.
            }
          };

          const shutdown = async (trigger: ServerStopTrigger): Promise<void> => {
            if (shuttingDown) return;
            shuttingDown = true;
            // Drain an in-flight refresh tick before the store closes — a
            // rotated refresh_token arriving on a closed database is lost
            // permanently (the provider already invalidated the old one).
            if (refreshScheduler) await refreshScheduler.stop();
            // Same reasoning for certificate renewal: an order abandoned
            // between issuance and storage is lost for good.
            if (renewalScheduler) await renewalScheduler.stop();
            if (mcpServer && !stdioClosed) {
              auditStop("stdio", opts.allowTokenless === true, undefined, trigger);
              await mcpServer.close();
            }
            if (mcpHttpServer) {
              auditStop("http", false, mcpHttpBoundPort, trigger);
              await mcpHttpServer.close();
            }
            if (restServer) {
              auditStop("rest", false, port, trigger);
              restServer.close();
            }
            if (egressProxy) {
              auditStop("proxy", false, proxyBoundPort, trigger);
              await egressProxy.close();
            }
            for (const agentSocket of agentSockets) {
              auditStop("ssh-agent", true, undefined, trigger, agentSocket.consumer);
              await agentSocket.stop();
            }
            // Abort the REST app's pending background OAuth flows before the
            // store closes: each authorization-code flow pins a loopback
            // listener and a 5-minute timer, and its completion writes to the
            // vault. Cancellation is a synchronous abort fan-out — nothing to
            // drain, unlike the schedulers above.
            restOAuthManager?.cancelPendingFlows();
            await engine?.destroy();
            process.exit(0);
          };

          process.on("SIGINT", () => void shutdown("SIGINT"));
          process.on("SIGTERM", () => void shutdown("SIGTERM"));

          // When stdio MCP runs alongside an HTTP server, MCP owns stdout for JSON-RPC.
          // Redirect console.log to stderr so HTTP startup messages don't corrupt the stream.
          if (opts.mcp && (opts.rest || opts.mcpHttp || opts.proxy || opts.sshAgent)) {
            console.log = console.error;
          }

          if (opts.mcp) {
            const { createStdioServerFactory } = await import("@harpoc/mcp-server");
            const { serveStdio } = await import("@modelcontextprotocol/server/stdio");
            // The launch token arrives through --token-file or the ambient
            // HARPOC_TOKEN (the file wins) — never argv (R9/A10). A profile-set
            // variable must not error out --rest-only starts, so the env var
            // is never checked without --mcp.
            const factory = createStdioServerFactory({
              engine,
              launchToken: fileToken ?? process.env.HARPOC_TOKEN,
              allowTokenless: opts.allowTokenless,
              enableTtyPrompt: true,
            });
            const handle = serveStdio(factory, {
              onerror: (error) =>
                process.stderr.write(`[harpoc] MCP stdio error: ${error.message}\n`),
            });
            mcpServer = handle;
            // The SDK transport listens for data and error only: an MCP host
            // that hangs up (stdin EOF) closes nothing. That hang-up is the
            // stdio server's graceful stop (R4/D67) — alone, it ends the
            // process; beside a listener or a scheduler it ends only the stdio
            // server, and the rest keeps serving.
            process.stdin.once("end", () => {
              if (stdioClosed || shuttingDown) return;
              stdioClosed = true;
              auditStop("stdio", opts.allowTokenless === true, undefined, "transport_closed");
              const alone =
                !opts.rest &&
                !opts.mcpHttp &&
                !opts.proxy &&
                !opts.sshAgent &&
                !opts.oauthRefresh &&
                !opts.certRenew;
              const closed = handle.close().catch(() => undefined);
              if (alone) void closed.then(() => shutdown("transport_closed"));
            });
            console.error("[harpoc] MCP server running on stdio");
          }

          if (opts.mcpHttp) {
            const { startMcpHttpServer } = await import("@harpoc/mcp-server");
            const server = await startMcpHttpServer({ engine, port: mcpHttpPort });
            mcpHttpServer = server;
            mcpHttpBoundPort = server.port;
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
            restServer = await startServer({
              engine,
              port,
              hostname: opts.host,
              allowedHosts: opts.allowedHost,
              oauthManager,
              uiDir,
            });
            if (opts.ui) {
              // Fragment, not query: the token must never appear in a request
              // line a server or proxy could log.
              const launchToken = engine.createToken(
                "web-ui",
                [Permission.ADMIN],
                uiTokenTtlMs ?? MAX_TOKEN_TTL_MS,
                {
                  principalType: "user",
                  label: "web-ui launch",
                },
              );
              console.error(
                `[harpoc] Web UI: http://${opts.host}:${String(port)}/ui#token=${launchToken}`,
              );
              const validity =
                uiTokenTtlMs === undefined ? "24 h cap" : `${String(uiTokenTtlMs / 60_000)} min`;
              console.error(
                `[harpoc] The link grants admin access until the token expires (${validity}). Do not share it.`,
              );
            }
          }

          if (opts.proxy) {
            const { createEgressProxy } = await import("@harpoc/egress-proxy");
            const proxy = createEgressProxy({ engine });
            const { port: boundPort } = await proxy.listenTcp(proxyPort, "127.0.0.1");
            egressProxy = proxy;
            proxyBoundPort = boundPort;
            for (const socketPath of proxySockets) await proxy.listenSocket(socketPath);
            const sockets =
              runtimeDir === undefined
                ? " (TCP only: no --runtime-dir)"
                : proxySockets.length === 0
                  ? ` (TCP only: no consumer directory under ${runtimeDir.path})`
                  : ` and ${String(proxySockets.length)} consumer socket${proxySockets.length === 1 ? "" : "s"} (<consumer>/proxy.sock)`;
            console.error(
              `[harpoc] egress proxy listening on http://127.0.0.1:${String(boundPort)}${sockets}`,
            );
          }

          if (opts.sshAgent && runtimeDir !== undefined) {
            const { AgentSocketServer } = await import("@harpoc/core");
            for (const socketPath of sshAgentSockets) {
              const consumer = basename(dirname(socketPath));
              // Kept as each start resolves: a signal during a start stops only the sockets
              // already serving and writes no stop row for the pending one (E-11).
              agentSockets.push(
                await AgentSocketServer.start({
                  socketPath,
                  consumer,
                  engine,
                  onError: (err) => {
                    // The code alone: the refusal's row is the engine's; no message reaches stderr.
                    if (shuttingDown) return;
                    console.error(`[harpoc] ssh-agent ${consumer}: ${err.code}`);
                  },
                }),
              );
            }
            const count = sshAgentSockets.length;
            console.error(
              `[harpoc] ssh-agent listening on ${String(count)} consumer socket${count === 1 ? "" : "s"} (<consumer>/ssh-agent.sock) under ${runtimeDir.path}`,
            );
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
                onRenewError: (secretId, err, phase) => {
                  if (shuttingDown) return;
                  const detail = err instanceof Error ? err.message : String(err);
                  console.error(
                    phase === "audit"
                      ? `Warning: the failed-renewal audit row could not be written (${secretId}): ${detail}`
                      : `Warning: certificate renewal failed (${secretId}): ${detail}`,
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
