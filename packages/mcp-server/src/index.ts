#!/usr/bin/env node

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import {
  assertBindAllowed,
  VAULT_DB_NAME,
  VAULT_DIR_NAME,
  SESSION_FILE_NAME,
} from "@harpoc/shared";
import type { ServerStopTrigger, ServerTransport } from "@harpoc/shared";
import { createBridgeServer, restClientFromTokenFile } from "./bridge.js";
import {
  DEFAULT_MCP_HTTP_PORT,
  parseAllowedHostsOption,
  parseAllowTokenlessOption,
  parseHttpPortOption,
  parseTokenFileOption,
  parseUrlOption,
  parseVaultDirOption,
  readLaunchTokenFile,
} from "./cli-options.js";
import { installSignalLatch } from "./signal-latch.js";
import type { SignalLatch } from "./signal-latch.js";

// The `harpoc-mcp` binary only — the library entry is `lib.ts`. Nothing on
// this static graph loads the engine: `--url` runs without it (B1).
export {};

function resolveVaultDir(vaultDirOption?: string): string {
  if (vaultDirOption !== undefined) return vaultDirOption;
  const cwdVault = join(process.cwd(), VAULT_DIR_NAME);
  if (existsSync(cwdVault)) return cwdVault;
  return join(homedir(), VAULT_DIR_NAME);
}

async function main(): Promise<void> {
  // First, before argv: a stop that lands anywhere in the start-up meets a
  // handler, never the signal's default disposition (D8, 2026-09-07).
  const latch = installSignalLatch();
  const { values } = parseArgs({
    options: {
      token: { type: "string" },
      "token-file": { type: "string" },
      "allow-tokenless": { type: "boolean" },
      "vault-dir": { type: "string" },
      url: { type: "string" },
      http: { type: "boolean" },
      port: { type: "string" },
      host: { type: "string" },
      "allowed-host": { type: "string", multiple: true },
    },
    strict: false,
  });

  // `--token` is declared only to be refused: under `strict: false` an
  // undeclared flag would be swallowed and the JWT silently ignored (R9/A10).
  if (values.token !== undefined) {
    process.stderr.write(
      "Error: --token was removed: pass the launch token via the HARPOC_TOKEN environment variable or --token-file <path> — command-line arguments are visible to other local processes.\n",
    );
    process.exit(1);
  }

  const tokenFileOption = parseTokenFileOption(values["token-file"]);
  if (!tokenFileOption.ok) {
    process.stderr.write(tokenFileOption.message);
    process.exit(1);
  }
  const tokenFile = tokenFileOption.value;

  const allowTokenlessOption = parseAllowTokenlessOption(values["allow-tokenless"]);
  if (!allowTokenlessOption.ok) {
    process.stderr.write(allowTokenlessOption.message);
    process.exit(1);
  }
  const allowTokenless = allowTokenlessOption.value;

  const vaultDirOption = parseVaultDirOption(values["vault-dir"]);
  if (!vaultDirOption.ok) {
    process.stderr.write(vaultDirOption.message);
    process.exit(1);
  }

  // `--url` is the REST bridge (B1): stdio in, REST out, no engine — so the
  // flags that reach for a vault, a listener or the waiver are refused here.
  const urlOption = parseUrlOption(values.url);
  if (!urlOption.ok) {
    process.stderr.write(urlOption.message);
    process.exit(1);
  }
  const url = urlOption.value;
  if (url !== undefined && values.http) {
    process.stderr.write(
      "Error: --url is not supported with --http. The bridge serves stdio only; the Streamable HTTP listener runs in the vault's own process.\n",
    );
    process.exit(1);
  }
  if (url !== undefined && vaultDirOption.value !== undefined) {
    process.stderr.write(
      "Error: --url conflicts with --vault-dir. The bridge opens no vault; the REST server at --url holds it.\n",
    );
    process.exit(1);
  }
  if (url !== undefined && allowTokenless) {
    process.stderr.write(
      "Error: --allow-tokenless is not supported with --url. The bridge holds no engine; the REST server verifies the token on every request.\n",
    );
    process.exit(1);
  }

  if (values.http && tokenFile !== undefined) {
    process.stderr.write(
      "Error: --token-file is not supported with --http. HTTP clients authenticate per request via Authorization: Bearer.\n",
    );
    process.exit(1);
  }

  if (values.http && allowTokenless) {
    process.stderr.write(
      "Error: --allow-tokenless is not supported with --http. The Streamable HTTP transport has no tokenless mode.\n",
    );
    process.exit(1);
  }

  if (allowTokenless && (tokenFile !== undefined || process.env.HARPOC_TOKEN)) {
    process.stderr.write(
      "Error: --allow-tokenless conflicts with a launch token (--token-file / HARPOC_TOKEN). Provide one or the other.\n",
    );
    process.exit(1);
  }

  const parsedPort = parseHttpPortOption(values.port as string | undefined);
  if (values.http && !parsedPort.ok) {
    process.stderr.write(parsedPort.message);
    process.exit(1);
  }
  const port = parsedPort.ok ? parsedPort.port : DEFAULT_MCP_HTTP_PORT;

  const parsedHosts = parseAllowedHostsOption(values["allowed-host"]);
  if (!parsedHosts.ok) {
    process.stderr.write(parsedHosts.message);
    process.exit(1);
  }
  if (!values.http && parsedHosts.hosts.length > 0) {
    process.stderr.write("Error: --allowed-host requires --http.\n");
    process.exit(1);
  }
  const host = (values.host as string | undefined) ?? "127.0.0.1";
  // Refused here, before the vault opens, for the same reason as the port:
  // a misconfigured listener must not cost a session (R11/D61).
  if (values.http) {
    try {
      assertBindAllowed(host, parsedHosts.hosts);
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    }
  }

  if (url !== undefined && tokenFile === undefined) {
    process.stderr.write(
      "Error: --url requires --token-file <path>. The REST server verifies that token on every request.\n",
    );
    process.exit(1);
  }

  // Read before any vault is opened, like the port refusal: a bad file never
  // touches the session.
  let fileToken: string | undefined;
  if (tokenFile !== undefined) {
    const read = readLaunchTokenFile(tokenFile);
    if (!read.ok) {
      process.stderr.write(read.message);
      process.exit(1);
    }
    fileToken = read.token;
  }

  if (url !== undefined && tokenFile !== undefined) {
    await serveBridge(url, tokenFile, latch);
    return;
  }

  const vaultDir = resolveVaultDir(vaultDirOption.value);
  const dbPath = join(vaultDir, VAULT_DB_NAME);
  const sessionPath = join(vaultDir, SESSION_FILE_NAME);

  // The engine path's modules load here, past every refusal — never on the
  // bridge path, whose process must not resolve `@harpoc/core` (B1).
  const [{ VaultEngine }, { startMcpHttpServer }, { createStdioServerFactory }] = await Promise.all(
    [import("@harpoc/core"), import("./http.js"), import("./server.js")],
  );

  // stdout is the transport; a session-file or job-wrapper warning goes where the banner goes.
  const engine = new VaultEngine({
    dbPath,
    sessionPath,
    onSessionFilePermissionRepairFailure: (error) => {
      process.stderr.write(`Warning: ${error.message}\n`);
    },
    onJobWrapperUnavailable: (reason) => {
      process.stderr.write(
        `Warning: the Windows job wrapper is unavailable (${reason}); spawns run on the taskkill tier and strict_tree_exit secrets refuse\n`,
      );
    },
  });

  const loaded = await engine.loadSession();
  if (!loaded) {
    process.stderr.write("Error: Vault is locked. Run `harpoc unlock` first.\n");
    process.exit(1);
  }

  // A stop that arrived while the session loaded: nothing has started and
  // nothing is recorded, so the start is skipped rather than begun.
  if (latch.pending() !== null) {
    await engine.destroy();
    process.exit(0);
  }

  const startedAt = Date.now();
  const tokenless = allowTokenless;
  let close: () => Promise<void>;
  // `harpoc-mcp` serves two of the three transports; `rest` is the CLI's.
  // The narrowing is deliberate (R21/D1) — the union is shared, the subset
  // is local.
  let transport: Extract<ServerTransport, "stdio" | "http">;
  let boundPort: number | undefined;
  let banner: string;
  let shuttingDown = false;

  // The stop row mirrors the start row (R4/D67). A sealed vault cannot take
  // it, and a stop that cannot be recorded must not block the stop.
  const shutdown = async (trigger: ServerStopTrigger): Promise<void> => {
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
    const httpServer = await startMcpHttpServer({
      engine,
      port,
      host,
      allowedHosts: parsedHosts.hosts,
    });
    close = httpServer.close;
    transport = "http";
    boundPort = httpServer.port;
    banner = `Harpoc MCP server listening on http://${host}:${httpServer.port}${httpServer.endpoint} (Streamable HTTP)\n`;
  } else {
    // The launch token arrives through --token-file or the ambient
    // HARPOC_TOKEN (the file wins) — never argv (R9/A10). It is only read for
    // stdio — a profile-set variable must not affect --http, which
    // authenticates per request.
    const factory = createStdioServerFactory({
      engine,
      launchToken: fileToken ?? (process.env.HARPOC_TOKEN || undefined),
      allowTokenless,
      enableTtyPrompt: true,
    });
    const stdio = serveStdio(factory, {
      onerror: (error) => process.stderr.write(`[harpoc] MCP stdio error: ${error.message}\n`),
    });
    close = () => stdio.close();
    transport = "stdio";
    // The SDK transport listens for data and error only: an MCP host that
    // hangs up (stdin EOF) closes nothing. That hang-up is this server's
    // graceful stop.
    process.stdin.once("end", () => void shutdown("transport_closed"));
    banner = "Harpoc MCP server running on stdio\n";
  }

  // Armed after the transport is up and its start row written: a stop that
  // arrived during the setup runs the normal shutdown now, so the start row
  // pairs with its stop row. The banner is the readiness signal a launcher
  // keys on (the integration twin sends SIGTERM the moment it appears), so it
  // follows the arming — written first, a stop sent on seeing it could still
  // meet SIGTERM's default disposition, the race the Linux CI leg caught at
  // 0100d3e — and is not written at all for a server already stopping.
  latch.arm((trigger) => void shutdown(trigger));
  if (shuttingDown) return;
  process.stderr.write(banner);
}

/**
 * `harpoc-mcp --url <base> --token-file <path>` (B1): the stdio transport in
 * front of the REST server, holding no engine and no session — so it writes
 * no `server.start` row; the REST server's own rows record every request it
 * forwards. The stop is the stdio server's: stdin EOF or a stop signal, then
 * exit 0; the banner follows the arming, as above.
 */
async function serveBridge(url: URL, tokenFile: string, latch: SignalLatch): Promise<void> {
  const baseUrl = `${url.origin}${url.pathname}`.replace(/\/+$/, "");
  const client = restClientFromTokenFile(baseUrl, tokenFile);
  const bridge = serveStdio(() => createBridgeServer({ client, baseUrl }), {
    onerror: (error) => process.stderr.write(`[harpoc] MCP stdio error: ${error.message}\n`),
  });
  let stopping = false;
  const stop = async (): Promise<void> => {
    if (stopping) return;
    stopping = true;
    await bridge.close();
    process.exit(0);
  };
  process.stdin.once("end", () => void stop());
  latch.arm(() => void stop());
  if (stopping) return;
  process.stderr.write(`Harpoc MCP bridge → ${baseUrl} (stdio)\n`);
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
