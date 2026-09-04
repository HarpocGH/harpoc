import { serve } from "@hono/node-server";
import type { VaultEngine } from "@harpoc/core";
import type { CertManager } from "@harpoc/cert-manager";
import type { OAuthManager } from "@harpoc/oauth-proxy";
import { VaultError, VaultState } from "@harpoc/shared";
import { createApp } from "./app.js";

export interface ServerOptions {
  engine: VaultEngine;
  port?: number;
  /** Bind address. Loopback by default (thesis §4.1); override for shared/team deployments. */
  hostname?: string;
  /** Optional managers; `createApp` constructs REST-appropriate defaults otherwise. */
  oauthManager?: OAuthManager;
  certManager?: CertManager;
  /** Absolute path to the built Web UI; served at /ui when set. */
  uiDir?: string;
}

export function startServer(options: ServerOptions): ReturnType<typeof serve> {
  const { engine, port = 3000, hostname = "127.0.0.1" } = options;

  if (engine.getState() === VaultState.SEALED) {
    throw VaultError.vaultLocked();
  }

  if (!["127.0.0.1", "::1", "localhost"].includes(hostname)) {
    console.warn(
      `[harpoc] Warning: REST API binding to non-loopback address ${hostname} — traffic leaves the host; ensure network-level protection and TLS termination.`,
    );
  }

  const app = createApp(engine, options);

  // One row per listener start (R4/B22), before the bind like the stdio
  // waiver: no record, no listener. The port is the configured one — the CLI
  // never passes an ephemeral port here.
  engine.auditServerStart({
    transport: "rest",
    tokenless: false,
    port,
    host: hostname,
  });

  const server = serve({ fetch: app.fetch, port, hostname });
  console.log(`[harpoc] REST API listening on ${hostname}:${port}`);

  return server;
}
