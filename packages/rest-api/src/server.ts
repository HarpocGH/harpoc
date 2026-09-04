import { serve } from "@hono/node-server";
import type { VaultEngine } from "@harpoc/core";
import type { CertManager } from "@harpoc/cert-manager";
import type { OAuthManager } from "@harpoc/oauth-proxy";
import { assertBindAllowed, buildAllowedHostSet, VaultError, VaultState } from "@harpoc/shared";
import { createApp } from "./app.js";

export interface ServerOptions {
  engine: VaultEngine;
  port?: number;
  /** Bind address. Loopback by default (thesis §4.1); override for shared/team deployments. */
  hostname?: string;
  /**
   * Host names clients reach this listener by (R11/D61). Required for a
   * non-loopback bind; additive on loopback, where 127.0.0.1, ::1 and
   * localhost are always allowed.
   */
  allowedHosts?: readonly string[];
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

  // A non-loopback bind is refused without an allowed host (R11/D61) — the
  // former warning was the only notice, and a launcher's log pipe swallowed it.
  assertBindAllowed(hostname, options.allowedHosts ?? []);
  const allowedHostSet = buildAllowedHostSet(hostname, options.allowedHosts ?? []);

  const app = createApp(engine, { ...options, allowedHostSet });

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
