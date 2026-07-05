import { serve } from "@hono/node-server";
import type { VaultEngine } from "@harpoc/core";
import { VaultState } from "@harpoc/shared";
import { createApp } from "./app.js";

export interface ServerOptions {
  engine: VaultEngine;
  port?: number;
  /** Bind address. Loopback by default (thesis §4.1); override for shared/team deployments. */
  hostname?: string;
}

export function startServer(options: ServerOptions): ReturnType<typeof serve> {
  const { engine, port = 3000, hostname = "127.0.0.1" } = options;

  if (engine.getState() === VaultState.SEALED) {
    console.warn("[harpoc] Warning: Vault is SEALED. All protected endpoints will return 503.");
  }

  if (!["127.0.0.1", "::1", "localhost"].includes(hostname)) {
    console.warn(
      `[harpoc] Warning: REST API binding to non-loopback address ${hostname} — traffic leaves the host; ensure network-level protection and TLS termination.`,
    );
  }

  const app = createApp(engine);

  const server = serve({ fetch: app.fetch, port, hostname });
  console.log(`[harpoc] REST API listening on ${hostname}:${port}`);

  return server;
}
