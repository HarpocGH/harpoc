import { serve } from "@hono/node-server";
import type { VaultEngine } from "@harpoc/core";
import { VaultState } from "@harpoc/shared";
import { createApp } from "./app.js";

export interface ServerOptions {
  engine: VaultEngine;
  port?: number;
}

export function startServer(options: ServerOptions): ReturnType<typeof serve> {
  const { engine, port = 3000 } = options;

  if (engine.getState() === VaultState.SEALED) {
    console.warn("[harpoc] Warning: Vault is SEALED. All protected endpoints will return 503.");
  }

  const app = createApp(engine);

  const server = serve({ fetch: app.fetch, port, hostname: "127.0.0.1" });
  console.log(`[harpoc] REST API listening on 127.0.0.1:${port}`);

  return server;
}
