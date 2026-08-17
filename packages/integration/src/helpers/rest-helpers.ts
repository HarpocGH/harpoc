import type { AddressInfo } from "node:net";
import { serve } from "@hono/node-server";
import type { VaultEngine } from "@harpoc/core";
import { createApp } from "@harpoc/rest-api";
import type { CreateAppOptions } from "@harpoc/rest-api";

export interface TestServer {
  baseUrl: string;
  close: () => Promise<void>;
}

/**
 * Start a real HTTP server on port 0 (random port) for RestClient tests.
 * Returns the base URL and a close function. `options` is threaded to
 * `createApp`, so a test that needs to observe or cancel what the app's
 * managers are doing in the background can inject its own.
 */
export function startTestServer(engine: VaultEngine, options?: CreateAppOptions): TestServer {
  const app = createApp(engine, options);
  const server = serve({ fetch: app.fetch, port: 0 });

  const addr = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  return {
    baseUrl,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
