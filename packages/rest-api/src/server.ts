import type { AddressInfo } from "node:net";
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

export async function startServer(options: ServerOptions): Promise<ReturnType<typeof serve>> {
  const { engine, port = 3000, hostname = "127.0.0.1" } = options;

  if (engine.getState() === VaultState.SEALED) {
    throw VaultError.vaultLocked();
  }

  // A non-loopback bind is refused without an allowed host (R11/D61) — the
  // former warning was the only notice, and a launcher's log pipe swallowed it.
  assertBindAllowed(hostname, options.allowedHosts ?? []);
  const allowedHostSet = buildAllowedHostSet(hostname, options.allowedHosts ?? []);

  const app = createApp(engine, { ...options, allowedHostSet });

  const server = serve({ fetch: app.fetch, port, hostname });
  // `serve` returns before the socket is listening and reports a failed bind
  // only as an `error` event on the server it already handed back (R26/D9).
  // Without this the process died on an unhandled EADDRINUSE — and the start
  // row had already been written for a listener that never came up.
  const boundPort = await new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.once("listening", () => {
      server.removeListener("error", reject);
      resolve((server.address() as AddressInfo).port);
    });
  });

  try {
    // One row per listener start (R4/B22), after the bind so it carries the
    // bound port — `port: 0` records the port the kernel gave. An unwritable
    // row undoes the bind: no record, no listener.
    engine.auditServerStart({
      transport: "rest",
      tokenless: false,
      port: boundPort,
      host: hostname,
    });
  } catch (err) {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    throw err;
  }

  console.log(`[harpoc] REST API listening on ${hostname}:${boundPort}`);

  return server;
}
