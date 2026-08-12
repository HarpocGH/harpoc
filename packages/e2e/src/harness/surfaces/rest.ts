import { serve } from "@hono/node-server";
import type { AddressInfo } from "node:net";
import { createApp } from "@harpoc/rest-api";
import type { Permission } from "@harpoc/shared";
import type { HarnessVault } from "../vault.js";
import type { CallOutcome, Surface } from "./surface.js";

export interface RestSurface extends Surface {
  name: "rest";
}

/**
 * The REST access interface, over a real socket. The repository's existing
 * `/use` coverage goes through Hono's in-process `app.request()`, which never
 * serializes a request onto a wire; this driver listens on an ephemeral port
 * and speaks HTTP to it, so the arms exercise the deployed path.
 *
 * The request is hand-built rather than delegated to `RestClient` on purpose:
 * the `sdk` surface is the one that drives the client library, and two cells
 * asserting the same client code would count as two interfaces while covering
 * one.
 */
export async function startRestSurface(
  vault: HarnessVault,
  principal: string,
  scopes: Permission[],
): Promise<RestSurface> {
  const app = createApp(vault.engine);
  // The bind is asynchronous: `serve()` returns before the socket is listening,
  // so the port has to come from the ready callback, not from a same-tick
  // `address()` (which is still null).
  const { server, port } = await new Promise<{ server: ReturnType<typeof serve>; port: number }>(
    (resolve) => {
      const started = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, (info) => {
        resolve({ server: started, port: (info as AddressInfo).port });
      });
    },
  );
  const baseUrl = `http://127.0.0.1:${String(port)}`;
  const token = vault.engine.createToken(principal, scopes);

  return {
    name: "rest",
    interfaceId: "rest",
    auditInterface: "rest",
    principal,
    async callUseSecret(handle, action): Promise<CallOutcome> {
      const raw = handle.startsWith("secret://") ? handle.slice("secret://".length) : handle;
      const response = await fetch(`${baseUrl}/api/v1/secrets/${encodeURIComponent(raw)}/use`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ action }),
        signal: AbortSignal.timeout(120_000),
      });

      const text = await response.text();
      let parsed: { data?: unknown; error?: string; message?: string } = {};
      try {
        parsed = JSON.parse(text) as typeof parsed;
      } catch {
        // A non-JSON body is itself the observation; `text` carries it verbatim.
      }

      if (!response.ok) {
        const errorText = `${parsed.error ?? String(response.status)}: ${parsed.message ?? text}`;
        return { ok: false, result: parsed, text, errorText };
      }
      return { ok: true, result: parsed.data, text: JSON.stringify(parsed.data) };
    },
    async close() {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    },
  };
}
