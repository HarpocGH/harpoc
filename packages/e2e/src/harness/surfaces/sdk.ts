import { serve } from "@hono/node-server";
import type { AddressInfo } from "node:net";
import { createApp } from "@harpoc/rest-api";
import { RestClient } from "@harpoc/sdk";
import { VaultError } from "@harpoc/shared";
import type { Permission, UseSecretAction } from "@harpoc/shared";
import type { HarnessVault } from "../vault.js";
import type { CallOutcome, Surface } from "./surface.js";

export interface SdkSurface extends Surface {
  name: "sdk";
}

/**
 * The SDK access interface: `RestClient` against a running REST API.
 *
 * `DirectClient` is deliberately NOT the SDK surface. It is a one-line
 * pass-through to `VaultEngine` with no token, so a cell driven through it
 * would silently skip the token checks the demonstration exists to exercise
 * (C-2) — it would report a pass that says nothing about the deployed posture.
 * The trusted-local path it represents is covered by the `cli` surface, where
 * it is an asserted property rather than an accident.
 *
 * The listener is this surface's own: sharing one with the `rest` surface would
 * couple their lifecycles and make a per-surface audit principal ambiguous.
 */
export async function startSdkSurface(
  vault: HarnessVault,
  principal: string,
  scopes: Permission[],
): Promise<SdkSurface> {
  const app = createApp(vault.engine);
  // Asynchronous bind — see the note in the rest driver.
  const { server, port } = await new Promise<{ server: ReturnType<typeof serve>; port: number }>(
    (resolve) => {
      const started = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, (info) => {
        resolve({ server: started, port: (info as AddressInfo).port });
      });
    },
  );
  const token = vault.engine.createToken(principal, scopes);
  const client = new RestClient({
    baseUrl: `http://127.0.0.1:${String(port)}`,
    token,
    timeoutMs: 120_000,
  });

  return {
    name: "sdk",
    interfaceId: "sdk",
    // The SDK reaches the vault over the REST wire, so the vault attributes it
    // as `rest`: the access interface is what the request arrived through, not
    // which client library composed it. Cells tell the two apart by principal.
    auditInterface: "rest",
    principal,
    async callUseSecret(handle, action): Promise<CallOutcome> {
      try {
        const result = await client.useSecret(handle, action as UseSecretAction);
        return { ok: true, result, text: JSON.stringify(result) };
      } catch (err) {
        const errorText =
          err instanceof VaultError
            ? `${err.code}: ${err.message}`
            : err instanceof Error
              ? err.message
              : String(err);
        return { ok: false, result: err, text: errorText, errorText };
      }
    },
    async close() {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    },
  };
}
