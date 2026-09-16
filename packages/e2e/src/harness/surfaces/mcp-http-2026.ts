import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { startMcpHttpServer } from "@harpoc/mcp-server";
import type { McpHttpServer } from "@harpoc/mcp-server";
import type { Permission } from "@harpoc/shared";
import type { HarnessVault } from "../vault.js";
import { ensureAgent } from "../vault.js";
import { textOf } from "./mcp-http.js";
import type { CallOutcome, Surface } from "./surface.js";

export interface McpHttp2026Surface extends Surface {
  name: "mcp-http-2026";
  /**
   * The connected client, exposed so the Phase 4 Harpoc arm can drive the
   * metadata surfaces (`list_secrets`, `get_secret_info`, resources) that
   * §6.2.1 probes alongside `use_secret`. Kept off the base `Surface` type: the
   * demonstration matrix only ever calls `use_secret`, and widening the
   * contract every surface must satisfy for one consumer's benefit would force
   * six other drivers to expose a client they have no use for.
   */
  client: Client;
}

/**
 * Never `--allow-tokenless`: a tokenless run skips token expiry, the revocation
 * recheck, per-secret policy, configuration gating, enumeration filtering and
 * audit scope filtering, and would report passes that say nothing about the
 * deployed posture.
 */
export async function startMcpHttp2026Surface(
  vault: HarnessVault,
  principal: string,
  scopes: Permission[],
): Promise<McpHttp2026Surface> {
  ensureAgent(vault, principal);
  const server: McpHttpServer = await startMcpHttpServer({ engine: vault.engine, port: 0 });
  const token = vault.engine.createToken(principal, scopes);

  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${server.port}${server.endpoint}`),
    { requestInit: { headers: { Authorization: `Bearer ${token}` } } },
  );
  const client = new Client(
    { name: "harpoc-e2e-client-2026", version: "1.0.0" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  await client.connect(transport);

  return {
    name: "mcp-http-2026",
    interfaceId: "mcp",
    auditInterface: "mcp-http",
    principal,
    client,
    async callUseSecret(handle, action): Promise<CallOutcome> {
      const raw = (await client.callTool({
        name: "use_secret",
        arguments: { handle, action },
      })) as { isError?: boolean; content?: unknown };

      const text = textOf(raw);
      if (raw.isError === true) return { ok: false, result: raw, text, errorText: text };
      return { ok: true, result: raw, text };
    },
    async close() {
      await client.close();
      await server.close();
    },
  };
}
