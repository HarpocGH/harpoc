import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { startMcpHttpServer } from "@harpoc/mcp-server";
import type { McpHttpServer } from "@harpoc/mcp-server";
import type { Permission } from "@harpoc/shared";
import type { HarnessVault } from "../vault.js";
import type { CallOutcome, Surface } from "./surface.js";

export type { CallOutcome } from "./surface.js";

export interface McpHttpSurface extends Surface {
  name: "mcp-http";
  /**
   * The connected client, exposed so the Phase 4 Harpoc arm can drive the
   * metadata surfaces (`list_secrets`, `get_secret_info`, resources) that
   * §6.2.1 probes alongside `use_secret`. Kept off the base `Surface` type: the
   * demonstration matrix only ever calls `use_secret`, and widening the
   * contract every surface must satisfy for one consumer's benefit would force
   * four other drivers to expose a client they have no use for.
   */
  client: Client;
}

export function textOf(result: { content?: unknown }): string {
  const content = result.content as Array<{ type: string; text?: string }> | undefined;
  return (content ?? []).map((c) => c.text ?? "").join("\n");
}

/**
 * The surface the thesis names for Tier-1 evidence: Harpoc's own MCP server
 * over the real Streamable HTTP wire, reached by a scripted client carrying a
 * scoped, vault-signed Bearer token (C-1, C-2). Never `--allow-tokenless`: a
 * tokenless run skips token expiry, the revocation recheck, per-secret policy,
 * configuration gating, enumeration filtering and audit scope filtering, and
 * would report passes that say nothing about the deployed posture.
 */
export async function startMcpHttpSurface(
  vault: HarnessVault,
  principal: string,
  scopes: Permission[],
): Promise<McpHttpSurface> {
  const server: McpHttpServer = await startMcpHttpServer({ engine: vault.engine, port: 0 });
  const token = vault.engine.createToken(principal, scopes);

  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${server.port}${server.endpoint}`),
    { requestInit: { headers: { Authorization: `Bearer ${token}` } } },
  );
  const client = new Client({ name: "harpoc-e2e-client", version: "1.0.0" });
  await client.connect(transport);

  return {
    name: "mcp-http",
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
