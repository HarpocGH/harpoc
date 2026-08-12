import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Permission } from "@harpoc/shared";
import type { HarnessVault } from "../vault.js";
import { resolveMcpServerEntry } from "../fixtures.js";
import { textOf } from "./mcp-http.js";
import type { CallOutcome, Surface } from "./surface.js";

export interface McpStdioSurface extends Surface {
  name: "mcp-stdio";
}

/**
 * MCP's other transport: the compiled `harpoc-mcp` binary as a real child
 * process, spoken to over real stdio framing by a scripted client.
 *
 * Two properties of this driver are load-bearing.
 *
 * The launch token travels in the child's ENVIRONMENT, never argv — argv is
 * readable by any local process, which is why the CLI's own help says so. Since
 * V3 the token is also mandatory: without it the child exits with
 * TOKEN_REQUIRED, and `--allow-tokenless` is never passed (C-2).
 *
 * The whole parent environment is forwarded explicitly, because
 * StdioClientTransport otherwise applies its own allowlist and silently drops
 * everything else. The child would then lose HARPOC_SESSION_KEYSTORE (and read
 * a session file the harness wrote unwrapped as if it were keystore-wrapped),
 * NODE_EXTRA_CA_CERTS (no fixture-CA trust, so the http cell's TLS fails) and
 * the PATH ordering that puts the native ssh first on Windows — three failures
 * that would surface far from their cause.
 *
 * The child runs its OWN vault engine against the same vault directory as the
 * harness: this is the repository's first two-process vault access, reading the
 * session file the harness's `initVault` wrote.
 */
export async function startMcpStdioSurface(
  vault: HarnessVault,
  principal: string,
  scopes: Permission[],
): Promise<McpStdioSurface> {
  const token = vault.engine.createToken(principal, scopes);
  const entry = resolveMcpServerEntry();

  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined) env[key] = value;
  }
  env["HARPOC_TOKEN"] = token;

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entry, "--vault-dir", vault.tmpDir],
    env,
    stderr: "pipe",
  });

  const client = new Client({ name: "harpoc-e2e-stdio-client", version: "1.0.0" });
  await client.connect(transport);

  return {
    name: "mcp-stdio",
    interfaceId: "mcp",
    // The stdio transport is the plain `mcp` interface; `mcp-http` is the
    // Streamable-HTTP one. Cells assert the distinction rather than assume it.
    auditInterface: "mcp",
    principal,
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
      await transport.close();
    },
  };
}
