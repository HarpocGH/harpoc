import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { MCP_DOWNSTREAM, assertFleetUp } from "./backends.js";

/**
 * Smoke coverage for the downstream MCP backend, ahead of the `mcp`
 * demonstration cell. Proves the counterparty works before the cell can blame
 * the vault for it: a real MCP client speaks the real Streamable HTTP transport
 * to it, the `reveal` tool reflects the Authorization it was handed, and the
 * out-of-band /recorded endpoint reports the same value — the readback the cell
 * uses to show the downstream received the credential the caller never saw.
 */
async function connectClient(
  bearer: string,
): Promise<{ client: Client; close: () => Promise<void> }> {
  const transport = new StreamableHTTPClientTransport(new URL(MCP_DOWNSTREAM.endpoint), {
    requestInit: { headers: { Authorization: `Bearer ${bearer}` } },
  });
  const client = new Client({ name: "harpoc-e2e-downstream-smoke", version: "1.0.0" });
  await client.connect(transport);
  return {
    client,
    close: async () => {
      await client.close();
      await transport.close();
    },
  };
}

function textOf(result: unknown): string {
  const raw = (result as { content?: unknown }).content;
  const content = Array.isArray(raw) ? raw : [];
  return content
    .map((part) =>
      typeof part === "object" && part !== null && "text" in part
        ? String((part as { text: unknown }).text)
        : "",
    )
    .join("");
}

describe("mcp-downstream backend", () => {
  it("serves the reveal tool and reflects the Authorization it received", async () => {
    assertFleetUp("mcp-downstream");

    const credential = "downstream-smoke-credential-1";
    const { client, close } = await connectClient(credential);
    try {
      const tools = await client.listTools();
      expect(tools.tools.map((t) => t.name)).toContain(MCP_DOWNSTREAM.tool);

      const result = await client.callTool({ name: MCP_DOWNSTREAM.tool, arguments: {} });
      const payload = JSON.parse(textOf(result)) as {
        authorization: string | null;
        received_credential: string | null;
        marker: string | null;
      };
      expect(payload.authorization).toBe(`Bearer ${credential}`);
      expect(payload.received_credential).toBe(credential);
      // The arms' negative control travels in the same payload as the
      // credential — without it, blanket redaction would read as opacity.
      expect(payload.marker).toBe(MCP_DOWNSTREAM.benignMarker);
    } finally {
      await close();
    }
  }, 30_000);

  it("reports the received Authorization on the out-of-band /recorded endpoint", async () => {
    assertFleetUp("mcp-downstream");

    await fetch(MCP_DOWNSTREAM.recordedUrl, { method: "DELETE" });
    const credential = "downstream-smoke-credential-2";
    const { close } = await connectClient(credential);
    await close();

    const response = await fetch(MCP_DOWNSTREAM.recordedUrl);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { authorizations: string[] };
    expect(body.authorizations).toContain(`Bearer ${credential}`);
  }, 30_000);
});
