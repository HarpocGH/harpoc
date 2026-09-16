import { describe, it, expect } from "vitest";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { MCP_DOWNSTREAM_2026, assertFleetUp } from "./backends.js";

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
  pinned: boolean,
): Promise<{ client: Client; close: () => Promise<void> }> {
  const transport = new StreamableHTTPClientTransport(new URL(MCP_DOWNSTREAM_2026.endpoint), {
    requestInit: { headers: { Authorization: `Bearer ${bearer}` } },
  });
  const client = pinned
    ? new Client(
        { name: "harpoc-e2e-downstream-2026-smoke", version: "1.0.0" },
        { versionNegotiation: { mode: { pin: "2026-07-28" } } },
      )
    : new Client({ name: "harpoc-e2e-downstream-2026-legacy", version: "1.0.0" });
  try {
    await client.connect(transport);
  } catch (err) {
    await transport.close();
    throw err;
  }
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

describe("mcp-downstream-2026 backend", () => {
  it("serves the reveal tool to a pinned 2026-07-28 client and reflects the Authorization", async () => {
    assertFleetUp("mcp-downstream-2026");

    const credential = "downstream-2026-smoke-credential-1";
    const { client, close } = await connectClient(credential, true);
    try {
      expect(client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
      const tools = await client.listTools();
      expect(tools.tools.map((t) => t.name)).toContain(MCP_DOWNSTREAM_2026.tool);

      const result = await client.callTool({ name: MCP_DOWNSTREAM_2026.tool, arguments: {} });
      const payload = JSON.parse(textOf(result)) as {
        authorization: string | null;
        received_credential: string | null;
        marker: string | null;
      };
      expect(payload.authorization).toBe(`Bearer ${credential}`);
      expect(payload.received_credential).toBe(credential);
      // The arms' negative control travels in the same payload as the
      // credential — without it, blanket redaction would read as opacity.
      expect(payload.marker).toBe(MCP_DOWNSTREAM_2026.benignMarker);
    } finally {
      await close();
    }
  }, 30_000);

  it("reports the received Authorization on the out-of-band /recorded endpoint", async () => {
    assertFleetUp("mcp-downstream-2026");

    await fetch(MCP_DOWNSTREAM_2026.recordedUrl, { method: "DELETE" });
    const credential = "downstream-2026-smoke-credential-2";
    const { close } = await connectClient(credential, true);
    await close();

    const response = await fetch(MCP_DOWNSTREAM_2026.recordedUrl);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { authorizations: string[] };
    expect(body.authorizations).toContain(`Bearer ${credential}`);
  }, 30_000);

  it("refuses a legacy client: the handler serves the 2026-07-28 revision only", async () => {
    assertFleetUp("mcp-downstream-2026");

    let thrown: unknown;
    try {
      const { close } = await connectClient("downstream-2026-smoke-credential-3", false);
      await close();
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toContain("Unsupported protocol version: 2025-11-25");
    expect((thrown as Error).message).toContain('"supported":["2026-07-28"]');
  }, 30_000);
});
