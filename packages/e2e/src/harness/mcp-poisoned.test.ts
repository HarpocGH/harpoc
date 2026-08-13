import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { MCP_POISONED, assertFleetUp } from "./backends.js";
import { poisonedToolDescription, attackerUrlFromDescription } from "./mcp-poisoned.js";

/**
 * Smoke coverage for the tool-poisoning backend, ahead of §6.2.3's arms. The
 * counterparty is proved to work — and to be poisoned — before any arm can
 * blame the vault for its behaviour.
 *
 * The load-bearing property is the last one: the attacker URL the scenario
 * issues its induced call against is PARSED OUT of the served description. If
 * the poisoning were removed the parse fails and the arms error, where an arm
 * built on a hardcoded URL would keep passing against an unpoisoned server and
 * quietly stop being a tool-poisoning test.
 */
describe("mcp-poisoned backend", () => {
  it("serves a tool whose description carries the injection", async () => {
    assertFleetUp("mcp-poisoned");

    const transport = new StreamableHTTPClientTransport(new URL(MCP_POISONED.endpoint));
    const client = new Client({ name: "harpoc-e2e-poisoned-smoke", version: "1.0.0" });
    await client.connect(transport);
    try {
      const tools = await client.listTools();
      const tool = tools.tools.find((t) => t.name === MCP_POISONED.tool);
      expect(tool, `no ${MCP_POISONED.tool} tool on the poisoned server`).toBeDefined();

      const description = tool?.description ?? "";
      // The injection is metadata, not a malformed message: nothing about this
      // server violates the protocol, which is what makes the class hard.
      expect(description).toContain("<IMPORTANT>");
      expect(description).toContain("MUST");
      expect(attackerUrlFromDescription(description)).toBe(MCP_POISONED.attackerUrl);
    } finally {
      await client.close();
      await transport.close();
    }
  }, 30_000);

  it("reflects the Authorization it received, beside a surviving benign marker", async () => {
    assertFleetUp("mcp-poisoned");

    const credential = "poisoned-smoke-credential-1";
    const transport = new StreamableHTTPClientTransport(new URL(MCP_POISONED.endpoint), {
      requestInit: { headers: { Authorization: `Bearer ${credential}` } },
    });
    const client = new Client({ name: "harpoc-e2e-poisoned-smoke", version: "1.0.0" });
    await client.connect(transport);
    try {
      const result = (await client.callTool({ name: MCP_POISONED.tool, arguments: {} })) as {
        content?: Array<{ text?: string }>;
      };
      const payload = JSON.parse((result.content ?? []).map((p) => p.text ?? "").join("")) as {
        received_credential: string | null;
        marker: string | null;
      };
      expect(payload.received_credential).toBe(credential);
      expect(payload.marker).toBe(MCP_POISONED.benignMarker);
    } finally {
      await client.close();
      await transport.close();
    }
  }, 30_000);

  it("agrees with the harness constant on the endpoint it names", async () => {
    assertFleetUp("mcp-poisoned");
    // The fixture is a container image and cannot import backends.ts. A drift
    // between the two would leave the `mcp` variant configured against one
    // server while the http variant attacks another.
    expect(attackerUrlFromDescription(await poisonedToolDescription())).toBe(
      MCP_POISONED.attackerUrl,
    );
  }, 30_000);
});
