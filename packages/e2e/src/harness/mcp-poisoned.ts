import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { MCP_POISONED } from "./backends.js";

/**
 * Read the poisoned tool's description off the live server (§6.2.3).
 *
 * Read rather than assumed: the arms issue the call the description INDUCES,
 * against the URL the description names, so the poisoning is what drives the
 * attack. An arm built on a constant would keep passing against an unpoisoned
 * server and would no longer be a tool-poisoning test.
 *
 * The connection is the harness's own, not the vault's — this is metadata an
 * agent host reads while assembling its tool list, which is precisely the
 * surface the attack lives on.
 */
export async function poisonedToolDescription(): Promise<string> {
  const transport = new StreamableHTTPClientTransport(new URL(MCP_POISONED.endpoint));
  const client = new Client({ name: "harpoc-e2e-poisoning-reader", version: "1.0.0" });
  await client.connect(transport);
  try {
    const tools = await client.listTools();
    const tool = tools.tools.find((t) => t.name === MCP_POISONED.tool);
    const description = tool?.description ?? "";
    if (description === "") {
      throw new Error(
        `the poisoned server serves no description for "${MCP_POISONED.tool}" — ` +
          "the arms would attack a URL nothing asked for",
      );
    }
    return description;
  } finally {
    await client.close();
    await transport.close();
  }
}

/**
 * The endpoint the injection names. Throws rather than falling back to a
 * default: a silent fallback is how an arm keeps reporting BLOCKED after the
 * thing it was blocking stopped being requested.
 */
export function attackerUrlFromDescription(description: string): string {
  const match = /https?:\/\/[^\s"'<>]+/.exec(description);
  if (!match) {
    throw new Error(
      `the poisoned description names no URL — cannot issue the induced call:\n${description}`,
    );
  }
  return match[0];
}

/** Empty the poisoned server's recorder and confirm it is empty. */
export async function resetPoisonedRecorder(): Promise<void> {
  const deleted = await fetch(MCP_POISONED.recordedUrl, { method: "DELETE" });
  if (deleted.status !== 204) {
    throw new Error(`poisoned recorder reset failed with status ${String(deleted.status)}`);
  }
  const remaining = await poisonedAuthorizations();
  if (remaining.length > 0) {
    throw new Error(`poisoned recorder still holds ${String(remaining.length)} entr(ies)`);
  }
}

/** What the poisoned server has actually been handed, read out of band. */
export async function poisonedAuthorizations(): Promise<string[]> {
  const response = await fetch(MCP_POISONED.recordedUrl);
  if (response.status !== 200) {
    throw new Error(`poisoned recorder query failed with status ${String(response.status)}`);
  }
  return ((await response.json()) as { authorizations: string[] }).authorizations;
}
