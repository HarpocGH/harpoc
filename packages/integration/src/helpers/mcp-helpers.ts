import { inMemoryClientFor } from "@harpoc/test-utils";
import type { McpServer } from "@modelcontextprotocol/server";

export interface ToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

/**
 * `JSON.parse` of an empty tool result dies as a bare "Unexpected end of JSON
 * input" naming neither the tool nor the error flag that explains it — so the
 * emptiness is asserted first and the caller named.
 */
export function parseToolResult(result: ToolResult, context: string): unknown {
  const text = result.content[0]?.text;
  if (!text) {
    throw new Error(`empty tool result in ${context} (isError=${String(result.isError ?? false)})`);
  }
  return JSON.parse(text);
}

/**
 * Call an MCP tool over the SDK's in-memory wire — for tests about TOOL LOGIC
 * only. The in-memory transport carries no HTTP layer (no Bearer auth, no
 * session fingerprint pinning); transport-level behavior is covered by
 * mcp-http-transport.test.ts against the real Streamable HTTP wire.
 */
export async function callTool(
  server: McpServer,
  name: string,
  args: Record<string, unknown>,
): Promise<ToolResult> {
  return (await inMemoryClientFor(server)).callTool(name, args);
}

export interface ToolDescriptor {
  name: string;
  description?: string;
  inputSchema: { properties?: Record<string, unknown> };
}

/**
 * List the registered tools over the same wire. The advertised inputSchema is
 * the agent-facing contract — what a model may be asked for — so a pin on its
 * property names is a pin on that contract.
 */
export async function listTools(server: McpServer): Promise<ToolDescriptor[]> {
  return (await inMemoryClientFor(server)).listTools();
}

/** Over the wire; a resource handler's throw arrives as the SDK's ProtocolError. */
export async function readResource(
  server: McpServer,
  uri: string,
): Promise<{ contents: Array<{ uri: string; mimeType?: string; text?: string }> }> {
  return (await inMemoryClientFor(server)).readResource(uri);
}
