import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

interface ToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

/**
 * Call an MCP tool via the low-level _requestHandlers hack — for tests about
 * TOOL LOGIC only. This bypasses the real transport entirely (no Bearer auth,
 * no session fingerprint pinning); transport-level behavior is covered by
 * mcp-http-transport.test.ts against the real Streamable HTTP wire.
 * Same pattern used in @harpoc/mcp-server unit tests.
 */
export async function callTool(
  server: McpServer,
  name: string,
  args: Record<string, unknown>,
): Promise<ToolResult> {
  const lowLevel = (server as unknown as { server: { _requestHandlers: Map<string, unknown> } })
    .server;
  const handler = lowLevel._requestHandlers.get("tools/call") as (
    req: { method: string; params: { name: string; arguments?: Record<string, unknown> } },
    extra: unknown,
  ) => Promise<ToolResult>;

  if (!handler) throw new Error("No tools/call handler registered");

  return handler(
    { method: "tools/call", params: { name, arguments: args } },
    { signal: new AbortController().signal, sessionId: "integration-test" },
  );
}

export interface ToolDescriptor {
  name: string;
  description?: string;
  inputSchema: { properties?: Record<string, unknown> };
}

/**
 * List the registered tools via the same low-level hack. The advertised
 * inputSchema is the agent-facing contract — what a model may be asked for —
 * so a pin on its property names is a pin on that contract.
 */
export async function listTools(server: McpServer): Promise<ToolDescriptor[]> {
  const lowLevel = (server as unknown as { server: { _requestHandlers: Map<string, unknown> } })
    .server;
  const handler = lowLevel._requestHandlers.get("tools/list") as (
    req: { method: string; params: Record<string, never> },
    extra: unknown,
  ) => Promise<{ tools: ToolDescriptor[] }>;

  if (!handler) throw new Error("No tools/list handler registered");

  const result = await handler(
    { method: "tools/list", params: {} },
    { signal: new AbortController().signal, sessionId: "integration-test" },
  );
  return result.tools;
}

/**
 * Read an MCP resource via the low-level _requestHandlers hack.
 */
export async function readResource(
  server: McpServer,
  uri: string,
): Promise<{ contents: Array<{ uri: string; mimeType?: string; text?: string }> }> {
  const lowLevel = (server as unknown as { server: { _requestHandlers: Map<string, unknown> } })
    .server;
  const handler = lowLevel._requestHandlers.get("resources/read") as (
    req: { method: string; params: { uri: string } },
    extra: unknown,
  ) => Promise<{ contents: Array<{ uri: string; mimeType?: string; text?: string }> }>;

  if (!handler) throw new Error("No resources/read handler registered");

  return handler(
    { method: "resources/read", params: { uri } },
    { signal: new AbortController().signal, sessionId: "integration-test" },
  );
}
