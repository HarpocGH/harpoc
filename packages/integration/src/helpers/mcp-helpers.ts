import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

interface ToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

/**
 * Call an MCP tool via the low-level _requestHandlers hack.
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
