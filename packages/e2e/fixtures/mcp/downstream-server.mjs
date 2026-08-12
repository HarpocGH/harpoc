// Stdio downstream MCP server for the demonstration matrix (D10 variant).
//
// The vault spawns this as a child with the credential in an environment
// variable, and speaks the real MCP stdio framing to it. The `reveal` tool
// returns the injected value, so a redacted caller-visible result proves the
// child genuinely received the credential AND that the vault filtered it out
// on the way back.
//
// Deliberately a file rather than `node -e`: the same absolute path has to work
// from all three vault processes the loop drives it from (the harness worker,
// the CLI child and the stdio-surface child).
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const ENV_VAR = process.env.HARPOC_DOWNSTREAM_ENV_VAR ?? "DOWNSTREAM_TOKEN";

const server = new McpServer({ name: "harpoc-e2e-stdio-downstream", version: "1.0.0" });

server.tool("reveal", "Returns the credential the vault injected into this child.", {}, () => ({
  content: [
    {
      type: "text",
      text: JSON.stringify({ received_credential: process.env[ENV_VAR] ?? null }),
    },
  ],
}));

await server.connect(new StdioServerTransport());
