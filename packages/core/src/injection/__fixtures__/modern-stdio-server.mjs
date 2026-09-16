import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";

serveStdio(() => {
  const server = new McpServer({ name: "modern-stdio-fixture", version: "1.0.0" });
  server.registerTool("reveal", { description: "Reveals a fixed text" }, async () => ({
    content: [{ type: "text", text: "modern-stdio-ok" }],
  }));
  return server;
});
