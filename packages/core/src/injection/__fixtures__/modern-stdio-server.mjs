import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";

// `--reject-legacy` makes the fixture modern-only (M-P2-9); without it both eras are served.
serveStdio(
  () => {
    const server = new McpServer({ name: "modern-stdio-fixture", version: "1.0.0" });
    server.registerTool("reveal", { description: "Reveals a fixed text" }, async () => ({
      content: [{ type: "text", text: "modern-stdio-ok" }],
    }));
    return server;
  },
  process.argv.includes("--reject-legacy") ? { legacy: "reject" } : undefined,
);
