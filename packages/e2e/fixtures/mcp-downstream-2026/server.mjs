// Downstream MCP server on the 2026-07-28 revision only — the SDK v2 handler
// with legacy traffic rejected, so a vault pinned to the modern era is proved
// against a server that speaks nothing else. Records every Authorization value
// it is handed (/recorded) like the 1.30.0 fixtures; one handler for the
// process, a fresh McpServer per request, the header carried into the factory
// by the same AsyncLocalStorage idiom the vault's own listener uses.
import { AsyncLocalStorage } from "node:async_hooks";
import { createServer } from "node:http";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { toNodeHandler } from "@modelcontextprotocol/node";

const PORT = Number(process.env.PORT ?? 8092);
const MAX_RECORDED = 100;
// Kept byte-identical in src/harness/backends.ts (MCP_DOWNSTREAM_2026.benignMarker).
const BENIGN_MARKER = "mcp-downstream-2026-benign-marker";

const recorded = [];
function record(authorization) {
  if (typeof authorization !== "string" || authorization === "") return;
  recorded.push(authorization);
  if (recorded.length > MAX_RECORDED) recorded.shift();
}
function bearerOf(authorization) {
  if (typeof authorization !== "string") return null;
  const match = /^Bearer\s+(.*)$/i.exec(authorization);
  return match ? match[1] : authorization;
}

const requestAuthorization = new AsyncLocalStorage();

const handler = createMcpHandler(
  () => {
    const authorization = requestAuthorization.getStore();
    const server = new McpServer({ name: "harpoc-e2e-downstream-2026", version: "1.0.0" });
    server.registerTool(
      "reveal",
      { description: "Returns the Authorization header value this downstream server received." },
      () => ({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              authorization: authorization ?? null,
              received_credential: bearerOf(authorization),
              marker: BENIGN_MARKER,
            }),
          },
        ],
      }),
    );
    return server;
  },
  { legacy: "reject" },
);
const mcp = toNodeHandler(handler);

const httpServer = createServer((req, res) => {
  void (async () => {
    const url = new URL(req.url ?? "/", "http://mcp-downstream-2026");
    if (url.pathname === "/health") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
      return;
    }
    if (url.pathname === "/recorded") {
      if (req.method === "DELETE") {
        recorded.length = 0;
        res.writeHead(204);
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ authorizations: recorded }));
      return;
    }
    if (url.pathname !== "/mcp") {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
      return;
    }
    record(req.headers["authorization"]);
    await requestAuthorization.run(req.headers["authorization"], () => mcp(req, res));
  })();
});

httpServer.listen(PORT, "0.0.0.0", () => {
  process.stdout.write(`mcp-downstream-2026 listening on ${String(PORT)}\n`);
});
