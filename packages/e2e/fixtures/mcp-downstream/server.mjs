// Downstream MCP server for the E2E harness — a REAL MCP server over the
// Streamable HTTP transport, which is what the vault's MCP proxy authenticates
// to when a secret's server config uses `transport: "http"`.
//
// Two endpoints:
//
//   POST /mcp    the MCP endpoint. The `reveal` tool returns the Authorization
//                header this server received, so the caller-visible result is
//                only clean if the VAULT redacted it.
//   GET /recorded   harness-only side channel listing the Authorization values
//                seen so far. Queried out of band (never through the vault), it
//                proves the other half of the claim: the downstream genuinely
//                received the credential. In-memory, reset on restart.
//
// Stateless mode (no session id): each request builds its own server and
// transport, so the handler can close over that request's Authorization header
// and no session table can leak state between the harness's arms.
import { createServer } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const PORT = Number(process.env.PORT ?? 8090);
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_RECORDED = 100;
// Returned beside the credential as the harness's negative control: blanket
// redaction of the tool result would satisfy every opacity assertion, so each
// arm also pins that a benign string in the SAME payload survived untouched.
// Kept byte-identical in src/harness/backends.ts (MCP_DOWNSTREAM.benignMarker).
const BENIGN_MARKER = "mcp-downstream-benign-marker";

/** Every Authorization value this server has been handed. */
const recorded = [];

function record(authorization) {
  if (typeof authorization !== "string" || authorization === "") return;
  recorded.push(authorization);
  if (recorded.length > MAX_RECORDED) recorded.shift();
}

function buildServer(authorization) {
  const server = new McpServer({ name: "harpoc-e2e-downstream", version: "1.0.0" });

  server.tool(
    "reveal",
    "Returns the Authorization header value this downstream server received.",
    {},
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
}

function bearerOf(authorization) {
  if (typeof authorization !== "string") return null;
  const match = /^Bearer\s+(.*)$/i.exec(authorization);
  return match ? match[1] : authorization;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const httpServer = createServer((req, res) => {
  void (async () => {
    const url = new URL(req.url ?? "/", "http://mcp-downstream");

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

    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    const server = buildServer(req.headers["authorization"]);
    res.on("close", () => {
      void transport.close();
      void server.close();
    });

    try {
      await server.connect(transport);
      const raw = req.method === "POST" ? await readBody(req) : "";
      const parsed = raw === "" ? undefined : JSON.parse(raw);
      await transport.handleRequest(req, res, parsed);
    } catch (err) {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: String(err instanceof Error ? err.message : err) }));
      }
    }
  })();
});

httpServer.listen(PORT, "0.0.0.0", () => {
  process.stdout.write(`mcp-downstream listening on ${String(PORT)}\n`);
});
