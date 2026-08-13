// The §2.3 status quo, executable — the BASELINE arm of the C-3 comparison.
//
// This is thesis Listing 2.1 as a running server: the credential arrives in the
// launch environment and the process holds it in memory, with no vault in the
// path. It deliberately implements none of the defences under evaluation — no
// target allowlist, no output sanitization, no response shaping, no opaque
// handle — because its expected outcome is that every attack SUCCEEDS. A
// baseline that accidentally defended would erase the effect the paired table
// is supposed to show.
//
// Deviation from Listing 2.1, deliberate (D5): the listing is a stdio launch
// config, but the Harpoc arm is reached over Streamable HTTP. Serving HTTP here
// holds the transport constant across the two arms, so a paired difference is
// attributable to credential handling alone. The env-borne credential — the
// property the listing is cited for — is preserved exactly.
//
// Tools, each the naive counterpart of a vault mechanism:
//
//   use_secret       takes the SAME action object the vault's tool takes, and
//                    does the obvious unmediated thing with it.
//   list_secrets     returns names AND values.
//   get_secret_info  returns metadata including the value.
//   failing_request  throws an error whose message embeds the credential —
//                    the naive counterpart of the H2 thrown-error channel.
//
// Resource `credentials://env` exposes the same material, since a naive server
// commonly does.
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const PORT = Number(process.env.PORT ?? 0);
// Named as Listing 2.1 names it: a plain provider token in the launch config.
const CREDENTIAL = process.env.API_TOKEN ?? "";
const SECRET_NAME = process.env.SECRET_NAME ?? "baseline-secret";
const MAX_BODY_BYTES = 4 * 1024 * 1024;

function unmediatedHttp(action) {
  const headers = { ...(action.headers ?? {}) };
  // No allowlist, no scheme check, no redirect policy: whatever URL the caller
  // named is where the credential goes.
  const mode = action.injection?.type ?? "bearer";
  if (mode === "bearer") headers["authorization"] = `Bearer ${CREDENTIAL}`;
  else if (mode === "header") headers[action.injection.name ?? "x-api-key"] = CREDENTIAL;
  else if (mode === "basic_auth") {
    headers["authorization"] = `Basic ${Buffer.from(CREDENTIAL, "utf8").toString("base64")}`;
  }

  const url = new URL(action.url);
  if (mode === "query") url.searchParams.set(action.injection.name ?? "token", CREDENTIAL);

  return fetch(url, {
    method: action.method ?? "GET",
    headers,
    body: action.body ?? undefined,
    redirect: "follow",
  }).then(async (response) => {
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });
    // Everything, verbatim: no filtering, no encoding-aware redaction.
    return {
      status: response.status,
      status_text: response.statusText,
      headers: responseHeaders,
      body: await response.text(),
    };
  });
}

function unmediatedProcess(action) {
  return new Promise((resolve) => {
    const child = spawn(action.command, action.args ?? [], {
      // The credential goes into the child environment under the caller's
      // chosen name, and the whole ambient environment goes with it.
      env: { ...process.env, [action.env_var ?? "TOKEN"]: CREDENTIAL },
      shell: false,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c) => (stderr += c.toString("utf8")));
    child.on("error", (err) => resolve({ exit_code: -1, stdout, stderr: String(err.message) }));
    // Verbatim again: the child's own output is returned unscanned, which is
    // the output-channel leak §6.2.6 measures.
    child.on("close", (code) => resolve({ exit_code: code ?? -1, stdout, stderr }));
  });
}

async function dispatch(action) {
  if (action?.type === "http") return unmediatedHttp(action);
  if (action?.type === "process") return unmediatedProcess(action);
  // Fail loudly. A silent no-op here would record as "the baseline did not
  // leak", which is exactly the false negative that makes a paired row vacuous.
  throw new Error(`baseline-mcp: unimplemented action type "${String(action?.type)}"`);
}

function buildServer() {
  const server = new McpServer({ name: "harpoc-e2e-baseline", version: "1.0.0" });

  server.tool(
    "use_secret",
    "Performs the requested action using the configured credential.",
    { handle: z.string().optional(), action: z.record(z.unknown()) },
    async ({ action }) => ({
      content: [{ type: "text", text: JSON.stringify(await dispatch(action)) }],
    }),
  );

  server.tool("list_secrets", "Lists the configured credentials.", {}, () => ({
    content: [
      {
        type: "text",
        text: JSON.stringify({ secrets: [{ name: SECRET_NAME, value: CREDENTIAL }] }),
      },
    ],
  }));

  server.tool("get_secret_info", "Returns metadata for a credential.", {}, () => ({
    content: [
      {
        type: "text",
        text: JSON.stringify({ name: SECRET_NAME, value: CREDENTIAL, type: "api_key" }),
      },
    ],
  }));

  server.tool("failing_request", "Triggers an error.", {}, () => {
    throw new Error(`upstream rejected credential ${CREDENTIAL}`);
  });

  server.resource("credentials", "credentials://env", () => ({
    contents: [
      {
        uri: "credentials://env",
        text: JSON.stringify({ API_TOKEN: CREDENTIAL }),
      },
    ],
  }));

  return server;
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
    const url = new URL(req.url ?? "/", "http://baseline-mcp");

    if (url.pathname === "/health") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
      return;
    }

    if (url.pathname !== "/mcp") {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
      return;
    }

    // Stateless: one server and transport per request, so no session table can
    // carry state between the harness's arms.
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    const server = buildServer();
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

// Port 0 plus a stdout handshake: the parent reads the chosen port rather than
// racing a fixed one, which matters because several arms may run in sequence.
httpServer.listen(PORT, "127.0.0.1", () => {
  const address = httpServer.address();
  process.stdout.write(`LISTENING ${String(typeof address === "object" ? address.port : PORT)}\n`);
});
