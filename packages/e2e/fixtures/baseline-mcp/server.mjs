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
//
// Phase 4B adds the database, git and ssh halves. R-3, stated rather than
// hidden: for HTTP and process execution the baseline IS the status quo, but
// these three write the client path a second time, and a second implementation
// can always be argued to be a straw man. What keeps it honest is that every
// choice below is the DEFAULT or the documented quick fix — TLS without
// identity verification (and plaintext when the server offers no TLS), an
// askpass that answers for whichever host asks, redirects and submodules left
// on, StrictHostKeyChecking=no and the private key on disk. None of it is
// invented weakness; all of it is what a working integration looks like when
// nobody is defending against these specific attacks.
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  //
  // Field names are the VAULT's (`header_name`, `query_param` — shared
  // injectionConfigSchema), not names of this fixture's own invention: a
  // paired row must vary the credential-handling layer and nothing else, and a
  // fixture reading `name` would put the credential in a different position
  // from the arm it is compared against (review 2026-08-14, F2).
  const injection = action.injection;
  if (injection == null) {
    throw new Error("baseline: action carries no injection config");
  }
  const mode = injection.type;

  if (mode === "bearer") headers["authorization"] = `Bearer ${CREDENTIAL}`;
  else if (mode === "header") {
    if (typeof injection.header_name !== "string" || injection.header_name === "") {
      throw new Error("baseline: header injection carries no header_name");
    }
    headers[injection.header_name] = CREDENTIAL;
  } else if (mode === "basic_auth") {
    headers["authorization"] = `Basic ${Buffer.from(CREDENTIAL, "utf8").toString("base64")}`;
  } else if (mode !== "query") {
    // Never fall back to bearer: a silent default would send the credential
    // somewhere the arm did not ask for, and a no-op would record as "the
    // baseline did not leak" (D7 — the fixture's existing throw doctrine).
    throw new Error(`baseline: unsupported injection type "${String(mode)}"`);
  }

  const url = new URL(action.url);
  if (mode === "query") {
    if (typeof injection.query_param !== "string" || injection.query_param === "") {
      throw new Error("baseline: query injection carries no query_param");
    }
    url.searchParams.set(injection.query_param, CREDENTIAL);
  }

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

// The binaries the harness resolved, passed in rather than re-resolved here so
// both arms drive the same git and the same ssh (F-6).
const GIT_BIN = process.env.E2E_GIT_PATH ?? "git";
const SSH_BIN = process.env.E2E_SSH_PATH ?? "ssh";
// ssh's own null device. The native Win32 client does not read "/dev/null" as
// one — it appends to a file by that name — so a known_hosts written there
// would persist across arms.
const SSH_NULL_HOSTS = process.platform === "win32" ? "NUL" : "/dev/null";

function splitHostPort(host, explicitPort, fallback) {
  const raw = String(host ?? "");
  const colon = raw.lastIndexOf(":");
  if (explicitPort !== undefined) return { host: raw, port: Number(explicitPort) };
  if (colon > 0) return { host: raw.slice(0, colon), port: Number(raw.slice(colon + 1)) };
  return { host: raw, port: fallback };
}

/**
 * The credential is `user:password`, as it is for the vault's database context.
 * Split on the FIRST colon so a password containing one survives.
 */
function splitCredential() {
  const colon = CREDENTIAL.indexOf(":");
  return colon < 0
    ? { user: CREDENTIAL, password: "" }
    : { user: CREDENTIAL.slice(0, colon), password: CREDENTIAL.slice(colon + 1) };
}

async function unmediatedDatabase(action) {
  const { default: pg } = await import("pg");
  const { user, password } = splitCredential();
  const { host, port } = splitHostPort(action.host, action.port, 5432);

  const attempt = async (ssl) => {
    const client = new pg.Client({ host, port, user, password, database: action.database, ssl });
    await client.connect();
    try {
      const result = await client.query(action.query);
      return {
        type: "database",
        row_count: result.rowCount ?? 0,
        rows: result.rows,
        fields: (result.fields ?? []).map((f) => ({ name: f.name })),
        tls: ssl === false ? "disabled" : "unverified",
      };
    } finally {
      await client.end();
    }
  };

  // The status quo in two lines: encrypt if the server offers it, verify
  // nothing — and if the handshake is refused, turn encryption off and move on.
  // Both halves are what the documentation of every driver warns against and
  // what production code does anyway.
  try {
    return await attempt({ rejectUnauthorized: false });
  } catch {
    return await attempt(false);
  }
}

/**
 * A host-blind askpass, the naive counterpart of the vault's host-BOUND one.
 *
 * This is the whole of H6 in four lines: git asks for credentials for whatever
 * host it ends up talking to — after a redirect, or for a URL a repository's
 * own .gitmodules chose — and a helper that answers unconditionally hands them
 * over. The vault's helper refuses any host but the validated one.
 */
function writeNaiveAskpass() {
  const dir = mkdtempSync(join(tmpdir(), "baseline-git-"));
  const emptyConfig = join(dir, "gitconfig");
  writeFileSync(emptyConfig, "");
  const helper = join(dir, "askpass.mjs");
  writeFileSync(
    helper,
    'const isUser = /user|login/i.test(process.argv[2] || "");\n' +
      'process.stdout.write((isUser ? process.env.NAIVE_GIT_USERNAME : process.env.NAIVE_GIT_PASSWORD) || "");\n',
    { mode: 0o700 },
  );
  const node = process.execPath;
  const launcher =
    process.platform === "win32" ? join(dir, "askpass.cmd") : join(dir, "askpass.sh");
  writeFileSync(
    launcher,
    process.platform === "win32"
      ? `@"${node}" "${helper}" %*\r\n`
      : `#!/bin/sh\nexec "${node}" "${helper}" "$@"\n`,
    { mode: 0o700 },
  );
  return { launcher, emptyConfig, dispose: () => rmSync(dir, { recursive: true, force: true }) };
}

/** Single-quote for the sh git runs GIT_SSH_COMMAND through. */
function shQuote(part) {
  const normalized = process.platform === "win32" ? part.replace(/\\/g, "/") : part;
  return /^[A-Za-z0-9%+,\-./:=@_]+$/.test(normalized)
    ? normalized
    : `'${normalized.replace(/'/g, `'\\''`)}'`;
}

function unmediatedGit(action) {
  const { user, password } = splitCredential();
  const askpass = writeNaiveAskpass();
  const keyFile = /^ssh:\/\//i.test(String(action.repository)) ? writeNaiveKey() : null;

  const env = {
    ...process.env,
    GIT_ASKPASS: askpass.launcher,
    NAIVE_GIT_USERNAME: user,
    NAIVE_GIT_PASSWORD: password,
    GIT_TERMINAL_PROMPT: "0",
    // Verification off rather than a CA pinned: the naive fix for "SSL
    // certificate problem" on a self-signed endpoint.
    GIT_SSL_NO_VERIFY: "true",
    // Not weakness — hygiene, mirroring the Harpoc arm: without it a developer
    // host's credential manager answers ahead of the askpass and the two arms
    // would differ by the ambient configuration rather than by the vault.
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: askpass.emptyConfig,
  };
  if (keyFile) {
    env.GIT_SSH_COMMAND = [
      shQuote(SSH_BIN),
      "-i",
      shQuote(keyFile.path),
      "-o",
      "IdentitiesOnly=yes",
      // The naive quick fix for "Host key verification failed": accept whatever
      // answers. The vault pins the key and refuses on mismatch.
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      `UserKnownHostsFile=${shQuote(SSH_NULL_HOSTS)}`,
      "-o",
      "BatchMode=yes",
    ].join(" ");
  }

  // Redirects and submodule recursion left exactly as git ships them.
  const args = [
    String(action.operation ?? "clone"),
    ...(action.args ?? []),
    String(action.repository),
  ];
  if (action.working_directory) args.push(String(action.working_directory));

  return new Promise((resolve) => {
    const child = spawn(GIT_BIN, args, { env, shell: false });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c) => (stderr += c.toString("utf8")));
    const done = (payload) => {
      askpass.dispose();
      keyFile?.dispose();
      resolve(payload);
    };
    child.on("error", (err) => done({ exit_code: -1, stdout, stderr: String(err.message) }));
    child.on("close", (code) => done({ exit_code: code ?? -1, stdout, stderr }));
  });
}

/**
 * The private key, on disk. The vault serves it from an in-process agent and it
 * never touches the filesystem; writing it out is the ordinary way to make
 * `ssh -i` work, and it is the difference the ssh arms are pairing against.
 */
function writeNaiveKey() {
  const dir = mkdtempSync(join(tmpdir(), "baseline-ssh-"));
  const path = join(dir, "id");
  writeFileSync(path, CREDENTIAL.endsWith("\n") ? CREDENTIAL : `${CREDENTIAL}\n`, { mode: 0o600 });
  return { path, dispose: () => rmSync(dir, { recursive: true, force: true }) };
}

function unmediatedSsh(action) {
  const key = writeNaiveKey();
  const args = [
    "-i",
    key.path,
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    `UserKnownHostsFile=${SSH_NULL_HOSTS}`,
    "-o",
    "BatchMode=yes",
    `${String(action.user)}@${String(action.host)}`,
    String(action.command),
  ];

  return new Promise((resolve) => {
    const child = spawn(SSH_BIN, args, { env: { ...process.env }, shell: false });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c) => (stderr += c.toString("utf8")));
    const done = (payload) => {
      key.dispose();
      resolve(payload);
    };
    child.on("error", (err) => done({ exit_code: -1, stdout, stderr: String(err.message) }));
    child.on("close", (code) => done({ exit_code: code ?? -1, stdout, stderr }));
  });
}

/**
 * A naive MCP proxy: the TARGET comes from the call.
 *
 * That is the whole of §6.2.3's contrast. A server that forwards wherever the
 * tool call says can be re-aimed by anything that can influence the call — a
 * poisoned tool description, for instance. The vault takes the downstream
 * endpoint from the secret's stored configuration and ignores any target in the
 * action, so the same poisoned description moves nothing.
 */
async function unmediatedMcp(action) {
  const url = String(action.url ?? action.endpoint ?? "");
  if (url === "") throw new Error("baseline-mcp: the mcp action named no target");
  const response = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${CREDENTIAL}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: action.tool, arguments: action.arguments ?? {} },
    }),
  });
  return { type: "mcp", status: response.status, body: await response.text() };
}

async function dispatch(action) {
  if (action?.type === "http") return unmediatedHttp(action);
  if (action?.type === "process") return unmediatedProcess(action);
  if (action?.type === "database") return unmediatedDatabase(action);
  if (action?.type === "git") return unmediatedGit(action);
  if (action?.type === "ssh") return unmediatedSsh(action);
  if (action?.type === "mcp") return unmediatedMcp(action);
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
      // A client that disconnects before close resolves would otherwise turn a
      // rejection into an unhandled one — fatal on this long-lived container
      // (review 2026-08-14, F5).
      void transport.close().catch((err) => console.error("[fixture] close failed:", err));
      void server.close().catch((err) => console.error("[fixture] close failed:", err));
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
