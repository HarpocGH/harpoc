import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { VaultEngine } from "@harpoc/core";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { InjectionGuard } from "./guards/injection-guard.js";
import { RateLimiter } from "./guards/rate-limiter.js";
import { createMcpServer } from "./server.js";

export const DEFAULT_MCP_HTTP_PORT = 3001;
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_ENDPOINT = "/mcp";
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const MAX_SESSIONS = 128;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

export interface McpHttpServerOptions {
  engine: VaultEngine;
  port?: number;
  host?: string;
  endpoint?: string;
}

export interface McpHttpServer {
  /** Actual bound port (differs from the requested one when 0 was passed). */
  readonly port: number;
  readonly endpoint: string;
  close(): Promise<void>;
}

interface McpHttpSession {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  tokenFingerprint: Buffer;
}

/**
 * Serve the Harpoc MCP server over the Streamable HTTP transport (thesis
 * contribution 4: stdio for local agents, Streamable HTTP for remote access).
 *
 * Unlike stdio — where the spawning host is the single implicitly trusted
 * client — HTTP accepts arbitrary clients, so every request must carry a
 * vault-issued JWT in `Authorization: Bearer`. The token presented at
 * `initialize` defines the session's scope (same ScopeGuard semantics as a
 * stdio launch token) and is pinned to the session via a SHA-256 fingerprint;
 * subsequent requests must present the identical token and are re-verified so
 * expiry and revocation take effect mid-session, matching the REST API.
 */
export async function startMcpHttpServer(options: McpHttpServerOptions): Promise<McpHttpServer> {
  const { engine } = options;
  const host = options.host ?? DEFAULT_HOST;
  const endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
  const rebindingProtection = LOOPBACK_HOSTS.has(host);

  const sessions = new Map<string, McpHttpSession>();
  const rateLimiter = new RateLimiter();
  const injectionGuard = new InjectionGuard();

  let allowedHosts: string[] = [];
  let allowedOrigins: string[] = [];

  async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const path = (req.url ?? "/").split("?")[0];
    if (path !== endpoint) {
      sendJsonRpcError(res, 404, "Not found");
      return;
    }

    const token = extractBearerToken(req);
    if (token === undefined) {
      sendUnauthorized(res, "Missing or malformed Authorization: Bearer header");
      return;
    }

    const rawSessionId = req.headers["mcp-session-id"];
    const sessionId = Array.isArray(rawSessionId) ? rawSessionId[0] : rawSessionId;

    if (sessionId !== undefined) {
      const session = sessions.get(sessionId);
      if (!session) {
        sendJsonRpcError(res, 404, "Session not found");
        return;
      }
      if (!timingSafeEqual(fingerprint(token), session.tokenFingerprint)) {
        sendUnauthorized(res, "Token does not match the session's token");
        return;
      }
      try {
        engine.verifyToken(token);
      } catch (err) {
        sendAuthError(res, err);
        return;
      }
      if (req.method === "POST") {
        const read = await readJsonBodyOrRespond(req, res);
        if (!read.ok) return;
        await session.transport.handleRequest(req, res, read.body);
      } else {
        await session.transport.handleRequest(req, res);
      }
      return;
    }

    if (req.method !== "POST") {
      sendJsonRpcError(res, 400, "Mcp-Session-Id header required");
      return;
    }

    const read = await readJsonBodyOrRespond(req, res);
    if (!read.ok) return;
    const body = read.body;

    if (!isInitializeRequest(body)) {
      sendJsonRpcError(res, 400, "Bad Request: expected an initialize request (no session ID)");
      return;
    }

    if (sessions.size >= MAX_SESSIONS) {
      sendJsonRpcError(res, 429, "Too many concurrent MCP sessions");
      return;
    }

    let server: McpServer;
    try {
      server = createMcpServer({ engine, launchToken: token, rateLimiter, injectionGuard });
    } catch (err) {
      sendAuthError(res, err);
      return;
    }

    const tokenFingerprint = fingerprint(token);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableDnsRebindingProtection: rebindingProtection,
      allowedHosts: rebindingProtection ? allowedHosts : undefined,
      allowedOrigins: rebindingProtection ? allowedOrigins : undefined,
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, server, tokenFingerprint });
      },
      onsessionclosed: (id) => {
        sessions.delete(id);
      },
    });
    transport.onclose = () => {
      if (transport.sessionId !== undefined) {
        sessions.delete(transport.sessionId);
      }
    };

    await server.connect(transport);
    await transport.handleRequest(req, res, body);

    if (transport.sessionId === undefined) {
      // Initialization was rejected (e.g. DNS-rebinding check) — no session
      // was registered, so tear the orphaned server down.
      await server.close();
    }
  }

  const httpServer = createServer((req, res) => {
    handleRequest(req, res).catch((err: unknown) => {
      process.stderr.write(
        `[harpoc] MCP HTTP request failed: ${err instanceof Error ? err.message : String(err)}\n`,
      );
      if (!res.headersSent) {
        sendJsonRpcError(res, 500, "Internal server error");
      } else {
        res.end();
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(options.port ?? DEFAULT_MCP_HTTP_PORT, host, () => {
      httpServer.removeListener("error", reject);
      resolve();
    });
  });

  const boundPort = (httpServer.address() as AddressInfo).port;
  allowedHosts = [
    "127.0.0.1",
    `127.0.0.1:${boundPort}`,
    "localhost",
    `localhost:${boundPort}`,
    "[::1]",
    `[::1]:${boundPort}`,
  ];
  allowedOrigins = [
    `http://127.0.0.1:${boundPort}`,
    `http://localhost:${boundPort}`,
    `https://127.0.0.1:${boundPort}`,
    `https://localhost:${boundPort}`,
  ];

  return {
    port: boundPort,
    endpoint,
    close: async (): Promise<void> => {
      for (const session of [...sessions.values()]) {
        try {
          await session.server.close();
        } catch {
          // Best-effort teardown; the HTTP server close below is authoritative.
        }
      }
      sessions.clear();
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => {
          if (err) reject(err);
          else resolve();
        });
        httpServer.closeAllConnections();
      });
    },
  };
}

function extractBearerToken(req: IncomingMessage): string | undefined {
  const header = req.headers.authorization;
  if (typeof header !== "string") return undefined;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match?.[1];
}

function fingerprint(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

type BodyReadResult = { ok: true; body: unknown } | { ok: false };

/**
 * Read and parse a request body with the MAX_BODY_BYTES cap, answering 413
 * (too large) or 400 (malformed JSON) directly on failure. Every request path
 * that carries a body must go through this: the SDK transport's own body read
 * (`await req.json()`) is unbounded, so handing it an unread request reopens
 * the memory-exhaustion hole.
 */
async function readJsonBodyOrRespond(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<BodyReadResult> {
  try {
    return { ok: true, body: await readJsonBody(req) };
  } catch (err) {
    if (err instanceof VaultError) {
      sendJsonRpcError(res, 413, err.message);
    } else {
      sendJsonRpcError(res, 400, "Parse error: invalid JSON", -32700);
    }
    return { ok: false };
  }
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const raw = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    // Listener-based (not `for await`): exiting a stream's async iterator
    // destroys the socket, which would reset the connection before the 413
    // response reaches the client. Past the cap the remainder is drained and
    // discarded instead (bounded by Node's server request timeout), keeping
    // the socket healthy for the error response.
    req.on("data", (chunk: Buffer | string) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
      total += buf.length;
      if (total > MAX_BODY_BYTES) {
        settled = true;
        chunks.length = 0;
        reject(new VaultError(ErrorCode.INVALID_INPUT, "Request body too large"));
        return;
      }
      chunks.push(buf);
    });
    req.on("end", () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks));
    });
    req.on("error", (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
  return JSON.parse(raw.toString("utf8")) as unknown;
}

function sendJsonRpcError(
  res: ServerResponse,
  status: number,
  message: string,
  rpcCode = -32000,
): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: rpcCode, message }, id: null }));
}

function sendUnauthorized(res: ServerResponse, message: string): void {
  res.setHeader("WWW-Authenticate", 'Bearer realm="harpoc"');
  sendJsonRpcError(res, 401, message);
}

function sendAuthError(res: ServerResponse, err: unknown): void {
  if (err instanceof VaultError) {
    if (err.statusCode === 401) {
      sendUnauthorized(res, err.message);
      return;
    }
    sendJsonRpcError(res, err.code === ErrorCode.VAULT_LOCKED ? 503 : err.statusCode, err.message);
    return;
  }
  sendJsonRpcError(res, 500, "Internal server error");
}
