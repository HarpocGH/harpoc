import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { CertManager } from "@harpoc/cert-manager";
import type { VaultEngine } from "@harpoc/core";
import {
  assertBindAllowed,
  buildAllowedHostSet,
  checkRequestHost,
  ErrorCode,
  VaultError,
} from "@harpoc/shared";
import { InjectionGuard } from "./guards/injection-guard.js";
import { RateLimiter } from "./guards/rate-limiter.js";
import { createDefaultOAuthManager, createMcpServer } from "./server.js";

export const DEFAULT_MCP_HTTP_PORT = 3001;
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_ENDPOINT = "/mcp";
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const MAX_SESSIONS = 128;
/** A session untouched for this long is abandoned — its client is gone. */
const SESSION_IDLE_TTL_MS = 10 * 60 * 1000;
/** Cadence of the background reclamation sweep. */
const SESSION_SWEEP_INTERVAL_MS = 60 * 1000;
/**
 * At capacity, the least-recently-used session is reclaimed rather than the new
 * client refused — but only once it has been quiet this long, so a busy fleet
 * of legitimate clients is never churned.
 */
const SESSION_EVICTION_GRACE_MS = 30 * 1000;

/** Session-lifecycle limits. Defaults suit a normal deployment. */
export interface McpHttpSessionLimits {
  /** Concurrent sessions the server holds (default 128). */
  max?: number;
  /** Idle time after which a session is reclaimed (default 10 min). */
  idleTtlMs?: number;
  /** Reclamation sweep cadence (default 1 min). */
  sweepIntervalMs?: number;
  /** Quiet time before a session may be evicted to admit a new one (default 30 s). */
  evictionGraceMs?: number;
}

export interface McpHttpServerOptions {
  engine: VaultEngine;
  port?: number;
  host?: string;
  /**
   * Host names clients reach this listener by (R11/D61). Required for a
   * non-loopback bind; additive on loopback, where 127.0.0.1, ::1 and
   * localhost are always allowed. Matched on the parsed hostname of Host and
   * Origin, port-agnostic.
   */
  allowedHosts?: readonly string[];
  endpoint?: string;
  sessionLimits?: McpHttpSessionLimits;
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
  /** Unix seconds, from the pinned token — a session cannot outlive its token. */
  tokenExp: number;
  tokenJti: string;
  /** Epoch ms of the last request served on this session. */
  lastSeen: number;
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
 *
 * Every request's Host (and Origin, when present) is checked against the
 * listener's allowed-host set before anything else — the vault's own check
 * since 2026-09-04 (R11/D61), the SDK's deprecated transport options no longer
 * used.
 */
export async function startMcpHttpServer(options: McpHttpServerOptions): Promise<McpHttpServer> {
  const { engine } = options;
  const host = options.host ?? DEFAULT_HOST;
  const endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
  assertBindAllowed(host, options.allowedHosts ?? []);
  const allowedHosts = buildAllowedHostSet(host, options.allowedHosts ?? []);

  const sessions = new Map<string, McpHttpSession>();
  const rateLimiter = new RateLimiter();
  const injectionGuard = new InjectionGuard();
  const oauthManager = createDefaultOAuthManager(engine);
  const certManager = new CertManager(engine);

  const maxSessions = options.sessionLimits?.max ?? MAX_SESSIONS;
  const idleTtlMs = options.sessionLimits?.idleTtlMs ?? SESSION_IDLE_TTL_MS;
  const sweepIntervalMs = options.sessionLimits?.sweepIntervalMs ?? SESSION_SWEEP_INTERVAL_MS;
  const evictionGraceMs = options.sessionLimits?.evictionGraceMs ?? SESSION_EVICTION_GRACE_MS;

  function dropSession(id: string, session: McpHttpSession): void {
    sessions.delete(id);
    void session.server.close().catch(() => undefined);
  }

  /**
   * Reclaim sessions no client can still be using. Without this a session left
   * the map only on an explicit `DELETE /mcp` or on shutdown, so every client
   * that died without one (crash, sleep, network drop) leaked a slot — and the
   * least-privileged token in the deployment could deliberately consume all
   * MAX_SESSIONS with cheap initializes and lock out every other principal,
   * `admin` included, until the daemon restarted.
   */
  function sweepSessions(): void {
    const now = Date.now();
    const nowSeconds = Math.floor(now / 1000);
    for (const [id, session] of [...sessions.entries()]) {
      if (now - session.lastSeen > idleTtlMs || session.tokenExp <= nowSeconds) {
        dropSession(id, session);
        continue;
      }
      try {
        if (engine.isTokenRevoked(session.tokenJti)) dropSession(id, session);
      } catch {
        // A sealed vault cannot answer; the idle TTL still reclaims the slot.
      }
    }
  }

  /** Last resort at capacity: reclaim the quietest session, or refuse. */
  function evictLeastRecentlyUsed(): boolean {
    let oldestId: string | undefined;
    let oldest = Number.POSITIVE_INFINITY;
    for (const [id, session] of sessions) {
      if (session.lastSeen < oldest) {
        oldest = session.lastSeen;
        oldestId = id;
      }
    }
    if (oldestId === undefined || Date.now() - oldest < evictionGraceMs) return false;
    const session = sessions.get(oldestId);
    if (!session) return false;
    dropSession(oldestId, session);
    return true;
  }

  const sweepTimer = setInterval(sweepSessions, sweepIntervalMs);
  if (sweepTimer.unref) sweepTimer.unref();

  async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // The listener's host allowlist answers first (R11/D61): a DNS-rebinding
    // request never reaches the path, the token gate or a session, and the
    // refusal names the parsed hostname only — the SDK's own wording, kept.
    const hostCheck = checkRequestHost(
      { host: req.headers.host, origin: req.headers.origin },
      allowedHosts,
    );
    if (!hostCheck.ok) {
      sendJsonRpcError(
        res,
        403,
        `Invalid ${hostCheck.header} header: ${hostCheck.hostname ?? "(missing)"}`,
      );
      return;
    }

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
      session.lastSeen = Date.now();
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

    if (sessions.size >= maxSessions) {
      sweepSessions();
      if (sessions.size >= maxSessions && !evictLeastRecentlyUsed()) {
        sendJsonRpcError(res, 429, "Too many concurrent MCP sessions");
        return;
      }
    }

    // Verified here as well as inside createMcpServer: the session must record
    // its token's expiry and jti so the sweep can reclaim it once the token it
    // is pinned to can no longer authorize anything (only the fingerprint is
    // kept, and a hash cannot be re-verified).
    let tokenExp: number;
    let tokenJti: string;
    let server: McpServer;
    try {
      const payload = engine.verifyToken(token);
      tokenExp = payload.exp;
      tokenJti = payload.jti;
      server = createMcpServer({
        engine,
        launchToken: token,
        rateLimiter,
        injectionGuard,
        oauthManager,
        certManager,
        accessInterface: "mcp-http",
        ...(req.socket.remoteAddress !== undefined
          ? { remoteAddress: req.socket.remoteAddress }
          : {}),
      });
    } catch (err) {
      sendAuthError(res, err);
      return;
    }

    const tokenFingerprint = fingerprint(token);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, {
          transport,
          server,
          tokenFingerprint,
          tokenExp,
          tokenJti,
          lastSeen: Date.now(),
        });
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
      // Initialization was rejected (a malformed initialize request) — no
      // session was registered, so tear the orphaned server down.
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

  try {
    // One row per listener (R4/B22), after the bind so it carries the bound
    // port; an unwritable row undoes the bind — no record, no listener.
    engine.auditServerStart({
      transport: "http",
      tokenless: false,
      port: boundPort,
      host,
    });
  } catch (err) {
    clearInterval(sweepTimer);
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    throw err;
  }

  return {
    port: boundPort,
    endpoint,
    close: async (): Promise<void> => {
      // The shared manager owns the in-flight device-code polls; without this
      // an orphaned poll completes against a destroyed engine (the CLI path
      // cancels in connect.ts — embedders of this server never exit the process).
      oauthManager.cancelPendingFlows();
      clearInterval(sweepTimer);
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
