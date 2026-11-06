import { chmodSync, lstatSync, rmSync, unlinkSync } from "node:fs";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { connect } from "node:net";
import type { AddressInfo, Socket } from "node:net";
import { pipeline } from "node:stream/promises";
import { validateUrl } from "@harpoc/core";
import type { ProxyLease, ProxyOutcome, ProxyTarget } from "@harpoc/core";
import {
  DEFAULT_HTTP_TIMEOUT_MS,
  ErrorCode,
  MAX_UNIX_SOCKET_PATH_BYTES,
  RateLimiter,
  VaultError,
  callerFromToken,
  checkTokenScope,
  isLoopbackBindHost,
  normalizeSocketPeer,
  parseHandle,
} from "@harpoc/shared";
import type {
  CallerContext,
  ScopeRefusalReason,
  ServerTransport,
  VaultApiToken,
} from "@harpoc/shared";
import type { Agent } from "undici";
import { findPlaceholder } from "./placeholder.js";
import type { PlaceholderMatch } from "./placeholder.js";
import { createRedactingTransform } from "./redact.js";
import { swapCredential } from "./swap.js";
import {
  failureClass,
  forwardUpstream,
  parseTarget,
  redactText,
  relayResponseHeaders,
  upstreamRequestHeaders,
} from "./upstream.js";
import type { ParsedTarget, ProxyHeaders } from "./upstream.js";

/**
 * The engine surface the proxy uses — four members a `VaultEngine` has;
 * declared here so the package depends on them, not on the class. The lease
 * types are core's (`resolveForProxy`).
 */
export interface ProxyEngine {
  verifyToken(token: string): VaultApiToken;
  auditScopeRefusal(
    caller: CallerContext | undefined,
    operation: string,
    reason: ScopeRefusalReason,
  ): void;
  auditServerStart(options: {
    transport: ServerTransport;
    tokenless: boolean;
    port?: number;
    host?: string;
  }): void;
  resolveForProxy(handle: string, caller: CallerContext, target: ProxyTarget): Promise<ProxyLease>;
}

export interface EgressProxyOptions {
  engine: ProxyEngine;
  /** The per-handle bucket of brokered requests; `RATE_LIMIT_USE_SECRET` per minute by default. */
  rateLimiter?: Pick<RateLimiter, "checkSecret">;
  /** Upstream connect and response-head budget; `DEFAULT_HTTP_TIMEOUT_MS` by default. */
  timeoutMs?: number;
  /** Upstream idle budget between response body chunks; `DEFAULT_HTTP_TIMEOUT_MS` by default. */
  bodyIdleTimeoutMs?: number;
  /** Every refusal and failure, value-free: the error the client was answered with, or — for a refusal after the lease behind the generic 500 — the refusal's own code. */
  onError?: (err: VaultError) => void;
}

export interface EgressProxy {
  /** Listen on loopback TCP; `host` must be 127.0.0.1, ::1 or localhost. Resolves with the bound port. */
  listenTcp(port: number, host: string): Promise<{ port: number }>;
  /** Listen on a Unix socket (`<runtime-dir>/<consumer>/proxy.sock`), mode 0660, no row of its own; refused on Windows. */
  listenSocket(path: string): Promise<void>;
  /** Close every listener, end every in-flight request (its lease completed), remove the socket files. */
  close(): Promise<void>;
}

const CHALLENGE = 'Bearer realm="harpoc"';

const CONNECT_REFUSAL = JSON.stringify({
  error: ErrorCode.INVALID_INPUT,
  message:
    "CONNECT is not supported: the egress proxy runs in plain-HTTP rewrite mode (send http://<proxy>/<host>/<path> or an absolute http:// URI)",
});

interface Refusal {
  status: number;
  error: VaultError;
  headers?: Record<string, string>;
  /** What `onError` receives instead of `error` — a post-lease refusal behind the generic 500. */
  reported?: VaultError;
}

function internalProxyError(): VaultError {
  return new VaultError(ErrorCode.INTERNAL_ERROR, "Internal proxy error");
}

interface Authenticated {
  token: VaultApiToken;
  caller: CallerContext;
}

/** REST's remap: a sealed vault is a temporarily unavailable service (`error-handler.ts`). */
function statusOf(err: VaultError): number {
  return err.code === ErrorCode.VAULT_LOCKED ? 503 : err.statusCode;
}

function peerOf(req: IncomingMessage): string | undefined {
  const address = req.socket.remoteAddress;
  return address ? normalizeSocketPeer(address) : undefined;
}

function hasBody(req: IncomingMessage): boolean {
  return (
    req.headers["content-length"] !== undefined || req.headers["transfer-encoding"] !== undefined
  );
}

function refuseConnect(_req: IncomingMessage, socket: Socket): void {
  socket.end(
    "HTTP/1.1 501 Not Implemented\r\ncontent-type: application/json\r\nconnection: close\r\n" +
      `content-length: ${Buffer.byteLength(CONNECT_REFUSAL)}\r\n\r\n${CONNECT_REFUSAL}`,
  );
}

/** A connect, not `existsSync` (the `agentSocketAccepts` probe): true when something accepts on `path`. */
function socketAccepts(path: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const probe = connect(path);
    probe.on("connect", () => {
      probe.destroy();
      resolve(true);
    });
    probe.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ECONNREFUSED" || err.code === "ENOENT") resolve(false);
      else reject(err);
    });
  });
}

async function clearStaleSocket(path: string): Promise<void> {
  let isSocket: boolean;
  try {
    isSocket = lstatSync(path).isSocket();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  if (!isSocket) {
    throw VaultError.invalidInput(`Egress proxy socket: ${path} exists and is not a socket`);
  }
  if (await socketAccepts(path)) {
    throw VaultError.invalidInput(`Egress proxy socket: another process is listening on ${path}`);
  }
  unlinkSync(path);
}

function listen(server: Server, target: { port: number; host: string } | { path: string }) {
  return new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(target, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise<void>((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections();
  });
}

export function createEgressProxy(options: EgressProxyOptions): EgressProxy {
  const { engine } = options;
  const limiter = options.rateLimiter ?? new RateLimiter();
  const timeoutMs = options.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
  const bodyIdleTimeoutMs = options.bodyIdleTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
  const servers = new Set<Server>();
  const socketPaths = new Set<string>();
  const dispatchers = new Set<Agent>();
  const inFlight = new Set<Promise<void>>();
  let closed = false;

  function refuse(res: ServerResponse, refusal: Refusal): void {
    try {
      options.onError?.(refusal.reported ?? refusal.error);
    } catch {
      /* a throwing hook changes no answer */
    }
    if (res.headersSent) {
      res.destroy();
      return;
    }
    const body = JSON.stringify({ error: refusal.error.code, message: refusal.error.message });
    res.writeHead(refusal.status, {
      ...refusal.headers,
      "content-type": "application/json",
      "content-length": Buffer.byteLength(body),
    });
    res.end(body);
  }

  /** `Proxy-Authorization: Bearer <jwt>` on every request (DB-14) — nothing else is read before it. */
  function authenticate(req: IncomingMessage): Authenticated | Refusal {
    const header = req.headers["proxy-authorization"];
    if (header === undefined) {
      return {
        status: 407,
        error: new VaultError(ErrorCode.INVALID_TOKEN, "Missing Proxy-Authorization header"),
        headers: { "proxy-authenticate": CHALLENGE },
      };
    }
    const match = /^Bearer\s+(\S+)$/i.exec(header);
    if (!match) {
      return {
        status: 401,
        error: new VaultError(ErrorCode.INVALID_TOKEN, "Malformed Proxy-Authorization header"),
        headers: { "www-authenticate": CHALLENGE },
      };
    }
    let token: VaultApiToken;
    try {
      token = engine.verifyToken(match[1] as string);
    } catch (err) {
      if (!(err instanceof VaultError)) throw err;
      const status = statusOf(err);
      return {
        status,
        error: err,
        ...(status === 401 ? { headers: { "www-authenticate": CHALLENGE } } : {}),
      };
    }
    return { token, caller: callerFromToken(token, "proxy", peerOf(req)) };
  }

  /**
   * Validate, forward, relay. `needles` is set on a brokered request: the body
   * runs through the redactor and every response field is redacted. A brokered
   * request goes upstream to `brokered.url` (the credential in place), while a
   * `Location` is mapped against `target`, the client's own URL. The outcome is
   * what the lease's `complete` records; a pass-through ignores it.
   */
  async function exchange(
    req: IncomingMessage,
    res: ServerResponse,
    target: ParsedTarget,
    headers: ProxyHeaders,
    brokered: { url: URL; caPem?: string; needles: Uint8Array[] } | null,
  ): Promise<ProxyOutcome> {
    const needles = brokered?.needles ?? null;
    const scrub = (err: VaultError): VaultError =>
      needles === null
        ? err
        : new VaultError(err.code, redactText(err.message, needles, "utf8").text);

    let resolvedAddresses: string[] | undefined;
    try {
      resolvedAddresses = (await validateUrl(target.url.origin)).resolvedAddresses;
    } catch (err) {
      if (!(err instanceof VaultError)) throw err;
      refuse(res, { status: statusOf(err), error: scrub(err) });
      return { error: err.code };
    }

    let upstream: Awaited<ReturnType<typeof forwardUpstream>>;
    try {
      if (closed) throw new Error("the proxy is closing");
      upstream = await forwardUpstream({
        url: brokered?.url ?? target.url,
        method: req.method ?? "GET",
        headers,
        body: hasBody(req) ? req : null,
        ...(resolvedAddresses === undefined ? {} : { resolvedAddresses }),
        ...(brokered?.caPem === undefined ? {} : { caPem: brokered.caPem }),
        timeoutMs,
        bodyIdleTimeoutMs,
        dispatchers,
      });
    } catch (err) {
      // undici's own text never leaves: the factory names the origin and a fixed
      // class keyed on the error's code.
      const failure = VaultError.proxyUpstreamFailed(target.url.origin, failureClass(err));
      refuse(res, { status: failure.statusCode, error: scrub(failure) });
      return { error: ErrorCode.PROXY_UPSTREAM_FAILED };
    }

    const transform = needles === null ? null : createRedactingTransform(needles);
    try {
      const relayed = relayResponseHeaders(upstream.headers, target, needles);
      // A body that disagrees with a relayed Content-Length errors instead of
      // desyncing a kept-alive connection (lane P's P-5).
      res.strictContentLength = true;
      res.writeHead(upstream.statusCode, relayed.headers);
      // The status reaches the client now, not when the redactor first releases
      // bytes (it holds back up to the longest needle's length − 1).
      res.flushHeaders();
      try {
        if (transform === null) await pipeline(upstream.body, res);
        else await pipeline(upstream.body, transform, res);
      } catch {
        // The client went away or the upstream body failed after the head was
        // sent: the use happened, so the row records the status (the HTTP
        // injector's precedent for a body it could not read).
        res.destroy();
      }
      return {
        status: upstream.statusCode,
        sanitized: relayed.changed || transform?.changed === true,
      };
    } finally {
      await upstream.release();
    }
  }

  async function broker(
    req: IncomingMessage,
    res: ServerResponse,
    target: ParsedTarget,
    match: PlaceholderMatch,
    auth: Authenticated,
  ): Promise<void> {
    const { placeholder } = match;
    const { project, name } = parseHandle(placeholder.handle);
    const judged: ProxyTarget = {
      method: req.method ?? "GET",
      origin: target.url.origin,
      path: target.url.pathname,
    };
    let lease: ProxyLease;
    try {
      // Token scope is the interface's (shared.md: "per-secret name scope
      // stays checkTokenScope's"); the refusal's access.denied row first (D2g).
      checkTokenScope(auth.token, "use", project, name, (reason) =>
        engine.auditScopeRefusal(
          auth.caller,
          `${judged.method} ${judged.origin}${judged.path}`,
          reason,
        ),
      );
      limiter.checkSecret(placeholder.handle, true);
      lease = await engine.resolveForProxy(placeholder.handle, auth.caller, judged);
    } catch (err) {
      if (!(err instanceof VaultError)) throw err;
      refuse(res, { status: statusOf(err), error: err });
      return;
    }

    let completed = false;
    const complete = (outcome: ProxyOutcome): void => {
      if (completed) return;
      completed = true;
      lease.complete(outcome);
    };
    let needles: Uint8Array[] = [];
    try {
      const swapped = swapCredential(
        { headers: req.headers, url: target.url },
        match.placement,
        lease.value,
      );
      needles = swapped.needles;
      lease.value.fill(0);
      const headers = upstreamRequestHeaders(swapped.headers);
      headers["accept-encoding"] = "identity";
      complete(
        await exchange(req, res, target, headers, {
          url: swapped.url,
          ...(lease.caPem === undefined ? {} : { caPem: lease.caPem }),
          needles,
        }),
      );
    } catch (err) {
      if (!(err instanceof VaultError)) {
        complete({ error: ErrorCode.INTERNAL_ERROR });
        throw err;
      }
      // Its code reaches the row and onError; the client gets the generic 500 —
      // a descriptive code would disclose a property of the secret.
      complete({ error: err.code });
      const secret = needles.length > 0 ? needles : [lease.value];
      refuse(res, {
        status: 500,
        error: internalProxyError(),
        reported: new VaultError(err.code, redactText(err.message, secret, "utf8").text),
      });
    } finally {
      lease.value.fill(0);
      for (const needle of needles) needle.fill(0);
    }
  }

  async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const auth = authenticate(req);
    if ("error" in auth) return refuse(res, auth);

    const parsed = parseTarget(req.url ?? "");
    if (!parsed.ok) {
      return refuse(res, { status: 400, error: VaultError.invalidInput(parsed.message) });
    }
    // Lane P's scan reads node's req.headers (never headersDistinct) and skips
    // the fields that never go upstream.
    const scan = findPlaceholder(req.headers, parsed.target.url);
    if (scan.outcome === "multiple") {
      const refusal = VaultError.proxyMultiplePlaceholders(parsed.target.url.origin);
      return refuse(res, { status: refusal.statusCode, error: refusal });
    }
    if (scan.outcome === "none") {
      // No placeholder: pass-through — no engine call, no row, the client's own
      // Accept-Encoding, the SSRF floor still underneath.
      await exchange(req, res, parsed.target, upstreamRequestHeaders(req.headers), null);
      return;
    }
    await broker(req, res, parsed.target, scan.match, auth);
  }

  function newServer(): Server {
    const server = createServer((req, res) => {
      const handled = serve(req, res).catch(() => {
        refuse(res, { status: 500, error: internalProxyError() });
      });
      inFlight.add(handled);
      const settled = (): void => {
        inFlight.delete(handled);
      };
      void handled.then(settled, settled);
    });
    server.on("connect", refuseConnect);
    servers.add(server);
    return server;
  }

  /** Bind; a bind failure (EADDRINUSE, EACCES) rejects as node raised it — the CLI's fatal path prints it. */
  async function startListener(
    server: Server,
    target: { port: number; host: string } | { path: string },
  ): Promise<void> {
    try {
      await listen(server, target);
    } catch (err) {
      servers.delete(server);
      throw err;
    }
    try {
      if ("path" in target) {
        chmodSync(target.path, 0o660);
        // The sockets ride the TCP listener's row pair (RA-4): no row of their own.
        return;
      }
      // The proxy's one server.start row, after the bind (rest-api server.ts);
      // an unwritable row undoes the bind — no record, no listener.
      engine.auditServerStart({
        transport: "proxy",
        tokenless: false,
        port: (server.address() as AddressInfo).port,
        host: target.host,
      });
    } catch (err) {
      servers.delete(server);
      await closeServer(server);
      if ("path" in target) rmSync(target.path, { force: true });
      throw err;
    }
  }

  return {
    async listenTcp(port: number, host: string): Promise<{ port: number }> {
      const bindHost = host.trim().toLowerCase();
      if (!isLoopbackBindHost(bindHost)) {
        throw VaultError.invalidInput(
          `Egress proxy: the TCP listener binds loopback only (127.0.0.1, ::1 or localhost), not ${JSON.stringify(host)}`,
        );
      }
      if (!Number.isInteger(port) || port < 0 || port > 65535) {
        throw VaultError.invalidInput(`Egress proxy: port ${String(port)} is not 0-65535`);
      }
      const server = newServer();
      await startListener(server, { port, host: bindHost });
      return { port: (server.address() as AddressInfo).port };
    },

    async listenSocket(path: string): Promise<void> {
      if (process.platform === "win32") {
        throw VaultError.invalidInput(
          `Egress proxy socket: not supported on Windows (no socket directory mode to rely on): ${path}`,
        );
      }
      const bytes = Buffer.byteLength(path);
      if (bytes > MAX_UNIX_SOCKET_PATH_BYTES) {
        throw VaultError.invalidInput(
          `Egress proxy socket: path is ${bytes} bytes, over the ${MAX_UNIX_SOCKET_PATH_BYTES} a Unix socket address holds: ${path}`,
        );
      }
      await clearStaleSocket(path);
      const server = newServer();
      await startListener(server, { path });
      socketPaths.add(path);
    },

    async close(): Promise<void> {
      closed = true;
      const destroying = [...dispatchers].map((dispatcher) => dispatcher.destroy());
      dispatchers.clear();
      const closing = [...servers].map((server) => closeServer(server));
      servers.clear();
      // Every in-flight request settles — its lease completed — before close()
      // resolves: the CLI destroys the engine right after (RA).
      await Promise.all([...destroying, ...closing, ...inFlight]);
      for (const path of socketPaths) rmSync(path, { force: true });
      socketPaths.clear();
    },
  };
}
