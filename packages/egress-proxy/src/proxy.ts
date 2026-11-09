import { chmodSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { pipeline } from "node:stream/promises";
import { prepareUnixSocketPath, validateUrl } from "@harpoc/core";
import type { ProxyLease, ProxyOutcome, ProxyTarget } from "@harpoc/core";
import {
  DEFAULT_HTTP_TIMEOUT_MS,
  ErrorCode,
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
import { createLeafCache, hostPermitted } from "./ca.js";
import type { LeafCache, ProxyCaOptions } from "./ca.js";
import { connectReply, createTunnelHost, parseConnectTarget, tunnelTarget } from "./connect.js";
import type { Tunnel } from "./connect.js";
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
  /** The CA a CONNECT tunnel's TLS is terminated with (`secret://harpoc-ca`); without one CONNECT answers 501. */
  ca?: ProxyCaOptions;
}

export interface EgressProxy {
  /** Listen on loopback TCP; `host` must be 127.0.0.1, ::1 or localhost. Resolves with the bound port. */
  listenTcp(port: number, host: string): Promise<{ port: number }>;
  /** Listen on a Unix socket (`<runtime-dir>/<consumer>/proxy.sock`), mode 0660, no row of its own; refused on Windows. */
  listenSocket(path: string): Promise<void>;
  /** Close every listener and tunnel, end every in-flight request (its lease completed), remove the socket files. */
  close(): Promise<void>;
}

const CHALLENGE = 'Bearer realm="harpoc"';

/** A CONNECT's 407 offers both schemes, Basic first: curl's and git's `anyauth` answer a Basic challenge only. */
const CONNECT_CHALLENGES: [string, string][] = [
  ["proxy-authenticate", 'Basic realm="harpoc"'],
  ["proxy-authenticate", CHALLENGE],
];

const NO_CA_MESSAGE =
  "CONNECT is not enabled: no proxy CA is enrolled (harpoc proxy ca init, then restart server start --proxy); the plain-HTTP rewrite mode answers http://<proxy>/<host>/<path> and absolute http:// URIs";

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
  /** The bearer as sent — a tunnel keeps it to verify every request it carries again. */
  raw: string;
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

/**
 * The token of a CONNECT's `Proxy-Authorization: Basic base64(<user>:<token>)`,
 * the form clients build from `HTTPS_PROXY=http://harpoc:<token>@…`; the user is
 * ignored. `null` unless the credentials are canonical base64 of UTF-8 text
 * with a colon and a token without whitespace after it.
 */
function basicToken(credentials: string): string | null {
  const decoded = Buffer.from(credentials, "base64");
  if (decoded.toString("base64") !== credentials) return null;
  const text = decoded.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(decoded)) return null;
  const colon = text.indexOf(":");
  if (colon === -1) return null;
  const token = text.slice(colon + 1);
  return /^\S+$/.test(token) ? token : null;
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
  const { engine, onError } = options;
  const limiter = options.rateLimiter ?? new RateLimiter();
  const timeoutMs = options.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
  const bodyIdleTimeoutMs = options.bodyIdleTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
  const servers = new Set<Server>();
  const socketPaths = new Set<string>();
  const dispatchers = new Set<Agent>();
  const inFlight = new Set<Promise<void>>();
  const caHosts = options.ca?.hosts;
  const leaves: LeafCache | null =
    options.ca === undefined ? null : createLeafCache({ ca: options.ca });
  const tunnels = createTunnelHost((req, res) => track(req, res), timeoutMs);
  let closed = false;

  function report(err: VaultError): void {
    try {
      onError?.(err);
    } catch {
      /* a throwing hook changes no answer */
    }
  }

  function refuse(res: ServerResponse, refusal: Refusal): void {
    report(refusal.reported ?? refusal.error);
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

  /**
   * `Proxy-Authorization: Bearer <jwt>` on every request (DB-14) — nothing else
   * is read before it. A CONNECT also takes `Basic base64(<user>:<jwt>)`, the
   * form clients build from a proxy URL's userinfo; a plain-HTTP request stays
   * Bearer-only (RQ-2).
   */
  function authenticate(req: IncomingMessage, connect = false): Authenticated | Refusal {
    const header = req.headers["proxy-authorization"];
    if (header === undefined) {
      return {
        status: 407,
        error: new VaultError(ErrorCode.INVALID_TOKEN, "Missing Proxy-Authorization header"),
        headers: { "proxy-authenticate": CHALLENGE },
      };
    }
    const match = /^Bearer\s+(\S+)$/i.exec(header);
    const basic = connect && match === null ? /^Basic\s+(\S+)$/i.exec(header) : null;
    const raw = match ? (match[1] as string) : basic ? basicToken(basic[1] as string) : null;
    if (raw === null) {
      return {
        status: 401,
        error: new VaultError(ErrorCode.INVALID_TOKEN, "Malformed Proxy-Authorization header"),
        headers: { "www-authenticate": CHALLENGE },
      };
    }
    return verify(raw, peerOf(req));
  }

  function verify(raw: string, peer: string | undefined): Authenticated | Refusal {
    let token: VaultApiToken;
    try {
      token = engine.verifyToken(raw);
    } catch (err) {
      if (!(err instanceof VaultError)) throw err;
      const status = statusOf(err);
      return {
        status,
        error: err,
        ...(status === 401 ? { headers: { "www-authenticate": CHALLENGE } } : {}),
      };
    }
    return { token, caller: callerFromToken(token, "proxy", peer), raw };
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
    const tunnel = tunnels.tunnelOf(req);
    // Inside a tunnel the CONNECT's token is verified again for every request:
    // an expiry or a revocation mid-tunnel answers this request and ends the tunnel.
    const auth = tunnel === undefined ? authenticate(req) : verify(tunnel.token, tunnel.peer);
    if ("error" in auth) {
      if (tunnel !== undefined) res.shouldKeepAlive = false;
      return refuse(res, auth);
    }

    const parsed =
      tunnel === undefined ? parseTarget(req.url ?? "") : tunnelTarget(req.url ?? "", tunnel);
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

  function track(req: IncomingMessage, res: ServerResponse): void {
    const handled = serve(req, res).catch(() => {
      refuse(res, { status: 500, error: internalProxyError() });
    });
    inFlight.add(handled);
    const settled = (): void => {
      inFlight.delete(handled);
    };
    void handled.then(settled, settled);
  }

  function refuseConnect(socket: Socket, refusal: Refusal): void {
    report(refusal.reported ?? refusal.error);
    const headers: [string, string][] =
      refusal.status === 407 ? CONNECT_CHALLENGES : Object.entries(refusal.headers ?? {});
    socket.end(connectReply(refusal.status, refusal.error, headers));
  }

  /**
   * `CONNECT <host>:<port>` (B8): authenticate (Bearer or Basic) → the target →
   * the CA's hosts → the host's leaf → `200` and the TLS tunnel, whose requests
   * the ladder serves with the target fixed to the tunnel's origin. Every
   * refusal precedes the 200, closes the connection and writes no row.
   */
  function onConnect(req: IncomingMessage, socket: Socket, head: Buffer): void {
    // The CONNECT socket is detached from the HTTP server: an unhandled reset would end the process.
    socket.on("error", () => socket.destroy());
    try {
      if (closed) {
        socket.destroy();
        return;
      }
      if (caHosts === undefined || leaves === null) {
        return refuseConnect(socket, {
          status: 501,
          error: VaultError.invalidInput(NO_CA_MESSAGE),
        });
      }
      const auth = authenticate(req, true);
      if ("error" in auth) return refuseConnect(socket, auth);
      const target = parseConnectTarget(req.url ?? "");
      if (!target.ok) {
        return refuseConnect(socket, {
          status: 400,
          error: VaultError.invalidInput(target.message),
        });
      }
      if (!hostPermitted({ hosts: caHosts }, target.host)) {
        const refusal = VaultError.proxyConnectDenied(target.host, target.port);
        return refuseConnect(socket, { status: refusal.statusCode, error: refusal });
      }
      const context = leaves.contextFor(target.host);
      const tunnel: Tunnel = {
        authority: target.authority,
        host: target.host,
        port: target.port,
        token: auth.raw,
        peer: socket.remoteAddress ? normalizeSocketPeer(socket.remoteAddress) : undefined,
      };
      tunnels.open(socket, head, tunnel, context);
    } catch (err) {
      // An expired CA refuses every leaf: the authenticated caller gets CERT_EXPIRED and its status.
      if (err instanceof VaultError) {
        return refuseConnect(socket, { status: statusOf(err), error: err });
      }
      return refuseConnect(socket, { status: 500, error: internalProxyError() });
    }
  }

  function newServer(): Server {
    const server = createServer(track);
    server.on("connect", onConnect);
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
      await prepareUnixSocketPath(path, "Egress proxy socket");
      const server = newServer();
      await startListener(server, { path });
      socketPaths.add(path);
    },

    async close(): Promise<void> {
      closed = true;
      // The tunnels first: their in-flight requests then settle with the rest.
      tunnels.close();
      leaves?.clear();
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
