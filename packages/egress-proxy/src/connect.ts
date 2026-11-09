import { STATUS_CODES, createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { isIP } from "node:net";
import type { Socket } from "node:net";
import { TLSSocket } from "node:tls";
import type { SecureContext } from "node:tls";
import type { VaultError } from "@harpoc/shared";
import type { ParsedTarget, TargetParse } from "./upstream.js";

/** One CONNECT tunnel: where it leads and who opened it. */
export interface Tunnel {
  /** `<host>:<port>` as the CONNECT line named it — the host lower-cased, an IPv6 literal bracketed. */
  authority: string;
  /** The host without brackets. */
  host: string;
  port: number;
  /** The raw token the CONNECT carried: every request inside the tunnel is re-verified with it. */
  token: string;
  /** The client's address, read from the raw socket before the TLS wrap. */
  peer: string | undefined;
}

export type ConnectTargetParse =
  { ok: true; host: string; port: number; authority: string } | { ok: false; message: string };

const CONNECT_TARGET_REFUSAL = "Not a CONNECT target: send CONNECT <host>:<port>";
const TUNNEL_TARGET_REFUSAL =
  "Not a request inside the tunnel: send an origin-form target (/<path>) or the tunnel's own https:// authority";

/** `host:port` (RFC 9110 § 9.3.6) — a DNS name or IPv4 literal, or a bracketed IPv6 literal; the port required. */
const AUTHORITY = /^(?:([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)|\[([0-9A-Fa-f:.]+)\]):(\d{1,5})$/;

/** The 200 a tunnel opens with; every client measured accepts the reason phrase (and `OK`). */
export const CONNECT_ESTABLISHED = "HTTP/1.1 200 Connection Established\r\n\r\n";

export function parseConnectTarget(requestUrl: string): ConnectTargetParse {
  const match = AUTHORITY.exec(requestUrl);
  if (!match) return { ok: false, message: CONNECT_TARGET_REFUSAL };
  const name = match[1];
  const v6 = match[2];
  const port = Number(match[3]);
  if (port < 1 || port > 65535) return { ok: false, message: CONNECT_TARGET_REFUSAL };
  if (v6 !== undefined) {
    if (isIP(v6) !== 6) return { ok: false, message: CONNECT_TARGET_REFUSAL };
    const host = v6.toLowerCase();
    return { ok: true, host, port, authority: `[${host}]:${port}` };
  }
  const host = (name as string).toLowerCase();
  return { ok: true, host, port, authority: `${host}:${port}` };
}

/**
 * The upstream target of a request inside a tunnel: the tunnel's authority
 * and the request's origin-form path, appended as a string (never resolved
 * as a reference). An absolute-form `https://` line naming the tunnel's own
 * authority is read the same way; any other form is refused. The form is
 * `absolute-https`, so a `Location` passes as sent — the client believes it
 * talks to the origin, and a cross-origin follow-up opens its own CONNECT.
 */
export function tunnelTarget(requestUrl: string, tunnel: Tunnel): TargetParse {
  const refused: TargetParse = { ok: false, message: TUNNEL_TARGET_REFUSAL };
  let path = requestUrl;
  if (!requestUrl.startsWith("/")) {
    if (!/^https:\/\//i.test(requestUrl)) return refused;
    let given: URL;
    try {
      given = new URL(requestUrl);
    } catch {
      return refused;
    }
    const tunnelled = new URL(`https://${tunnel.authority}/`);
    if (given.username !== "" || given.password !== "" || given.host !== tunnelled.host) {
      return refused;
    }
    path = `${given.pathname}${given.search}`;
  }
  let url: URL;
  try {
    url = new URL(`https://${tunnel.authority}${path}`);
  } catch {
    return refused;
  }
  url.hash = "";
  const target: ParsedTarget = { url, form: "absolute-https" };
  return { ok: true, target };
}

/** A refusal on the CONNECT's own socket — the status, the JSON body, `connection: close` — before any 200. */
export function connectReply(
  status: number,
  error: VaultError,
  headers: readonly [string, string][] = [],
): string {
  const body = JSON.stringify({ error: error.code, message: error.message });
  const lines = headers.map(([name, value]) => `${name}: ${value}\r\n`).join("");
  return (
    `HTTP/1.1 ${status} ${STATUS_CODES[status] ?? ""}\r\n${lines}` +
    `content-type: application/json\r\ncontent-length: ${Buffer.byteLength(body)}\r\n` +
    `connection: close\r\n\r\n${body}`
  );
}

export interface TunnelHost {
  /** Answer the CONNECT 200, wrap the socket in TLS with `context` and serve its requests. */
  open(socket: Socket, head: Buffer, tunnel: Tunnel, context: SecureContext): void;
  /** The tunnel a request arrived on (keyed on `req.socket`, the TLS socket). */
  tunnelOf(req: IncomingMessage): Tunnel | undefined;
  /** Destroy every tunnel; in-flight requests are the proxy's to await. */
  close(): void;
}

/**
 * The tunnels' HTTP side: one non-listening `http.Server` that every
 * tunnel's TLS socket is handed to (`emit("connection")`), so keep-alive,
 * framing and the request parser are node's own. ALPN offers `http/1.1`
 * alone — the handler is HTTP/1.1; a client that offers only `h2` fails the
 * handshake with `no_application_protocol`. A tunnel that carries no byte
 * for `timeoutMs` in a gap — before its first request, between requests, a
 * stalled partial head — is destroyed; the deadline is suspended while a
 * request is in flight, whose upstream budgets bound it instead.
 */
export function createTunnelHost(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
  timeoutMs: number,
): TunnelHost {
  const tunnels = new WeakMap<Socket, Tunnel>();
  const raws = new WeakMap<Socket, { raw: Socket; inFlight: number }>();
  const open = new Set<Socket>();
  const server = createServer((req, res) => {
    const held = raws.get(req.socket);
    if (held !== undefined) {
      if (held.inFlight === 0) held.raw.setTimeout(0);
      held.inFlight += 1;
      res.once("close", () => {
        held.inFlight -= 1;
        if (held.inFlight === 0 && !held.raw.destroyed) held.raw.setTimeout(timeoutMs);
      });
    }
    handler(req, res);
  });
  let closed = false;

  return {
    open(socket, head, tunnel, context) {
      if (closed) {
        socket.destroy();
        return;
      }
      open.add(socket);
      socket.once("close", () => open.delete(socket));
      socket.setTimeout(timeoutMs);
      socket.on("timeout", () => socket.destroy());
      if (head.length > 0) socket.unshift(head);
      socket.write(CONNECT_ESTABLISHED);
      const tlsSocket = new TLSSocket(socket, {
        isServer: true,
        secureContext: context,
        ALPNProtocols: ["http/1.1"],
      });
      // A client that rejects the leaf or resets mid-handshake ends its own tunnel only.
      tlsSocket.on("error", () => tlsSocket.destroy());
      tunnels.set(tlsSocket, tunnel);
      raws.set(tlsSocket, { raw: socket, inFlight: 0 });
      open.add(tlsSocket);
      tlsSocket.once("close", () => open.delete(tlsSocket));
      server.emit("connection", tlsSocket);
    },
    tunnelOf: (req) => tunnels.get(req.socket),
    close() {
      closed = true;
      for (const socket of open) socket.destroy();
      open.clear();
    },
  };
}
