import { connect } from "node:net";
import type { Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import type { TLSSocket } from "node:tls";
import { PROXY_CLIENT_TIMEOUT_MS } from "./proxy-client.js";

export interface TunnelOpen {
  /** The proxy's answer to the CONNECT: its status line and fields, up to the blank line. */
  established: string;
  /** The TLS socket over the tunnel, verified against `ca` — absent when the CONNECT was refused. */
  socket?: TLSSocket;
  /** The refusal's body when the CONNECT was refused. */
  body?: string;
}

export interface TunnelCall {
  port: number;
  /** The CONNECT target, `<host>:<port>`. */
  authority: string;
  /** The raw CONNECT fields after the request line (each `Name: value`); `Host` is added. */
  fields: string[];
  /** The CA the client trusts for the tunnel's leaf. */
  ca: string;
  /** The ALPN protocols the client offers; none by default. */
  alpn?: string[];
}

function readHead(socket: Socket): Promise<{ head: string; rest: Buffer }> {
  return new Promise((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      buffered = Buffer.concat([buffered, chunk]);
      const end = buffered.indexOf("\r\n\r\n");
      if (end === -1) return;
      socket.removeListener("data", onData);
      socket.pause();
      resolve({
        head: buffered.subarray(0, end).toString("latin1"),
        rest: buffered.subarray(end + 4),
      });
    };
    socket.on("data", onData);
    socket.once("error", reject);
    socket.once("close", () => reject(new Error("the proxy closed before answering the CONNECT")));
  });
}

/** A CONNECT written by hand, then TLS over the tunnel when the proxy answers 200. */
export async function openTunnel(call: TunnelCall): Promise<TunnelOpen> {
  const raw = connect(call.port, "127.0.0.1");
  raw.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () => raw.destroy(new Error("CONNECT timed out")));
  raw.write(
    [`CONNECT ${call.authority} HTTP/1.1`, `Host: ${call.authority}`, ...call.fields, "", ""].join(
      "\r\n",
    ),
  );
  const { head, rest } = await readHead(raw);
  if (!head.startsWith("HTTP/1.1 200 ")) {
    const chunks: Buffer[] = [rest];
    raw.on("data", (chunk: Buffer) => chunks.push(chunk));
    raw.resume();
    await new Promise<void>((resolve) => raw.once("close", () => resolve()));
    return { established: head, body: Buffer.concat(chunks).toString("utf8") };
  }
  const host = call.authority.slice(0, call.authority.lastIndexOf(":")).replace(/^\[|\]$/g, "");
  const socket = await new Promise<TLSSocket>((resolve, reject) => {
    const tls = tlsConnect(
      {
        socket: raw,
        ca: call.ca,
        ...(/^[\d.]+$|:/.test(host) ? {} : { servername: host }),
        host,
        ...(call.alpn === undefined ? {} : { ALPNProtocols: call.alpn }),
      },
      () => resolve(tls),
    );
    tls.once("error", reject);
  });
  return { established: head, socket };
}

/** Write `text` into an open tunnel and resolve with every byte until the server ends the connection. */
export function exchangeInTunnel(socket: TLSSocket, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    socket.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () =>
      socket.destroy(new Error("tunnel exchange timed out")),
    );
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("error", reject);
    socket.once("close", () => resolve(Buffer.concat(chunks).toString("latin1")));
    socket.write(text);
  });
}
