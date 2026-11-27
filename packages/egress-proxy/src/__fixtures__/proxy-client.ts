import { request } from "node:http";
import type { IncomingHttpHeaders, OutgoingHttpHeaders } from "node:http";
import { connect } from "node:net";

/** Every request a suite sends has a socket deadline (testing.md: `rawGet` takes one). */
export const PROXY_CLIENT_TIMEOUT_MS = 10_000;

export interface ProxyReply {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
  /** Status line, every raw header line and the body — the needle sweep's input. */
  raw: string;
}

export interface ProxyCall {
  /** The request target as the client writes it: `/<host>/<path>` or an absolute URI. */
  path: string;
  port?: number;
  socketPath?: string;
  method?: string;
  headers?: OutgoingHttpHeaders;
  body?: string;
}

/** One request to the proxy over `node:http` (keep-alive off), resolved with the whole reply. */
export function proxyRequest(call: ProxyCall): Promise<ProxyReply> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        ...(call.socketPath === undefined
          ? { host: "127.0.0.1", port: call.port }
          : { socketPath: call.socketPath }),
        path: call.path,
        method: call.method ?? "GET",
        headers: call.headers,
        agent: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("error", reject);
        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          const lines: string[] = [];
          for (let i = 0; i < res.rawHeaders.length; i += 2) {
            lines.push(`${res.rawHeaders[i] ?? ""}: ${res.rawHeaders[i + 1] ?? ""}`);
          }
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body,
            raw: `${res.statusCode ?? 0} ${res.statusMessage ?? ""}\n${lines.join("\n")}\n\n${body}`,
          });
        });
      },
    );
    req.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () =>
      req.destroy(new Error("proxy request timed out")),
    );
    req.on("error", reject);
    req.end(call.body);
  });
}

export interface ProxyStreamReply {
  status: number;
  headers: IncomingHttpHeaders;
  /** Every body byte that arrived, decoded as UTF-8. */
  body: string;
  /** Node's `IncomingMessage.complete`: the response's terminating chunk arrived. */
  complete: boolean;
  /** From the request's start to the response's close. */
  elapsedMs: number;
}

/**
 * `proxyRequest` for a streamed reply: `onData` runs with each body chunk as
 * it arrives, and the promise resolves when the response closes, whole or cut.
 * It rejects once `deadlineMs` has passed since the request's start.
 */
export function proxyStream(
  call: ProxyCall,
  onData: (chunk: string) => void,
  deadlineMs: number = PROXY_CLIENT_TIMEOUT_MS,
): Promise<ProxyStreamReply> {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    let body = "";
    const req = request({
      ...(call.socketPath === undefined
        ? { host: "127.0.0.1", port: call.port }
        : { socketPath: call.socketPath }),
      path: call.path,
      method: call.method ?? "GET",
      headers: call.headers,
      agent: false,
    });
    const deadline = setTimeout(() => {
      reject(
        new Error(
          `the streamed request outlived its ${deadlineMs} ms deadline, ${body.length} body characters in`,
        ),
      );
      req.destroy();
    }, deadlineMs);
    req.on("response", (res) => {
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => {
        body += chunk;
        onData(chunk);
      });
      res.on("error", () => undefined);
      res.on("close", () => {
        clearTimeout(deadline);
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          body,
          complete: res.complete,
          elapsedMs: performance.now() - started,
        });
      });
    });
    req.on("error", (err) => {
      if ((err as NodeJS.ErrnoException).code === "ECONNRESET") return;
      clearTimeout(deadline);
      reject(err);
    });
    req.end(call.body);
  });
}

/** A raw request line written to the proxy's TCP port; resolves with every byte the proxy sent back. */
export function rawProxyExchange(port: number, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1");
    const chunks: Buffer[] = [];
    socket.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () =>
      socket.destroy(new Error("raw exchange timed out")),
    );
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("error", reject);
    socket.on("close", () => resolve(Buffer.concat(chunks).toString("latin1")));
    socket.write(text);
  });
}

/** `rawProxyExchange`, but the client resets the connection (RST) on the first answer bytes, as curl does. */
export function rawProxyExchangeThenReset(port: number, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1");
    socket.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () =>
      socket.destroy(new Error("raw exchange timed out")),
    );
    socket.on("error", reject);
    socket.on("close", () => reject(new Error("raw exchange closed before any answer byte")));
    socket.once("data", (chunk: Buffer) => {
      socket.resetAndDestroy();
      resolve(chunk.toString("latin1"));
    });
    socket.write(text);
  });
}
