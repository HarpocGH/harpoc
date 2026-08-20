import { createHash } from "node:crypto";
import { createServer } from "node:http";
import type { IncomingHttpHeaders, Server } from "node:http";
import type { AddressInfo, Socket } from "node:net";

/**
 * Scripted fake WebSocket server for the injector's handshake/collect/close
 * tests. Handles the upgrade by hand on a raw `node:http` server — no `ws`
 * dependency — so the tests exercise exactly the wire behavior the injector
 * must handle: the RFC 6455 handshake (`Sec-WebSocket-Accept` computed from
 * the client's `Sec-WebSocket-Key`), unmasked server→client text frames, and
 * a masked-frame decoder for client→server frames (send() assertions).
 */

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

export interface FakeWsScript {
  /** Server→client text frames sent, in order, once the handshake completes. */
  messages?: string[];
  /** After `messages` is exhausted, hold the connection open instead of
   * sending a close frame — simulates a server that stops responding
   * (used to pin the `window_ms` collect bound). */
  stall?: boolean;
  /** Delay in ms between successive frames (default 0 — sent back to back). */
  messageDelayMs?: number;
  /** When set, the upgrade attempt is answered with this HTTP status instead
   * of a 101 handshake (e.g. 400 for a generic non-101 failure, 302 with a
   * Location header to pin that a redirect is never followed). */
  respondStatus?: number;
  /** When set, a received Close frame is swallowed — no Close frame is sent
   * back and the TCP connection is left open — simulating a non-cooperating
   * server that never completes the RFC 6455 closing handshake. Used to pin
   * the injector's `waitWithTimeout` bound on the post-close wait. */
  neverAckClose?: boolean;
}

/** One request the fake server received — the upgrade request's headers and
 * path, so a test can assert the injected credential arrived at the handshake. */
export interface FakeWsRequest {
  headers: IncomingHttpHeaders;
  url: string | undefined;
}

/** One decoded client→server frame. */
export interface FakeWsFrame {
  opcode: number;
  payload: Buffer;
}

export interface FakeWsServer {
  port: number;
  requests(): FakeWsRequest[];
  clientFrames(): FakeWsFrame[];
  close(): Promise<void>;
}

function buildServerFrame(opcode: number, payload: Buffer): Buffer {
  if (payload.length > 125) {
    throw new Error("fake-ws-server: fixture only supports payloads <= 125 bytes");
  }
  // FIN=1, no extensions; server frames are never masked (RFC 6455 §5.1).
  return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
}

/**
 * Decodes exactly one masked client→server frame starting at `offset`, if the
 * buffer holds a complete one yet. Handles the 7-bit and 16-bit extended
 * length forms (the tests never send a frame large enough to need the 64-bit
 * form). Returns `null` when the buffer is not yet complete.
 */
function tryDecodeClientFrame(
  buf: Buffer,
  offset: number,
): { frame: FakeWsFrame; next: number } | null {
  if (buf.length - offset < 2) return null;
  const b0 = buf[offset] as number;
  const b1 = buf[offset + 1] as number;
  const opcode = b0 & 0x0f;
  const masked = (b1 & 0x80) !== 0;
  let len = b1 & 0x7f;
  let pos = offset + 2;
  if (len === 126) {
    if (buf.length - pos < 2) return null;
    len = buf.readUInt16BE(pos);
    pos += 2;
  } else if (len === 127) {
    if (buf.length - pos < 8) return null;
    len = Number(buf.readBigUInt64BE(pos));
    pos += 8;
  }
  let maskKey: Buffer | null = null;
  if (masked) {
    if (buf.length - pos < 4) return null;
    maskKey = buf.subarray(pos, pos + 4);
    pos += 4;
  }
  if (buf.length - pos < len) return null;
  const raw = buf.subarray(pos, pos + len);
  const key = maskKey;
  const payload = key
    ? Buffer.from(raw.map((byte, i) => byte ^ key.readUInt8(i % 4)))
    : Buffer.from(raw);
  pos += len;
  return { frame: { opcode, payload }, next: pos };
}

export async function startFakeWsServer(script: FakeWsScript): Promise<FakeWsServer> {
  const requests: FakeWsRequest[] = [];
  const clientFrames: FakeWsFrame[] = [];
  // Tracked explicitly (not left to `server.closeAllConnections()`): once a
  // socket is handed off via the 'upgrade' event, Node's http.Server no
  // longer reliably counts it among the connections that gate `close()`'s
  // callback — a `neverAckClose` script leaves such a socket open forever by
  // design, which would otherwise hang every test's cleanup.
  const openSockets = new Set<Socket>();

  const server: Server = createServer((_req, res) => {
    res.statusCode = 404;
    res.end();
  });
  server.on("error", () => undefined);

  server.on("upgrade", (req, socket: Socket) => {
    socket.on("error", () => undefined);
    openSockets.add(socket);
    socket.on("close", () => openSockets.delete(socket));
    requests.push({ headers: req.headers, url: req.url });

    if (script.respondStatus !== undefined && script.respondStatus !== 101) {
      const statusText = script.respondStatus === 302 ? "Found" : "Bad Request";
      const extra = script.respondStatus === 302 ? "Location: http://127.0.0.1/elsewhere\r\n" : "";
      socket.end(
        `HTTP/1.1 ${script.respondStatus} ${statusText}\r\n${extra}Connection: close\r\n\r\n`,
      );
      return;
    }

    const key = req.headers["sec-websocket-key"];
    if (typeof key !== "string") {
      socket.destroy();
      return;
    }
    const accept = createHash("sha1")
      .update(key + WS_GUID)
      .digest("base64");

    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );

    let buf = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      let offset = 0;
      for (;;) {
        const decoded = tryDecodeClientFrame(buf, offset);
        if (!decoded) break;
        clientFrames.push(decoded.frame);
        offset = decoded.next;
        // RFC 6455 §5.5.1 closing handshake: a received Close frame is
        // answered with one, then the TCP connection ends — unconditionally,
        // `stall` only governs whether the server sends unprompted frames of
        // its own, never whether it completes a handshake the client started.
        // Without this, a client that closes against a stalled connection
        // hangs forever waiting for its own `close` event. `neverAckClose`
        // deliberately opts back out of this, for the one test that needs a
        // server that leaves the handshake incomplete.
        if (decoded.frame.opcode === 0x8 && !socket.destroyed && !script.neverAckClose) {
          const closePayload = Buffer.alloc(2);
          closePayload.writeUInt16BE(1000, 0);
          socket.end(buildServerFrame(0x8, closePayload));
        }
      }
      buf = buf.subarray(offset);
    });

    const messages = script.messages ?? [];
    let i = 0;
    const sendNext = (): void => {
      if (socket.destroyed) return;
      if (i >= messages.length) {
        if (!script.stall) {
          const closePayload = Buffer.alloc(2);
          closePayload.writeUInt16BE(1000, 0);
          socket.end(buildServerFrame(0x8, closePayload));
        }
        return;
      }
      const text = messages[i] as string;
      i += 1;
      socket.write(buildServerFrame(0x1, Buffer.from(text, "utf8")));
      setTimeout(sendNext, script.messageDelayMs ?? 0);
    };
    // Deferred, not written back-to-back with the 101 response: a caller's
    // post-`open` code (e.g. its own `send()`, or attaching its `message`
    // listener) needs a full client-side round trip after `open` fires before
    // it runs. Racing that — most sharply when there are zero scripted
    // messages, so the very next thing the server does is send the close
    // frame — can close the connection before the caller's own frame ever
    // reaches the wire. A short, fixed delay gives that round trip room.
    setTimeout(sendNext, 30);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const port = (server.address() as AddressInfo).port;

  return {
    port,
    requests: () => requests,
    clientFrames: () => clientFrames,
    close: () =>
      new Promise<void>((resolve) => {
        // A `neverAckClose` script deliberately leaves a connection open
        // forever (that's the point of it) — `server.close()` alone waits for
        // every open connection to end before its callback fires, which would
        // hang cleanup for exactly such a test. Force them closed first.
        for (const socket of openSockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}
