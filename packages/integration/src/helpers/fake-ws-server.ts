import { createHash } from "node:crypto";
import { createServer } from "node:http";
import type { IncomingHttpHeaders, Server } from "node:http";
import type { AddressInfo, Socket } from "node:net";

/**
 * Scripted fake WebSocket server, a local copy of core's
 * `packages/core/src/injection/__fixtures__/fake-ws-server.ts` (integration
 * cannot import a module out of core's `src/` — see the SMTP fake's header).
 * It handles the RFC 6455 upgrade by hand on a raw `node:http` server: the
 * handshake (`Sec-WebSocket-Accept` from the client's key), unmasked
 * server→client text frames, and a masked-frame decoder for client→server
 * frames. Plain `ws://` on loopback, so no certificate is involved.
 */

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

export interface FakeWsScript {
  /** Server→client text frames sent, in order, once the handshake completes. */
  messages?: string[];
  /** After `messages` is exhausted, hold the connection open instead of
   * sending a close frame. */
  stall?: boolean;
  /** Delay in ms between successive frames (default 0). */
  messageDelayMs?: number;
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
 * buffer holds a complete one yet. Returns `null` when it does not.
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
        // RFC 6455 §5.5.1: answer a received Close with one, then end.
        if (decoded.frame.opcode === 0x8 && !socket.destroyed) {
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
    // Deferred so a caller's post-`open` frame reaches the wire before the
    // server closes on an empty script (mirrors the core fixture's note).
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
        for (const socket of openSockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}
