import { randomBytes } from "node:crypto";
import { connect } from "node:net";
import type { Socket } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { startFakeWsServer } from "./fake-ws-server.js";
import type { FakeWsServer } from "./fake-ws-server.js";

/**
 * Fixture self-check: clientFrames() must exclude control frames.
 *
 * The injector always finishes with a close frame, and whether that frame has
 * been decoded by the time a test samples clientFrames() is a scheduling race
 * the injector does not synchronize — macOS CI runners lost it routinely
 * while Linux and Windows happened to win it. The injector tests cannot pin
 * the exclusion deterministically (winning the race is what hid the defect),
 * so the pin lives here, where the close frame's arrival can be forced: the
 * server's close ack is sent only after it decoded the client's close frame,
 * so once the ack round-trip completes the frame is certainly recorded.
 */

function maskedClientFrame(opcode: number, payload: Buffer): Buffer {
  const mask = randomBytes(4);
  const masked = Buffer.from(payload);
  for (let i = 0; i < masked.length; i++) {
    masked[i] = (masked[i] as number) ^ (mask[i % 4] as number);
  }
  return Buffer.concat([Buffer.from([0x80 | opcode, 0x80 | payload.length]), mask, masked]);
}

let server: FakeWsServer | undefined;

afterEach(async () => {
  if (server) {
    await server.close();
    server = undefined;
  }
});

describe("fake-ws-server clientFrames", () => {
  it("excludes the close frame even after it is certainly decoded", async () => {
    server = await startFakeWsServer({});
    const fake = server;

    const socket: Socket = connect({ host: "127.0.0.1", port: fake.port });
    socket.on("error", () => undefined);
    await new Promise<void>((resolve) => socket.once("connect", () => resolve()));
    socket.write(
      "GET / HTTP/1.1\r\n" +
        `Host: 127.0.0.1:${String(fake.port)}\r\n` +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
        "Sec-WebSocket-Version: 13\r\n\r\n",
    );
    await new Promise<void>((resolve) => socket.once("data", () => resolve()));

    socket.write(maskedClientFrame(0x1, Buffer.from("hello", "utf8")));
    const closePayload = Buffer.alloc(2);
    closePayload.writeUInt16BE(1000, 0);
    socket.write(maskedClientFrame(0x8, closePayload));

    // The server ends the TCP connection right after answering the close
    // frame, so the socket closing proves the close frame was decoded and
    // recorded — no polling, no race.
    await new Promise<void>((resolve) => socket.once("close", () => resolve()));

    expect(fake.clientFrames().map((f) => f.opcode)).toEqual([0x1]);
    expect(fake.clientFrames()[0]?.payload.toString("utf8")).toBe("hello");
  });
});
