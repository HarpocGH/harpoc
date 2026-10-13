import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo, Server, Socket } from "node:net";
import { dirname, join } from "node:path";
import { Duplex } from "node:stream";
import { createSecureContext, TLSSocket } from "node:tls";
import { fileURLToPath } from "node:url";

/**
 * Loopback TLS listeners that speak just enough of each database protocol for
 * the real driver to start TLS: postgresql answers the SSLRequest with `S`,
 * mysql sends a HandshakeV10 advertising CLIENT_SSL and upgrades after the
 * SSLRequest packet, redis and mongodb open with TLS (redis then answers each
 * command `+OK`, PING `+PONG`, so the action completes). The server presents the
 * fixture leaf (`fixture.example.com`), records the SNI name each client sent,
 * and counts a client as having accepted the certificate only once it writes
 * application data over the secured socket — a client that refused the
 * server's identity tears the socket down before writing anything.
 */
const CERTS = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "__fixtures__", "certs");
export const FIXTURE_CERT_PEM = readFileSync(join(CERTS, "rsa-cert.pem"), "utf8");
const FIXTURE_KEY_PEM = readFileSync(join(CERTS, "rsa-key.pem"), "utf8");
export const FIXTURE_NAME = "fixture.example.com";

export type DbTlsEngine = "postgresql" | "mysql" | "redis" | "mongodb";

export interface DbTlsServer {
  port: number;
  /** The SNI name of each secured connection, `false` when the client sent none. */
  sni: (string | false)[];
  /** Secured connections on which the client went on to write application data. */
  accepted: number;
  close(): Promise<void>;
}

function mysqlHandshake(): Buffer {
  const payload = Buffer.concat([
    Buffer.from([0x0a]),
    Buffer.from("8.0.0\0", "latin1"),
    Buffer.from([1, 0, 0, 0]),
    Buffer.from("abcdefgh", "latin1"),
    Buffer.from([0]),
    Buffer.from([0x09, 0x8a]),
    Buffer.from([0x21]),
    Buffer.from([0x02, 0x00]),
    Buffer.from([0x08, 0x00]),
    Buffer.from([21]),
    Buffer.alloc(10),
    Buffer.from("ijklmnopqrst\0", "latin1"),
    Buffer.from("mysql_native_password\0", "latin1"),
  ]);
  const header = Buffer.from([payload.length & 0xff, (payload.length >> 8) & 0xff, 0, 0]);
  return Buffer.concat([header, payload]);
}

/** One RESP simple-string reply per command in `chunk`: `+PONG` for PING, `+OK` otherwise. */
function respReplies(chunk: Buffer): string {
  const lines = chunk.toString("latin1").split("\r\n");
  let out = "";
  let i = 0;
  while (i < lines.length) {
    const head = /^\*(\d+)$/.exec(lines[i] ?? "");
    if (!head) {
      i += 1;
      continue;
    }
    const name = (lines[i + 2] ?? "").toUpperCase();
    out += name === "PING" ? "+PONG\r\n" : "+OK\r\n";
    i += 1 + 2 * Number(head[1]);
  }
  return out;
}

export async function startDbTlsServer(engine: DbTlsEngine): Promise<DbTlsServer> {
  const secureContext = createSecureContext({ cert: FIXTURE_CERT_PEM, key: FIXTURE_KEY_PEM });
  const sockets = new Set<Socket>();
  const state: DbTlsServer = {
    port: 0,
    sni: [],
    accepted: 0,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(() => resolve());
      }),
  };

  // The TLS layer runs over a bridge, not the raw socket: a mysql client
  // writes its ClientHello right behind the SSLRequest, often in one segment,
  // and the bytes already read past the preamble must reach the TLS layer.
  const secure = (raw: Socket, rest: Buffer): void => {
    raw.removeAllListeners("data");
    const bridge = new Duplex({
      read() {},
      write(chunk: Buffer, _encoding, callback) {
        raw.write(chunk, callback);
      },
    });
    if (rest.length > 0) bridge.push(rest);
    raw.on("data", (chunk: Buffer) => bridge.push(chunk));
    raw.on("close", () => bridge.destroy());
    const tlsSocket = new TLSSocket(bridge, { isServer: true, secureContext });
    sockets.add(tlsSocket);
    tlsSocket.on("error", () => undefined);
    tlsSocket.on("close", () => raw.destroy());
    tlsSocket.on("secure", () => {
      const name = (tlsSocket as TLSSocket & { servername?: string | false }).servername;
      state.sni.push(typeof name === "string" && name.length > 0 ? name : false);
    });
    let spoke = false;
    tlsSocket.on("data", (chunk: Buffer) => {
      if (!spoke) {
        spoke = true;
        state.accepted += 1;
      }
      if (engine === "redis") {
        tlsSocket.write(respReplies(chunk));
      } else {
        tlsSocket.destroy();
      }
    });
  };

  const server: Server = createServer((raw) => {
    sockets.add(raw);
    raw.on("error", () => undefined);
    if (engine === "redis" || engine === "mongodb") {
      secure(raw, Buffer.alloc(0));
      return;
    }
    if (engine === "mysql") raw.write(mysqlHandshake());
    let preamble = Buffer.alloc(0);
    const need = engine === "postgresql" ? 8 : 36;
    raw.on("data", (chunk: Buffer) => {
      preamble = Buffer.concat([preamble, chunk]);
      if (preamble.length < need) return;
      if (engine === "postgresql") raw.write("S");
      secure(raw, preamble.subarray(need));
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  state.port = (server.address() as AddressInfo).port;
  return state;
}
