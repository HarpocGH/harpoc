import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:net";
import type { AddressInfo, Socket } from "node:net";
import { BSON } from "mongodb";

export type FakeMongodAnswer = "answer" | "silent" | "trickle" | "close" | "answer-then-close";

export interface FakeMongodOptions {
  user: string;
  password: string;
  plan?: (
    stage: string,
    command: Record<string, unknown>,
    seen: { connection: number; nth: number },
  ) => FakeMongodAnswer;
  reply?: (command: Record<string, unknown>) => Record<string, unknown>;
  trickleMs?: number;
  iterations?: number;
}

export interface FakeMongod {
  port: number;
  connections(): number;
  openSockets(): number;
  received(): ReadonlyArray<{ stage: string; connection: number; maxTimeMS?: number }>;
  close(): Promise<void>;
}

interface Connection {
  id: number;
  clientFirstBare: string;
  serverFirst: string;
  nonce: string;
  user: string | undefined;
  authenticated: boolean;
}

const OP_REPLY = 1;
const OP_QUERY = 2004;
const OP_MSG = 2013;
const MORE_TO_COME = 2;
const ITERATIONS = 4096;

function header(length: number, requestId: number, responseTo: number, opCode: number): Buffer {
  const head = Buffer.alloc(16);
  head.writeInt32LE(length, 0);
  head.writeInt32LE(requestId, 4);
  head.writeInt32LE(responseTo, 8);
  head.writeInt32LE(opCode, 12);
  return head;
}

function frame(
  requestOpCode: number,
  requestId: number,
  responseTo: number,
  document: Record<string, unknown>,
): Buffer {
  const body = Buffer.from(BSON.serialize(document));
  if (requestOpCode === OP_QUERY) {
    const fixed = Buffer.alloc(20);
    fixed.writeInt32LE(8, 0);
    fixed.writeInt32LE(1, 16);
    return Buffer.concat([header(36 + body.length, requestId, responseTo, OP_REPLY), fixed, body]);
  }
  return Buffer.concat([
    header(21 + body.length, requestId, responseTo, OP_MSG),
    Buffer.alloc(5),
    body,
  ]);
}

function parse(
  message: Buffer,
): { opCode: number; moreToCome: boolean; command: Record<string, unknown> } | null {
  const opCode = message.readInt32LE(12);
  try {
    if (opCode === OP_QUERY) {
      const nameEnd = message.indexOf(0, 20);
      if (nameEnd < 0) return null;
      return {
        opCode,
        moreToCome: false,
        command: BSON.deserialize(message.subarray(nameEnd + 9)),
      };
    }
    if (opCode === OP_MSG && message[20] === 0) {
      return {
        opCode,
        moreToCome: (message.readUInt32LE(16) & MORE_TO_COME) !== 0,
        command: BSON.deserialize(message.subarray(21)),
      };
    }
  } catch {
    return null;
  }
  return null;
}

function stageOf(command: Record<string, unknown>): string {
  const name = Object.keys(command)[0] ?? "";
  if (name === "hello" || name === "ismaster" || name === "isMaster") {
    return "saslSupportedMechs" in command || "speculativeAuthenticate" in command
      ? "auth-hello"
      : "monitor-hello";
  }
  return name;
}

function hello(connectionId: number): Record<string, unknown> {
  return {
    helloOk: true,
    isWritablePrimary: true,
    ismaster: true,
    maxBsonObjectSize: 16_777_216,
    maxMessageSizeBytes: 48_000_000,
    maxWriteBatchSize: 100_000,
    localTime: new Date(),
    logicalSessionTimeoutMinutes: 30,
    connectionId,
    minWireVersion: 0,
    maxWireVersion: 21,
    readOnly: false,
    ok: 1,
  };
}

function unauthorized(name: string): Record<string, unknown> {
  return {
    ok: 0,
    errmsg: `command ${name} requires authentication`,
    code: 13,
    codeName: "Unauthorized",
  };
}

function payloadText(payload: unknown): string {
  return payload instanceof BSON.Binary ? payload.toString("utf8") : "";
}

function scramFields(text: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const part of text.split(",")) {
    const at = part.indexOf("=");
    if (at > 0) fields[part.slice(0, at)] = part.slice(at + 1);
  }
  return fields;
}

function hmac(key: Buffer, text: string): Buffer {
  return createHmac("sha256", key).update(text).digest();
}

function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

function xor(left: Buffer, right: Buffer): Buffer {
  return Buffer.from(left.map((byte, i) => byte ^ (right[i] ?? 0)));
}

export async function startFakeMongod(options: FakeMongodOptions): Promise<FakeMongod> {
  const plan = options.plan ?? (() => "answer");
  const reply = options.reply ?? (() => ({ ok: 1 }));
  const trickleMs = options.trickleMs ?? 200;
  const iterations = options.iterations ?? ITERATIONS;
  const saslUser = options.user.replace(/=/g, "=3D").replace(/,/g, "=2C");
  const salt = randomBytes(16);
  const salted = pbkdf2Sync(options.password, salt, iterations, 32, "sha256");
  const storedKey = sha256(hmac(salted, "Client Key"));
  const serverKey = hmac(salted, "Server Key");
  const received: { stage: string; connection: number; maxTimeMS?: number }[] = [];
  const seen = new Map<string, number>();
  const sockets = new Set<Socket>();
  let connections = 0;
  let nextRequestId = 1;
  let closing: Promise<void> | undefined;

  function startScram(conn: Connection, start: Record<string, unknown>): Record<string, unknown> {
    const clientFirst = payloadText(start.payload);
    conn.clientFirstBare = clientFirst.slice(
      clientFirst.indexOf(",", clientFirst.indexOf(",") + 1) + 1,
    );
    const fields = scramFields(conn.clientFirstBare);
    conn.user = fields.n;
    conn.nonce = `${fields.r ?? ""}${randomBytes(18).toString("base64")}`;
    conn.serverFirst = `r=${conn.nonce},s=${salt.toString("base64")},i=${String(iterations)}`;
    return {
      conversationId: 1,
      done: false,
      payload: new BSON.Binary(Buffer.from(conn.serverFirst)),
    };
  }

  function continueScram(conn: Connection, next: Record<string, unknown>): Record<string, unknown> {
    const clientFinal = payloadText(next.payload);
    const fields = scramFields(clientFinal);
    const withoutProof = clientFinal.slice(0, clientFinal.lastIndexOf(",p="));
    const authMessage = `${conn.clientFirstBare},${conn.serverFirst},${withoutProof}`;
    const signature = hmac(storedKey, authMessage);
    const proof = Buffer.from(fields.p ?? "", "base64");
    const proofHolds =
      proof.length === signature.length &&
      timingSafeEqual(sha256(xor(proof, signature)), storedKey);
    if (fields.r !== conn.nonce || conn.user !== saslUser || !proofHolds) {
      return {
        ok: 0,
        errmsg: "Authentication failed.",
        code: 18,
        codeName: "AuthenticationFailed",
      };
    }
    conn.authenticated = true;
    const verifier = hmac(serverKey, authMessage).toString("base64");
    return {
      conversationId: 1,
      done: true,
      payload: new BSON.Binary(Buffer.from(`v=${verifier}`)),
      ok: 1,
    };
  }

  function answerTo(
    conn: Connection,
    stage: string,
    command: Record<string, unknown>,
  ): Record<string, unknown> {
    if (stage === "monitor-hello") return hello(conn.id);
    if (stage === "auth-hello") {
      const speculative = command.speculativeAuthenticate;
      return {
        ...hello(conn.id),
        saslSupportedMechs: ["SCRAM-SHA-256"],
        ...(typeof speculative === "object" && speculative !== null
          ? { speculativeAuthenticate: startScram(conn, speculative as Record<string, unknown>) }
          : {}),
      };
    }
    if (stage === "saslStart") return { ...startScram(conn, command), ok: 1 };
    if (stage === "saslContinue") return continueScram(conn, command);
    if (!conn.authenticated) return unauthorized(stage);
    return reply(command);
  }

  function trickle(socket: Socket, announce: Buffer): void {
    socket.write(announce);
    const timer = setInterval(() => socket.write(Buffer.alloc(1)), trickleMs);
    socket.once("close", () => clearInterval(timer));
  }

  function respond(
    socket: Socket,
    how: FakeMongodAnswer,
    opCode: number,
    requestId: number,
    answer: Record<string, unknown>,
  ): void {
    if (how === "silent") return;
    if (how === "close") {
      socket.destroy();
    } else if (how === "trickle") {
      const replyOpCode = opCode === OP_QUERY ? OP_REPLY : OP_MSG;
      trickle(socket, header(1_000_000, nextRequestId++, requestId, replyOpCode));
    } else if (how === "answer-then-close") {
      socket.end(frame(opCode, nextRequestId++, requestId, answer));
    } else {
      socket.write(frame(opCode, nextRequestId++, requestId, answer));
    }
  }

  function handle(socket: Socket, conn: Connection, message: Buffer): void {
    const parsed = parse(message);
    if (parsed === null) {
      socket.destroy();
      return;
    }
    const { opCode, moreToCome, command } = parsed;
    const stage = stageOf(command);
    const maxTimeMS = command.maxTimeMS;
    received.push(
      typeof maxTimeMS === "number"
        ? { stage, connection: conn.id, maxTimeMS }
        : { stage, connection: conn.id },
    );
    if (moreToCome) return;
    const nth = (seen.get(stage) ?? 0) + 1;
    seen.set(stage, nth);
    const how = plan(stage, command, { connection: conn.id, nth });
    respond(socket, how, opCode, message.readInt32LE(4), answerTo(conn, stage, command));
  }

  const server = createServer((socket) => {
    const conn: Connection = {
      id: ++connections,
      clientFirstBare: "",
      serverFirst: "",
      nonce: "",
      user: undefined,
      authenticated: false,
    };
    sockets.add(socket);
    socket.on("error", () => undefined);
    socket.once("close", () => sockets.delete(socket));
    let buffered = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      while (buffered.length >= 4 && !socket.destroyed) {
        const length = buffered.readInt32LE(0);
        if (length < 16) {
          socket.destroy();
          return;
        }
        if (buffered.length < length) return;
        const message = buffered.subarray(0, length);
        buffered = buffered.subarray(length);
        handle(socket, conn, message);
      }
    });
  });

  async function closeAll(): Promise<void> {
    const socketsClosed = [...sockets].map(
      (socket) =>
        new Promise<void>((resolve) => {
          socket.once("close", () => resolve());
          socket.destroy();
        }),
    );
    await Promise.all([
      ...socketsClosed,
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
    ]);
  }

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: (server.address() as AddressInfo).port,
    connections: () => connections,
    openSockets: () => sockets.size,
    received: () => [...received],
    close: () => (closing ??= closeAll()),
  };
}
