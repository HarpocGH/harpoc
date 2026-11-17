import { createServer } from "node:net";
import type { AddressInfo, Socket } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DbConnectOptions } from "./db-adapters.js";
import { RedisAdapter } from "./redis-adapter.js";

const PASSWORD = "stand-in-password";
const GUARD_MS = 5_000;
const TRICKLE_MS = 100;
const COMMAND = ["ECHO", "stand-in reply"];

interface RespServer {
  readonly port: number;
  openSockets(): number;
  stalledOn(): string | undefined;
  close(): Promise<void>;
}

function parseCommand(buffer: Buffer): { args: string[]; length: number } | undefined {
  let at = buffer.indexOf("\r\n");
  if (buffer[0] !== 0x2a || at < 0) return undefined;
  const count = Number(buffer.subarray(1, at).toString());
  at += 2;
  const args: string[] = [];
  for (let i = 0; i < count; i++) {
    const end = buffer.indexOf("\r\n", at);
    if (end < 0) return undefined;
    const size = Number(buffer.subarray(at + 1, end).toString());
    if (buffer.length < end + 4 + size) return undefined;
    args.push(buffer.subarray(end + 2, end + 2 + size).toString());
    at = end + 4 + size;
  }
  return { args, length: at };
}

function answer([name = "", first = ""]: string[]): string {
  if (name.toUpperCase() === "PING") return "+PONG\r\n";
  if (name.toUpperCase() === "ECHO") return `$${String(Buffer.byteLength(first))}\r\n${first}\r\n`;
  return "+OK\r\n";
}

async function startRespServer(trickled?: string): Promise<RespServer> {
  const sockets = new Set<Socket>();
  let stalledOn: string | undefined;
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => undefined);
    socket.once("close", () => sockets.delete(socket));
    let buffered = Buffer.alloc(0);
    let stalled = false;
    socket.on("data", (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      for (;;) {
        const parsed = stalled ? undefined : parseCommand(buffered);
        if (parsed === undefined) return;
        buffered = buffered.subarray(parsed.length);
        const name = parsed.args[0]?.toUpperCase();
        if (name !== trickled) {
          socket.write(answer(parsed.args));
          continue;
        }
        stalled = true;
        stalledOn = name;
        socket.write("$1000000\r\n");
        const timer = setInterval(() => socket.write("x"), TRICKLE_MS);
        socket.once("close", () => clearInterval(timer));
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: (server.address() as AddressInfo).port,
    openSockets: () => sockets.size,
    stalledOn: () => stalledOn,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    },
  };
}

function opts(port: number, timeoutMs: number): DbConnectOptions {
  return {
    host: "127.0.0.1",
    address: "127.0.0.1",
    port,
    user: "default",
    password: PASSWORD,
    database: "0",
    tls: false,
    timeoutMs,
  };
}

function settled<T>(promise: Promise<T>): Promise<T | Error> {
  return promise.then(
    (value) => value,
    (err: unknown) => err as Error,
  );
}

async function within<T>(promise: Promise<T>, boundMs: number): Promise<T | "pending"> {
  let guard: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<"pending">((resolve) => {
        guard = setTimeout(() => resolve("pending"), boundMs);
      }),
    ]);
  } finally {
    clearTimeout(guard);
  }
}

function flushed(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

function execute(port: number, timeoutMs: number): Promise<unknown> {
  return within(settled(new RedisAdapter().execute(opts(port, timeoutMs), COMMAND)), GUARD_MS);
}

async function socketsClosed(resp: RespServer, boundMs: number): Promise<void> {
  await vi.waitFor(
    () => {
      expect(resp.openSockets()).toBe(0);
    },
    { timeout: boundMs, interval: 10 },
  );
}

describe("RedisAdapter against the RESP stand-in (the real driver): one deadline over the whole use", () => {
  let server: RespServer | undefined;
  let unhandled = 0;
  const countUnhandled = (): void => {
    unhandled += 1;
  };

  beforeEach(() => {
    unhandled = 0;
  });

  afterEach(async () => {
    process.off("unhandledRejection", countUnhandled);
    await server?.close();
    server = undefined;
  });

  it.each([
    ["HELLO", 1_000],
    ["ECHO", 1_000],
  ] as const)(
    "%s: a trickled reply ends at the budget with the deadline's text, the stand-in sees the socket closed, no unhandled rejection",
    async (trickled, budgetMs) => {
      process.on("unhandledRejection", countUnhandled);
      const resp = await startRespServer(trickled);
      server = resp;
      const outcome = await execute(resp.port, budgetMs);
      await flushed();
      expect(unhandled).toBe(0);
      expect(resp.stalledOn()).toBe(trickled);
      expect(outcome).toBeInstanceOf(Error);
      expect((outcome as Error).message).toBe(
        `command did not complete within ${String(budgetMs)} ms`,
      );
      await socketsClosed(resp, GUARD_MS);
    },
  );

  it("an answered command resolves with its reply and the stand-in sees the socket closed by the adapter, not by the idle bound", async () => {
    const resp = await startRespServer();
    server = resp;
    const outcome = await execute(resp.port, 30_000);
    expect(outcome).toEqual({
      rows: ["stand-in reply"],
      fields: [{ name: "reply" }],
      rowCount: 1,
      command: undefined,
    });
    await socketsClosed(resp, 2_000);
  });
});
