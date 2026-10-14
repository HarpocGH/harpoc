import { createServer } from "node:net";
import type { AddressInfo, Socket } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { DbConnectOptions } from "./db-adapters.js";
import { RedisAdapter } from "./redis-adapter.js";

type Drop = "fin-on-connect" | "reset-after-hello";

interface DropServer {
  readonly port: number;
  readonly connections: number;
  close(): Promise<void>;
}

/** A loopback listener that drops every connection: a FIN at once, or a reset after the client's first bytes. */
async function startDropServer(drop: Drop): Promise<DropServer> {
  const sockets = new Set<Socket>();
  let connections = 0;
  const server = createServer((socket) => {
    connections++;
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    if (drop === "fin-on-connect") socket.end();
    else socket.once("data", () => socket.resetAndDestroy());
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    port,
    get connections() {
      return connections;
    },
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    },
  };
}

function opts(port: number): DbConnectOptions {
  return {
    host: "127.0.0.1",
    address: "127.0.0.1",
    port,
    user: "default",
    password: "pw",
    database: "0",
    tls: false,
    timeoutMs: 1_000,
  };
}

/**
 * U3-k of test-review-2026-10-09's coverage program (fixed after U3's close):
 * an endpoint that drops the socket during the handshake. node-redis emits
 * `error` on the client for every socket failure; with no listener the emit
 * throws inside the socket's own event handler — an uncaught exception, which
 * would end the vault process — and on a FIN that throw also strands the
 * connect promise, so the use hung. Its default reconnect strategy retries
 * forever. The adapter runs one command on a throwaway client: it listens, and
 * it never reconnects.
 */
describe("RedisAdapter against an endpoint that drops the socket (the real driver)", () => {
  const uncaught: Error[] = [];
  const capture = (err: Error) => {
    uncaught.push(err);
  };
  let server: DropServer | undefined;

  beforeEach(() => {
    uncaught.length = 0;
    process.on("uncaughtException", capture);
  });

  afterEach(async () => {
    process.off("uncaughtException", capture);
    await server?.close();
    server = undefined;
  });

  it.each([["fin-on-connect"], ["reset-after-hello"]] as const)(
    "%s: execute rejects within the budget, raises no uncaught exception and never reconnects",
    async (drop) => {
      server = await startDropServer(drop);
      let guard: NodeJS.Timeout | undefined;
      const outcome = await Promise.race([
        new RedisAdapter().execute(opts(server.port), ["PING"]).then(
          () => "resolved" as const,
          (err: unknown) => err as Error,
        ),
        new Promise<"pending">((resolve) => {
          guard = setTimeout(() => resolve("pending"), 5_000);
        }),
      ]);
      clearTimeout(guard);
      expect(outcome).toBeInstanceOf(Error);
      expect((outcome as Error).message).toMatch(/socket closed unexpectedly|ECONNRESET/i);
      // The socket's second error (the reset's ECONNRESET, the FIN's close)
      // reaches the client a few event-loop turns after the rejection; its
      // absence has no product event to await.
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(uncaught.map((err) => err.message)).toEqual([]);
      expect(server.connections).toBe(1);
    },
  );
});
