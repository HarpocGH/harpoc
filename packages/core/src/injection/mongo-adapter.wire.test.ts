import { webcrypto } from "node:crypto";
import { MongoNetworkError } from "mongodb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DbConnectOptions } from "./db-adapters.js";
import { MongoAdapter } from "./mongo-adapter.js";
import { startFakeMongod } from "./__fixtures__/fake-mongod.js";
import type { FakeMongod, FakeMongodOptions } from "./__fixtures__/fake-mongod.js";

const USER_NAME = "app";
const PASSWORD = "stand-in-password";
const GUARD_MS = 5_000;
const TRICKLE_MS = 100;
const FIND = { find: "c", filter: {} };

let fake: FakeMongod | undefined;
let unhandled = 0;
const countUnhandled = (): void => {
  unhandled += 1;
};

beforeEach(() => {
  unhandled = 0;
});

afterEach(async () => {
  vi.restoreAllMocks();
  process.off("unhandledRejection", countUnhandled);
  await fake?.close();
  fake = undefined;
});

async function standIn(
  plan: FakeMongodOptions["plan"],
  reply?: FakeMongodOptions["reply"],
  iterations?: number,
): Promise<FakeMongod> {
  fake = await startFakeMongod({
    user: USER_NAME,
    password: PASSWORD,
    trickleMs: TRICKLE_MS,
    plan,
    reply,
    iterations,
  });
  return fake;
}

function opts(port: number, timeoutMs: number): DbConnectOptions {
  return {
    host: "127.0.0.1",
    address: "127.0.0.1",
    port,
    user: USER_NAME,
    password: PASSWORD,
    database: "app_db",
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
  return within(settled(new MongoAdapter().execute(opts(port, timeoutMs), FIND)), GUARD_MS);
}

describe("MongoAdapter against the wire stand-in (the real mongodb driver)", () => {
  it.each([["auth-hello"], ["saslContinue"]] as const)(
    "%s: a trickled authentication ends at the budget with the deadline's reason, no unhandled rejection",
    async (trickled) => {
      process.on("unhandledRejection", countUnhandled);
      const server = await standIn((stage) => (stage === trickled ? "trickle" : "answer"));
      const outcome = await execute(server.port, 1_000);
      await flushed();
      expect(unhandled).toBe(0);
      expect(outcome).toBeInstanceOf(MongoNetworkError);
      expect((outcome as Error).message).toBe("command did not complete within 1000 ms");
    },
  );

  it("a monitor whose hello is closed ends the use with the driver's MongoServerSelectionError, not the deadline's reason, no unhandled rejection", async () => {
    process.on("unhandledRejection", countUnhandled);
    const server = await standIn((stage) => (stage === "monitor-hello" ? "close" : "answer"));
    const outcome = await execute(server.port, 300);
    await flushed();
    expect(unhandled).toBe(0);
    expect((outcome as Error).name).toBe("MongoServerSelectionError");
  });

  it("a trickled reply ends at the budget and the command carried maxTimeMS at the budget", async () => {
    const server = await standIn((stage) => (stage === "find" ? "trickle" : "answer"));
    const outcome = await execute(server.port, 1_000);
    expect(outcome).toBeInstanceOf(MongoNetworkError);
    expect((outcome as Error).message).toBe("command did not complete within 1000 ms");
    expect(server.received().find((entry) => entry.stage === "find")?.maxTimeMS).toBe(1_000);
  });

  it("an unanswered command ends at the budget and close() dials no connection (the stand-in has seen exactly two)", async () => {
    const server = await standIn((stage, _command, seen) => {
      if (seen.connection > 2) return "trickle";
      return stage === "find" ? "silent" : "answer";
    });
    const outcome = await execute(server.port, 1_000);
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(server.connections()).toBe(2);
    expect(outcome).toBeInstanceOf(MongoNetworkError);
    expect((outcome as Error).message).toBe("command did not complete within 1000 ms");
  });

  it("an answered command resolves with the normalized rows and no socket stays open", async () => {
    const server = await standIn(undefined, () => ({
      cursor: {
        id: 0,
        ns: "app_db.c",
        firstBatch: [
          { _id: 1, x: "a" },
          { _id: 2, x: "b" },
        ],
      },
      ok: 1,
    }));
    const outcome = await execute(server.port, 1_000);
    expect(outcome).toEqual({
      rows: [
        { _id: 1, x: "a" },
        { _id: 2, x: "b" },
      ],
      fields: [{ name: "_id" }, { name: "x" }],
      rowCount: 2,
    });
    await vi.waitFor(
      () => {
        expect(server.openSockets()).toBe(0);
      },
      { timeout: GUARD_MS, interval: 10 },
    );
  });

  it("a server that announces a SCRAM iteration count of 100001 is refused before the key is derived: the driver's MongoRuntimeError naming the count and the ceiling, not the deadline's reason, no saslContinue sent, no unhandled rejection", async () => {
    const derive = vi.spyOn(webcrypto.subtle, "deriveBits");
    process.on("unhandledRejection", countUnhandled);
    const server = await standIn(undefined, undefined, 100_001);
    const outcome = await execute(server.port, 3_000);
    await flushed();
    expect(unhandled).toBe(0);
    expect((outcome as Error).name).toBe("MongoRuntimeError");
    expect((outcome as Error).message).toBe(
      "Server returned an iteration count 100001 above the ceiling of 100000",
    );
    expect(server.received().some((entry) => entry.stage === "saslContinue")).toBe(false);
    expect(derive).not.toHaveBeenCalled();
  });

  it("a server that announces exactly 100000 is served: the key is derived, the command resolves and a saslContinue was sent", async () => {
    const derive = vi.spyOn(webcrypto.subtle, "deriveBits");
    const server = await standIn(
      undefined,
      () => ({ cursor: { id: 0, ns: "app_db.c", firstBatch: [{ _id: 1 }] }, ok: 1 }),
      100_000,
    );
    const outcome = await execute(server.port, 3_000);
    expect(outcome).toEqual({ rows: [{ _id: 1 }], fields: [{ name: "_id" }], rowCount: 1 });
    expect(server.received().some((entry) => entry.stage === "saslContinue")).toBe(true);
    expect(derive).toHaveBeenCalled();
  });
});
