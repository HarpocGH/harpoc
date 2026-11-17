import { MongoClient, MongoServerError } from "mongodb";
import type { MongoClientOptions } from "mongodb";
import { afterEach, describe, expect, it } from "vitest";
import { startFakeMongod } from "./fake-mongod.js";
import type { FakeMongod } from "./fake-mongod.js";
import { expectAbsent } from "@harpoc/test-utils";

const USER_NAME = "app";
const PASSWORD = "stand-in-password";
const GUARD_MS = 5_000;

let fake: FakeMongod | undefined;
let client: MongoClient | undefined;

afterEach(async () => {
  try {
    await client?.close();
  } finally {
    client = undefined;
    await fake?.close();
    fake = undefined;
  }
});

function connectTo(port: number, options: MongoClientOptions): MongoClient {
  client = new MongoClient(`mongodb://127.0.0.1:${String(port)}/app_db`, {
    directConnection: true,
    serverSelectionTimeoutMS: 3_000,
    ...options,
  });
  return client;
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

describe("startFakeMongod against the real mongodb driver", () => {
  it("authenticates the driver over SCRAM-SHA-256 (the speculative hello and one saslContinue on the command's connection), answers the command with reply's document and records its maxTimeMS", async () => {
    fake = await startFakeMongod({
      user: USER_NAME,
      password: PASSWORD,
      reply: (command) => ({ ok: 1, answered: Object.keys(command)[0] }),
    });
    const mongo = connectTo(fake.port, { auth: { username: USER_NAME, password: PASSWORD } });
    const outcome = await within(
      settled(
        mongo.connect().then(() => mongo.db("app_db").command({ ping: 1, maxTimeMS: 1_500 })),
      ),
      GUARD_MS,
    );
    expect(outcome).toEqual({ ok: 1, answered: "ping" });
    const connection = fake.received().find((entry) => entry.stage === "ping")?.connection;
    expect(fake.received().filter((entry) => entry.connection === connection)).toEqual([
      { stage: "auth-hello", connection },
      { stage: "saslContinue", connection },
      { stage: "ping", connection, maxTimeMS: 1_500 },
    ]);
    expect(fake.connections()).toBe(2);
  });

  it.each([
    ["a wrong password", USER_NAME, `${PASSWORD}-wrong`],
    ["a wrong user name", `${USER_NAME}-other`, PASSWORD],
  ])(
    "refuses %s with Authentication failed. (code 18), the refusal carrying no part of the credential",
    async (_case, username, password) => {
      fake = await startFakeMongod({ user: USER_NAME, password: PASSWORD });
      const mongo = connectTo(fake.port, { auth: { username, password } });
      const outcome = await within(
        settled(mongo.connect().then(() => "connected" as const)),
        GUARD_MS,
      );
      expectAbsent((outcome as Error).message, PASSWORD);
      expect(outcome).toBeInstanceOf(MongoServerError);
      expect([(outcome as MongoServerError).code, (outcome as MongoServerError).message]).toEqual([
        18,
        "Authentication failed.",
      ]);
    },
  );

  it("keeps a trickled reply pending past two and a half idle windows of the client's socketTimeoutMS, and close() ends the command and destroys its socket", async () => {
    fake = await startFakeMongod({
      user: USER_NAME,
      password: PASSWORD,
      plan: (stage) => (stage === "ping" ? "trickle" : "answer"),
      trickleMs: 50,
    });
    const mongo = connectTo(fake.port, {
      auth: { username: USER_NAME, password: PASSWORD },
      socketTimeoutMS: 1_000,
    });
    expect(await within(settled(mongo.connect().then(() => "connected" as const)), GUARD_MS)).toBe(
      "connected",
    );
    const command = settled(mongo.db("app_db").command({ ping: 1 }));
    expect(await within(command, 2_500)).toBe("pending");
    await fake.close();
    const ended = await within(command, GUARD_MS);
    expect((ended as Error).name).toBe("MongoNetworkError");
    expect(fake.openSockets()).toBe(0);
  });

  it("never answers a silent command: the command is received and the client's socketTimeoutMS ends its idle read", async () => {
    fake = await startFakeMongod({
      user: USER_NAME,
      password: PASSWORD,
      plan: (stage) => (stage === "ping" ? "silent" : "answer"),
    });
    const mongo = connectTo(fake.port, {
      auth: { username: USER_NAME, password: PASSWORD },
      socketTimeoutMS: 1_000,
    });
    const outcome = await within(
      settled(mongo.connect().then(() => mongo.db("app_db").command({ ping: 1 }))),
      GUARD_MS,
    );
    expect((outcome as Error).name).toBe("MongoNetworkTimeoutError");
    expect(fake.received().map((entry) => entry.stage)).toContain("ping");
  });

  it("refuses a command on a connection that has not authenticated with code 13 Unauthorized", async () => {
    fake = await startFakeMongod({ user: USER_NAME, password: PASSWORD });
    const mongo = connectTo(fake.port, {});
    const outcome = await within(
      settled(mongo.connect().then(() => mongo.db("app_db").command({ find: "c", filter: {} }))),
      GUARD_MS,
    );
    expect(outcome).toBeInstanceOf(MongoServerError);
    expect([
      (outcome as MongoServerError).code,
      (outcome as MongoServerError).codeName,
      (outcome as MongoServerError).message,
    ]).toEqual([13, "Unauthorized", "command find requires authentication"]);
  });
});
