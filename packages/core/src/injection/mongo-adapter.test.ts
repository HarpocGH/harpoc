import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DbConnectOptions } from "./db-adapters.js";
import { MongoAdapter } from "./mongo-adapter.js";

// mongodb's `MongoClientOptions` fields relevant to TLS/socket dialing
// (`ca`, `checkServerIdentity`, `rejectUnauthorized`, `servername`, ...) are
// spread directly onto the object passed to `node:tls.connect()` with no
// field remapping — verified against mongodb@7.5.0's compiled
// `lib/cmap/connect.js` (`LEGAL_TLS_SOCKET_OPTIONS`). A fake `MongoClient`
// that records the constructor's `(uri, options)` and the `db().command()`
// call is therefore enough to assert on the exact wire shape without a live
// server, mirroring RedisAdapter's test strategy.
interface FakeCommandCall {
  command: unknown;
  options: { timeoutMS?: number } | undefined;
}

interface FakeBehavior {
  connectError?: Error;
  closeError?: Error;
  commandResult?: unknown;
  commandError?: Error;
}

const mongoClientCalls: { uri: string; options: MongoClientOptionsShape }[] = [];
const dbCalls: string[] = [];
const commandCalls: FakeCommandCall[] = [];
let closeCallCount = 0;
let behavior: FakeBehavior = {};

interface MongoClientOptionsShape {
  directConnection?: boolean;
  auth?: { username?: string; password?: string };
  connectTimeoutMS?: number;
  serverSelectionTimeoutMS?: number;
  socketTimeoutMS?: number;
  tls?: boolean;
  rejectUnauthorized?: boolean;
  tlsAllowInvalidCertificates?: boolean;
  tlsAllowInvalidHostnames?: boolean;
  ca?: string;
  servername?: string;
  checkServerIdentity?: (host: string, cert: unknown) => Error | undefined;
}

vi.mock("mongodb", () => {
  class MongoClient {
    constructor(uri: string, options: MongoClientOptionsShape) {
      mongoClientCalls.push({ uri, options });
    }
    connect(): Promise<this> {
      return behavior.connectError ? Promise.reject(behavior.connectError) : Promise.resolve(this);
    }
    close(): Promise<void> {
      closeCallCount += 1;
      return behavior.closeError ? Promise.reject(behavior.closeError) : Promise.resolve(undefined);
    }
    db(name: string): {
      command: (command: unknown, options?: { timeoutMS?: number }) => Promise<unknown>;
    } {
      dbCalls.push(name);
      return {
        command: (command: unknown, options?: { timeoutMS?: number }) => {
          commandCalls.push({ command, options });
          if (behavior.commandError) return Promise.reject(behavior.commandError);
          return Promise.resolve(behavior.commandResult ?? { ok: 1 });
        },
      };
    }
  }
  return { MongoClient };
});

function opts(overrides: Partial<DbConnectOptions> = {}): DbConnectOptions {
  return {
    host: "mongo.example.com",
    port: 27017,
    address: "203.0.113.9",
    user: "app",
    password: "s3cr3t",
    database: "app_db",
    tls: {},
    timeoutMs: 1000,
    ...overrides,
  };
}

beforeEach(() => {
  mongoClientCalls.length = 0;
  dbCalls.length = 0;
  commandCalls.length = 0;
  closeCallCount = 0;
  behavior = {};
});

describe("MongoAdapter connection config (SSRF pinning, spec §10.7)", () => {
  it("forces directConnection: true so the driver never dials undiscovered replica-set peers", async () => {
    await new MongoAdapter().execute(opts(), { ping: 1 });
    expect(mongoClientCalls[0]?.options.directConnection).toBe(true);
  });

  it("dials the pinned address in the connection URI, never the logical host", async () => {
    await new MongoAdapter().execute(opts(), { ping: 1 });
    const uri = mongoClientCalls[0]?.uri;
    expect(uri).toContain("203.0.113.9:27017");
    expect(uri).not.toContain("mongo.example.com");
  });

  it("brackets an IPv6 pinned address in the URI", async () => {
    await new MongoAdapter().execute(opts({ address: "2001:db8::1" }), { ping: 1 });
    const uri = mongoClientCalls[0]?.uri;
    expect(uri).toContain("[2001:db8::1]:27017");
  });

  it("binds TLS identity (servername) to the logical host while dialing the pinned address", async () => {
    await new MongoAdapter().execute(opts(), { ping: 1 });
    const cfg = mongoClientCalls[0]?.options;
    expect(cfg?.servername).toBe("mongo.example.com");
    expect(typeof cfg?.checkServerIdentity).toBe("function");
  });

  it("omits servername for an IP-literal target (SNI forbids an IP servername)", async () => {
    await new MongoAdapter().execute(opts({ host: "8.8.8.8", address: "8.8.8.8" }), { ping: 1 });
    const cfg = mongoClientCalls[0]?.options;
    expect(cfg).not.toHaveProperty("servername");
    // The identity check is still bound explicitly, so verification is not
    // silently skipped just because SNI cannot carry the name.
    expect(typeof cfg?.checkServerIdentity).toBe("function");
  });

  it("the identity check is bound to the logical host, not Node's own derivation", async () => {
    await new MongoAdapter().execute(opts(), { ping: 1 });
    const check = mongoClientCalls[0]?.options.checkServerIdentity as (
      h: string,
      c: { subject: { CN: string }; subjectaltname: string },
    ) => Error | undefined;

    const foreign = { subject: { CN: "localhost" }, subjectaltname: "DNS:localhost" };
    expect(check("localhost", foreign)).toBeInstanceOf(Error);

    const matching = {
      subject: { CN: "mongo.example.com" },
      subjectaltname: "DNS:mongo.example.com",
    };
    expect(check("localhost", matching)).toBeUndefined();
  });

  it("requires TLS by default with certificate + hostname verification never disabled", async () => {
    await new MongoAdapter().execute(opts(), { ping: 1 });
    const cfg = mongoClientCalls[0]?.options;
    expect(cfg?.tls).toBe(true);
    expect(cfg?.rejectUnauthorized).toBe(true);
    expect(cfg?.tlsAllowInvalidCertificates).toBe(false);
    expect(cfg?.tlsAllowInvalidHostnames).toBe(false);
  });

  it("still dials the pinned address with TLS disabled via the audited opt-out", async () => {
    await new MongoAdapter().execute(opts({ tls: false }), { ping: 1 });
    const cfg = mongoClientCalls[0]?.options;
    expect(cfg?.tls).toBe(false);
    expect(cfg).not.toHaveProperty("rejectUnauthorized");
    expect(cfg).not.toHaveProperty("checkServerIdentity");
    expect(cfg).not.toHaveProperty("ca");
  });

  it("forwards a pinned CA alongside certificate verification", async () => {
    await new MongoAdapter().execute(opts({ tls: { ca: "CA-PEM" } }), { ping: 1 });
    expect(mongoClientCalls[0]?.options.ca).toBe("CA-PEM");
  });

  it("forwards username/password from the split credential via the auth option", async () => {
    await new MongoAdapter().execute(opts({ user: "svc", password: "hunter2" }), { ping: 1 });
    expect(mongoClientCalls[0]?.options.auth).toEqual({ username: "svc", password: "hunter2" });
  });
});

describe("MongoAdapter timeouts (Task 10 carry-forward: bound the command, not just connect)", () => {
  it("bounds the connect phase with connectTimeoutMS + serverSelectionTimeoutMS", async () => {
    await new MongoAdapter().execute(opts({ timeoutMs: 4242 }), { ping: 1 });
    const cfg = mongoClientCalls[0]?.options;
    expect(cfg?.connectTimeoutMS).toBe(4242);
    expect(cfg?.serverSelectionTimeoutMS).toBe(4242);
  });

  it("sets a connection-level socketTimeoutMS as a defense-in-depth idle bound", async () => {
    await new MongoAdapter().execute(opts({ timeoutMs: 4242 }), { ping: 1 });
    expect(mongoClientCalls[0]?.options.socketTimeoutMS).toBe(4242);
  });

  // The load-bearing bound: mongodb@7.5.0's Db.command() has no public
  // `maxTimeMS` option — verified against the installed RunCommandOptions
  // type — only `timeoutMS` (CSOT), which both auto-injects `maxTimeMS` into
  // the outgoing command AND arms a client-side read deadline
  // (`timeoutForSocketRead`) independent of socket idle time. A long-running
  // command (an unindexed scan, a `$where` loop) must be bounded by this,
  // not just the connect-phase timeouts above.
  it("bounds the command phase by passing timeoutMS to db.command(), not just connect", async () => {
    await new MongoAdapter().execute(opts({ timeoutMs: 777 }), { count: "c" });
    expect(commandCalls[0]?.options?.timeoutMS).toBe(777);
  });

  it("still closes the client when the command call rejects (command-phase timeout surfaces as a rejection)", async () => {
    const timeoutError = new Error("operation exceeded time limit");
    timeoutError.name = "MongoOperationTimeoutError";
    behavior.commandError = timeoutError;
    await expect(
      new MongoAdapter().execute(opts({ timeoutMs: 50 }), { count: "c" }),
    ).rejects.toThrow("operation exceeded time limit");
    expect(closeCallCount).toBe(1);
  });
});

describe("MongoAdapter command execution + result normalization (spec §10.7)", () => {
  it("runs the command document via db.command() on the named database", async () => {
    await new MongoAdapter().execute(opts({ database: "app_db" }), { ping: 1 });
    expect(dbCalls).toEqual(["app_db"]);
    expect(commandCalls[0]?.command).toEqual({ ping: 1 });
  });

  it("normalizes a cursor-shaped response to its firstBatch", async () => {
    behavior.commandResult = {
      cursor: {
        id: 0n,
        ns: "app_db.c",
        firstBatch: [
          { _id: 1, x: "a" },
          { _id: 2, x: "b" },
        ],
      },
      ok: 1,
    };
    const res = await new MongoAdapter().execute(opts(), { find: "c" });
    expect(res.rows).toEqual([
      { _id: 1, x: "a" },
      { _id: 2, x: "b" },
    ]);
    expect(res.rowCount).toBe(2);
    expect(res.fields).toEqual([{ name: "_id" }, { name: "x" }]);
  });

  it("normalizes an empty cursor batch", async () => {
    behavior.commandResult = { cursor: { id: 0n, ns: "app_db.c", firstBatch: [] }, ok: 1 };
    const res = await new MongoAdapter().execute(opts(), { find: "c" });
    expect(res.rows).toEqual([]);
    expect(res.rowCount).toBe(0);
    expect(res.fields).toEqual([{ name: "result" }]);
  });

  it("normalizes a non-cursor response document as a single row", async () => {
    behavior.commandResult = { n: 42, ok: 1 };
    const res = await new MongoAdapter().execute(opts(), { count: "c" });
    expect(res.rows).toEqual([{ n: 42, ok: 1 }]);
    expect(res.rowCount).toBe(1);
    expect(res.fields).toEqual([{ name: "result" }]);
  });

  it("closes the client after a successful command", async () => {
    await new MongoAdapter().execute(opts(), { ping: 1 });
    expect(closeCallCount).toBe(1);
  });

  it("closes the client even when the command rejects, and propagates the error", async () => {
    behavior.commandError = new Error("boom");
    await expect(new MongoAdapter().execute(opts(), { ping: 1 })).rejects.toThrow("boom");
    expect(closeCallCount).toBe(1);
  });

  it("propagates a connect failure without ever calling db()/command()", async () => {
    behavior.connectError = new Error("ECONNREFUSED");
    await expect(new MongoAdapter().execute(opts(), { ping: 1 })).rejects.toThrow("ECONNREFUSED");
    expect(dbCalls).toHaveLength(0);
    expect(commandCalls).toHaveLength(0);
  });

  it("a close failure does not mask the original command error", async () => {
    behavior.commandError = new Error("boom");
    behavior.closeError = new Error("close failed");
    await expect(new MongoAdapter().execute(opts(), { ping: 1 })).rejects.toThrow("boom");
  });
});
