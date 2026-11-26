import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MongoNetworkError } from "mongodb";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { DbConnectOptions } from "./db-adapters.js";
import { MongoAdapter } from "./mongo-adapter.js";

// mongodb's `MongoClientOptions` fields relevant to TLS/socket dialing
// (`ca`, `checkServerIdentity`, `rejectUnauthorized`, `servername`, ...) are
// copied name by name onto the object passed to `node:tls.connect()` with no
// field remapping — verified against mongodb@7.9.0's compiled
// `lib/cmap/connect.js` (`LEGAL_TLS_SOCKET_OPTIONS`). A fake `MongoClient`
// that records the constructor's `(uri, options)` and the `db().command()`
// call is therefore enough to assert on the exact wire shape without a live
// server, mirroring RedisAdapter's test strategy.
interface FakeCommandOptions {
  signal?: AbortSignal;
  timeoutMS?: number;
}

interface FakeCommandCall {
  command: unknown;
  options: FakeCommandOptions | undefined;
}

interface FakeBehavior {
  connectError?: Error;
  connectHangs?: boolean;
  closeError?: Error;
  closeHangs?: boolean;
  closeThrows?: boolean;
  commandResult?: unknown;
  commandError?: Error;
  /** The command settles only when its `signal` aborts, as the driver's does. */
  commandHangs?: boolean;
  commandSettlesWith?: Promise<unknown>;
  reasonConstructorThrows?: boolean;
}

const mongoClientCalls: { uri: string; options: MongoClientOptionsShape }[] = [];
const dbCalls: string[] = [];
const commandCalls: FakeCommandCall[] = [];
let closeCallCount = 0;
let behavior: FakeBehavior = {};
let commandIssued: () => void = () => undefined;
let connectIssued: () => void = () => undefined;
let releaseConnect: () => void = () => undefined;

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
  class MongoNetworkError extends Error {
    constructor(message: string) {
      if (behavior.reasonConstructorThrows) throw new TypeError("driver constructor changed");
      super(message);
      this.name = "MongoNetworkError";
    }
  }
  class MongoClient {
    constructor(uri: string, options: MongoClientOptionsShape) {
      mongoClientCalls.push({ uri, options });
    }
    connect(): Promise<this> {
      connectIssued();
      if (behavior.connectHangs) {
        return new Promise((resolve) => {
          releaseConnect = () => resolve(this);
        });
      }
      return behavior.connectError ? Promise.reject(behavior.connectError) : Promise.resolve(this);
    }
    close(): Promise<void> {
      closeCallCount += 1;
      if (behavior.closeThrows) throw new Error("close threw");
      if (behavior.closeHangs) return new Promise(() => undefined);
      return behavior.closeError ? Promise.reject(behavior.closeError) : Promise.resolve(undefined);
    }
    db(name: string): {
      command: (command: unknown, options?: FakeCommandOptions) => Promise<unknown>;
    } {
      dbCalls.push(name);
      return {
        command: (command: unknown, options?: FakeCommandOptions) => {
          commandCalls.push({ command, options });
          commandIssued();
          if (behavior.commandHangs) {
            return new Promise((_resolve, reject) => {
              options?.signal?.addEventListener(
                "abort",
                () => {
                  reject(options.signal?.reason as Error);
                },
                { once: true },
              );
            });
          }
          if (behavior.commandSettlesWith) return behavior.commandSettlesWith;
          if (behavior.commandError) return Promise.reject(behavior.commandError);
          return Promise.resolve(behavior.commandResult ?? { ok: 1 });
        },
      };
    }
  }
  return { MongoClient, MongoNetworkError };
});

/** Runs every queued microtask: a real `setImmediate` (only the adapter's `setTimeout` is faked). */
function flushed(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

function nextCommand(): Promise<void> {
  return new Promise((resolve) => {
    commandIssued = resolve;
  });
}

function nextConnect(): Promise<void> {
  return new Promise((resolve) => {
    connectIssued = resolve;
  });
}

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
  commandIssued = () => undefined;
  connectIssued = () => undefined;
  releaseConnect = () => undefined;
});

afterEach(() => {
  vi.useRealTimers();
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

  it("a signal aborted while mongodb loads: VAULT_LOCKED, no client built", async () => {
    const controller = new AbortController();
    const suiteModule = await import("mongodb");
    vi.doMock("mongodb", () => {
      controller.abort();
      return suiteModule;
    });
    try {
      await expectVaultError(
        () => new MongoAdapter().execute(opts({ signal: controller.signal }), { ping: 1 }),
        ErrorCode.VAULT_LOCKED,
      );
      expect(mongoClientCalls.length).toBe(0);
    } finally {
      vi.doMock("mongodb", () => suiteModule);
    }
  });

  it("a live signal connects as before", async () => {
    await new MongoAdapter().execute(opts({ signal: new AbortController().signal }), { ping: 1 });
    expect(mongoClientCalls.length).toBe(1);
    expect(dbCalls).toEqual(["app_db"]);
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

  it("still closes the client when the command call rejects (command-phase timeout surfaces as a rejection)", async () => {
    const timeoutError = new Error("operation exceeded time limit");
    timeoutError.name = "MongoServerError";
    behavior.commandError = timeoutError;
    await expect(
      new MongoAdapter().execute(opts({ timeoutMs: 50 }), { count: "c" }),
    ).rejects.toThrow("operation exceeded time limit");
    expect(closeCallCount).toBe(1);
  });
});

describe("MongoAdapter command-phase bound (mongodb 7.8+ ignores timeoutMS)", () => {
  it("sends a copy of the command document carrying the budget as maxTimeMS, the caller's object untouched", async () => {
    const document = { count: "c" };
    await new MongoAdapter().execute(opts({ timeoutMs: 777 }), document);
    const sent = commandCalls[0]?.command as Record<string, unknown>;
    expect(sent).toEqual({ count: "c", maxTimeMS: 777 });
    expect(Object.keys(sent)[0]).toBe("count");
    expect(sent).not.toBe(document);
    expect(document).toEqual({ count: "c" });
  });

  it("replaces a caller's maxTimeMS at or above the budget, zero, negative or not an integer with the budget", async () => {
    for (const own of [777, 5000, 0, -1, 1.5, "100"]) {
      commandCalls.length = 0;
      await new MongoAdapter().execute(opts({ timeoutMs: 777 }), { count: "c", maxTimeMS: own });
      expect(commandCalls[0]?.command).toEqual({ count: "c", maxTimeMS: 777 });
    }
  });

  it("keeps a caller's own maxTimeMS below the budget, on a copy", async () => {
    const document = { count: "c", maxTimeMS: 100 };
    await new MongoAdapter().execute(opts({ timeoutMs: 777 }), document);
    expect(commandCalls[0]?.command).toEqual({ count: "c", maxTimeMS: 100 });
    expect(commandCalls[0]?.command).not.toBe(document);
  });

  it("no longer passes the deprecated timeoutMS to db.command()", async () => {
    await new MongoAdapter().execute(opts({ timeoutMs: 777 }), { count: "c" });
    expect(commandCalls[0]?.options).not.toHaveProperty("timeoutMS");
  });

  it("a command that never settles ends at the budget: aborted with a network-class reason, the client closed", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.commandHangs = true;
    const issued = nextCommand();
    let outcome: unknown = "pending";
    void new MongoAdapter().execute(opts({ timeoutMs: 1500 }), { find: "c" }).then(
      () => {
        outcome = "resolved";
      },
      (err: unknown) => {
        outcome = err;
      },
    );
    await issued;
    await vi.advanceTimersByTimeAsync(1499);
    await flushed();
    expect(outcome).toBe("pending");
    expect(closeCallCount).toBe(0);
    await vi.advanceTimersByTimeAsync(1);
    await flushed();
    expect(outcome).toBeInstanceOf(MongoNetworkError);
    expect((outcome as Error).message).toBe("command did not complete within 1500 ms");
    const signal = commandCalls[0]?.options?.signal;
    expect(signal?.aborted).toBe(true);
    expect(signal?.reason).toBe(outcome);
    expect(closeCallCount).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a command that never settles even after the abort still ends at the budget, the client closed once", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.commandSettlesWith = new Promise(() => undefined);
    const issued = nextCommand();
    let outcome: unknown = "pending";
    void new MongoAdapter().execute(opts({ timeoutMs: 1500 }), { find: "c" }).then(
      () => {
        outcome = "resolved";
      },
      (err: unknown) => {
        outcome = err;
      },
    );
    await issued;
    await vi.advanceTimersByTimeAsync(1499);
    await flushed();
    expect(outcome).toBe("pending");
    await vi.advanceTimersByTimeAsync(1);
    await flushed();
    expect(outcome).toBeInstanceOf(MongoNetworkError);
    expect((outcome as Error).message).toBe("command did not complete within 1500 ms");
    expect(closeCallCount).toBe(1);
  });

  it("a throwing abort-reason constructor fails the one call before any deadline is armed, the client closed", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.reasonConstructorThrows = true;
    await expect(
      new MongoAdapter().execute(opts({ timeoutMs: 1500 }), { ping: 1 }),
    ).rejects.toThrow("driver constructor changed");
    expect(commandCalls).toHaveLength(0);
    expect(vi.getTimerCount()).toBe(0);
    expect(closeCallCount).toBe(1);
  });

  it("the abort reason is the driver's own network error class, not its timeout subclass (the real module)", async () => {
    const real = await vi.importActual<typeof import("mongodb")>("mongodb");
    const reason = new real.MongoNetworkError("command did not complete within 1500 ms");
    expect(reason).toBeInstanceOf(real.MongoError);
    expect(reason).toBeInstanceOf(real.MongoNetworkError);
    expect(reason instanceof real.MongoNetworkTimeoutError).toBe(false);
    expect(reason.name).toBe("MongoNetworkError");
    expect(reason.message).toBe("command did not complete within 1500 ms");
  });

  it("arms one deadline while the command runs and leaves none behind when it settles in time", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    let settle: (value: unknown) => void = () => undefined;
    behavior.commandSettlesWith = new Promise((resolve) => {
      settle = resolve;
    });
    const issued = nextCommand();
    const run = new MongoAdapter().execute(opts({ timeoutMs: 1500 }), { ping: 1 });
    await issued;
    expect(vi.getTimerCount()).toBe(1);
    settle({ ok: 1 });
    await run;
    expect(vi.getTimerCount()).toBe(0);
    expect(closeCallCount).toBe(1);
  });
});

describe("MongoAdapter one budget from client construction to the command's end, the close raced against the grace", () => {
  let unhandled = 0;
  const countUnhandled = (): void => {
    unhandled += 1;
  };

  beforeEach(() => {
    unhandled = 0;
  });

  afterEach(() => {
    process.off("unhandledRejection", countUnhandled);
  });

  it("a connect that never settles ends at the budget with the network-class reason, no command issued, the client closed once, no unhandled rejection", async () => {
    process.on("unhandledRejection", countUnhandled);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.connectHangs = true;
    const connecting = nextConnect();
    let outcome: unknown = "pending";
    void new MongoAdapter().execute(opts({ timeoutMs: 1500 }), { find: "c" }).then(
      () => {
        outcome = "resolved";
      },
      (err: unknown) => {
        outcome = err;
      },
    );
    await connecting;
    await vi.advanceTimersByTimeAsync(1499);
    await flushed();
    expect(outcome).toBe("pending");
    await vi.advanceTimersByTimeAsync(1);
    await flushed();
    expect(unhandled).toBe(0);
    expect(outcome).toBeInstanceOf(MongoNetworkError);
    expect((outcome as Error).message).toBe("command did not complete within 1500 ms");
    expect(commandCalls).toHaveLength(0);
    expect(closeCallCount).toBe(1);
  });

  it("a connect that settles after the deadline issues no command", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.connectHangs = true;
    const connecting = nextConnect();
    void new MongoAdapter()
      .execute(opts({ timeoutMs: 1500 }), { find: "c" })
      .catch(() => undefined);
    await connecting;
    await vi.advanceTimersByTimeAsync(1500);
    await flushed();
    releaseConnect();
    await flushed();
    expect(commandCalls).toHaveLength(0);
  });

  it("a close that never settles after an answered command returns the result at the grace, no unhandled rejection", async () => {
    process.on("unhandledRejection", countUnhandled);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.closeHangs = true;
    behavior.commandResult = { n: 42, ok: 1 };
    const issued = nextCommand();
    let outcome: unknown = "pending";
    void new MongoAdapter().execute(opts({ timeoutMs: 1500 }), { count: "c" }).then(
      (result) => {
        outcome = result;
      },
      (err: unknown) => {
        outcome = err;
      },
    );
    await issued;
    await flushed();
    await vi.advanceTimersByTimeAsync(999);
    await flushed();
    expect(outcome).toBe("pending");
    expect(closeCallCount).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    await flushed();
    expect(unhandled).toBe(0);
    expect(outcome).toEqual({
      rows: [{ n: 42, ok: 1 }],
      fields: [{ name: "result" }],
      rowCount: 1,
    });
  });

  it("a close that never settles after the deadline ends the call at budget + grace with the deadline's reason, no unhandled rejection", async () => {
    process.on("unhandledRejection", countUnhandled);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.commandHangs = true;
    behavior.closeHangs = true;
    const issued = nextCommand();
    let outcome: unknown = "pending";
    void new MongoAdapter().execute(opts({ timeoutMs: 1500 }), { find: "c" }).then(
      () => {
        outcome = "resolved";
      },
      (err: unknown) => {
        outcome = err;
      },
    );
    await issued;
    await vi.advanceTimersByTimeAsync(1500);
    await flushed();
    expect(outcome).toBe("pending");
    expect(closeCallCount).toBe(1);
    await vi.advanceTimersByTimeAsync(999);
    await flushed();
    expect(outcome).toBe("pending");
    await vi.advanceTimersByTimeAsync(1);
    await flushed();
    expect(unhandled).toBe(0);
    expect(outcome).toBeInstanceOf(MongoNetworkError);
    expect((outcome as Error).message).toBe("command did not complete within 1500 ms");
  });

  it("a close that settles in time leaves no grace timer", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    await new MongoAdapter().execute(opts({ timeoutMs: 1500 }), { ping: 1 });
    expect(closeCallCount).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a close that throws synchronously after an answered command returns the result and leaves no timer", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.closeThrows = true;
    behavior.commandResult = { n: 42, ok: 1 };
    const outcome = await new MongoAdapter()
      .execute(opts({ timeoutMs: 1500 }), { count: "c" })
      .then(
        (result) => result,
        (err: unknown) => err,
      );
    expect(outcome).toEqual({
      rows: [{ n: 42, ok: 1 }],
      fields: [{ name: "result" }],
      rowCount: 1,
    });
    expect(closeCallCount).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("MongoAdapter command execution + result normalization (spec §10.7)", () => {
  it("runs the command document via db.command() on the named database", async () => {
    await new MongoAdapter().execute(opts({ database: "app_db" }), { ping: 1 });
    expect(dbCalls).toEqual(["app_db"]);
    expect(commandCalls[0]?.command).toEqual({ ping: 1, maxTimeMS: 1000 });
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

  it("propagates a connect failure without ever calling db()/command(), the client closed once", async () => {
    behavior.connectError = new Error("ECONNREFUSED");
    await expect(new MongoAdapter().execute(opts(), { ping: 1 })).rejects.toThrow("ECONNREFUSED");
    expect(dbCalls).toHaveLength(0);
    expect(commandCalls).toHaveLength(0);
    expect(closeCallCount).toBe(1);
  });

  it("a close failure does not mask the original command error", async () => {
    behavior.commandError = new Error("boom");
    behavior.closeError = new Error("close failed");
    await expect(new MongoAdapter().execute(opts(), { ping: 1 })).rejects.toThrow("boom");
  });
});
