import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { DbConnectOptions } from "./db-adapters.js";
import { RedisAdapter } from "./redis-adapter.js";

// node-redis's TLS socket options are spread straight into `tls.connect()`
// (verified against @redis/client@6.2.1's compiled socket.js — no field
// remapping happens in between), so a fake `createClient` that just records
// the option object it was called with is enough to assert on the exact
// wire shape without a live server.
interface FakeClientBehavior {
  sendCommandResult?: unknown;
  sendCommandError?: Error;
  sendCommandHangs?: boolean;
  connectError?: Error;
  connectHangs?: boolean;
  connectTimeoutError?: Error;
}

interface FakeClient {
  on: Mock;
  connect: Mock;
  sendCommand: Mock;
  close: Mock;
  destroy: Mock;
}

const createClientCalls: unknown[] = [];
let behavior: FakeClientBehavior = {};
let lastClient: FakeClient | undefined;
let connectIssued: () => void = () => undefined;
let commandIssued: () => void = () => undefined;

vi.mock("redis", () => ({
  createClient: vi.fn((cfg: unknown) => {
    createClientCalls.push(cfg);
    let pending = false;
    const client: FakeClient = {
      on: vi.fn(() => client),
      connect: vi.fn(() => {
        connectIssued();
        if (behavior.connectHangs) {
          pending = true;
          return new Promise(() => undefined);
        }
        const timedOut = behavior.connectTimeoutError;
        if (timedOut) {
          return new Promise((_resolve, reject) => {
            setTimeout(
              () => {
                reject(timedOut);
              },
              (cfg as RedisClientConfig).socket.connectTimeout,
            );
          });
        }
        return behavior.connectError
          ? Promise.reject(behavior.connectError)
          : Promise.resolve(client);
      }),
      sendCommand: vi.fn(() => {
        commandIssued();
        if (behavior.sendCommandHangs) {
          pending = true;
          return new Promise(() => undefined);
        }
        return behavior.sendCommandError
          ? Promise.reject(behavior.sendCommandError)
          : Promise.resolve(behavior.sendCommandResult ?? "PONG");
      }),
      close: vi.fn(() => (pending ? new Promise(() => undefined) : Promise.resolve(undefined))),
      destroy: vi.fn(),
    };
    lastClient = client;
    return client;
  }),
}));

interface SocketConfig {
  host: string;
  port: number;
  tls: boolean;
  connectTimeout?: number;
  socketTimeout?: number;
  reconnectStrategy?: false | number;
  rejectUnauthorized?: boolean;
  ca?: string;
  servername?: string;
  checkServerIdentity?: (host: string, cert: unknown) => Error | undefined;
}

interface RedisClientConfig {
  socket: SocketConfig;
  username: string;
  password: string;
  database?: number;
}

function opts(overrides: Partial<DbConnectOptions> = {}): DbConnectOptions {
  return {
    host: "redis.example.com",
    port: 6379,
    address: "203.0.113.9",
    user: "default",
    password: "s3cr3t",
    database: "0",
    tls: {},
    timeoutMs: 1000,
    ...overrides,
  };
}

function flushed(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

function nextConnect(): Promise<void> {
  return new Promise((resolve) => {
    connectIssued = resolve;
  });
}

function nextCommand(): Promise<void> {
  return new Promise((resolve) => {
    commandIssued = resolve;
  });
}

beforeEach(() => {
  createClientCalls.length = 0;
  behavior = {};
  lastClient = undefined;
  connectIssued = () => undefined;
  commandIssued = () => undefined;
});

afterEach(() => {
  vi.useRealTimers();
});

describe("RedisAdapter connection config (SSRF pinning + TLS identity, spec §10.2)", () => {
  it("dials the pinned address while binding TLS identity to the logical host", async () => {
    await new RedisAdapter().execute(opts(), ["PING"]);
    const cfg = createClientCalls[0] as RedisClientConfig;
    expect(cfg.socket.host).toBe("203.0.113.9");
    expect(cfg.socket.port).toBe(6379);
    expect(cfg.socket.tls).toBe(true);
    expect(cfg.socket.rejectUnauthorized).toBe(true);
    expect(cfg.socket.servername).toBe("redis.example.com");
    expect(typeof cfg.socket.checkServerIdentity).toBe("function");
    expect(cfg.socket.connectTimeout).toBe(1000);
    expect(cfg.socket.socketTimeout).toBe(1000);
  });

  // timeoutMs is documented (constants.ts) as a connect+query budget. One
  // deadline bounds the whole use (the deadline rows below); connectTimeout,
  // the dial's bound, and socketTimeout, the idle bound, stay at the same
  // budget beside it.
  it("keeps connectTimeout, the dial's bound, and socketTimeout, the idle bound, at the budget beside the deadline", async () => {
    await new RedisAdapter().execute(opts({ timeoutMs: 4242 }), ["BLPOP", "key", "0"]);
    const cfg = createClientCalls[0] as RedisClientConfig;
    expect(cfg.socket.connectTimeout).toBe(4242);
    expect(cfg.socket.socketTimeout).toBe(4242);
  });

  it("omits servername for an IP-literal target (SNI forbids an IP servername)", async () => {
    await new RedisAdapter().execute(opts({ host: "8.8.8.8", address: "8.8.8.8" }), ["PING"]);
    const cfg = createClientCalls[0] as RedisClientConfig;
    expect(cfg.socket.host).toBe("8.8.8.8");
    expect(cfg.socket.tls).toBe(true);
    expect(cfg.socket).not.toHaveProperty("servername");
    // The identity check is still bound explicitly, so verification is not
    // silently skipped just because SNI cannot carry the name.
    expect(typeof cfg.socket.checkServerIdentity).toBe("function");
  });

  it("the identity check is bound to the logical host, not Node's own derivation", async () => {
    await new RedisAdapter().execute(opts(), ["PING"]);
    const cfg = createClientCalls[0] as RedisClientConfig;
    const check = cfg.socket.checkServerIdentity as (
      h: string,
      c: { subject: { CN: string }; subjectaltname: string },
    ) => Error | undefined;

    const foreign = { subject: { CN: "localhost" }, subjectaltname: "DNS:localhost" };
    expect(check("localhost", foreign)).toBeInstanceOf(Error);

    const matching = {
      subject: { CN: "redis.example.com" },
      subjectaltname: "DNS:redis.example.com",
    };
    expect(check("localhost", matching)).toBeUndefined();
  });

  it("requires TLS by default (opts.tls is an object)", async () => {
    await new RedisAdapter().execute(opts(), ["PING"]);
    const cfg = createClientCalls[0] as RedisClientConfig;
    expect(cfg.socket.tls).toBe(true);
    expect(cfg.socket.rejectUnauthorized).toBe(true);
  });

  it("still dials the pinned address with TLS disabled via the audited opt-out", async () => {
    await new RedisAdapter().execute(opts({ tls: false }), ["PING"]);
    const cfg = createClientCalls[0] as RedisClientConfig;
    expect(cfg.socket.host).toBe("203.0.113.9");
    expect(cfg.socket.tls).toBe(false);
    expect(cfg.socket).not.toHaveProperty("rejectUnauthorized");
    expect(cfg.socket).not.toHaveProperty("checkServerIdentity");
    expect(cfg.socket.connectTimeout).toBe(1000);
    expect(cfg.socket.socketTimeout).toBe(1000);
  });

  it("forwards a pinned CA alongside certificate verification", async () => {
    await new RedisAdapter().execute(opts({ tls: { ca: "CA-PEM" } }), ["PING"]);
    const cfg = createClientCalls[0] as RedisClientConfig;
    expect(cfg.socket.ca).toBe("CA-PEM");
  });

  it("forwards username/password from the split credential", async () => {
    await new RedisAdapter().execute(opts({ user: "default", password: "hunter2" }), ["PING"]);
    const cfg = createClientCalls[0] as RedisClientConfig;
    expect(cfg.username).toBe("default");
    expect(cfg.password).toBe("hunter2");
  });

  it("selects the numeric database index when opts.database parses as one", async () => {
    await new RedisAdapter().execute(opts({ database: "3" }), ["PING"]);
    const cfg = createClientCalls[0] as RedisClientConfig;
    expect(cfg.database).toBe(3);
  });

  // U3-k (fixed after U3's close): the adapter runs one command on a throwaway
  // client. node-redis's default strategy reconnects forever after a dropped
  // socket, and it emits `error` on the client for every socket failure — an
  // emitter with no listener throws that inside the socket's own event
  // handler, an uncaught exception (`redis-adapter.socket-drop.test.ts` runs
  // the real driver against a dropping listener).
  it("never reconnects: both socket shapes carry reconnectStrategy false", async () => {
    await new RedisAdapter().execute(opts(), ["PING"]);
    await new RedisAdapter().execute(opts({ tls: false }), ["PING"]);
    const shapes = createClientCalls as RedisClientConfig[];
    expect(shapes).toHaveLength(2);
    expect(shapes.map((cfg) => cfg.socket.reconnectStrategy)).toEqual([false, false]);
  });

  it("listens for the client's error events before connecting", async () => {
    await new RedisAdapter().execute(opts(), ["PING"]);
    expect(lastClient?.on).toHaveBeenCalledWith("error", expect.any(Function));
    const [listened] = lastClient?.on.mock.invocationCallOrder ?? [];
    const [connected] = lastClient?.connect.mock.invocationCallOrder ?? [];
    expect(listened).toBeLessThan(connected as number);
  });

  it("refuses a non-integer database index before loading the driver (belt-and-braces under the schema)", async () => {
    await expect(
      new RedisAdapter().execute(opts({ database: "app" }), ["PING"]),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_DATABASE_CONFIG });
    await expect(
      new RedisAdapter().execute(opts({ database: "-1" }), ["PING"]),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_DATABASE_CONFIG });
    expect(createClientCalls).toHaveLength(0);
  });

  it("a signal aborted while redis loads: VAULT_LOCKED, no client built", async () => {
    const controller = new AbortController();
    const suiteModule = await import("redis");
    vi.doMock("redis", () => {
      controller.abort();
      return suiteModule;
    });
    try {
      await expectVaultError(
        () => new RedisAdapter().execute(opts({ signal: controller.signal }), ["PING"]),
        ErrorCode.VAULT_LOCKED,
      );
      expect(createClientCalls.length).toBe(0);
    } finally {
      vi.doMock("redis", () => suiteModule);
    }
  });

  it("a live signal connects as before", async () => {
    await new RedisAdapter().execute(opts({ signal: new AbortController().signal }), ["PING"]);
    expect(createClientCalls.length).toBe(1);
    expect(lastClient?.sendCommand).toHaveBeenCalledWith(["PING"]);
  });
});

describe("RedisAdapter command execution", () => {
  it("sends the generic command array via sendCommand and normalizes the reply", async () => {
    behavior.sendCommandResult = "PONG";
    const res = await new RedisAdapter().execute(opts(), ["PING"]);
    expect(lastClient?.sendCommand).toHaveBeenCalledWith(["PING"]);
    expect(res).toEqual({
      rows: ["PONG"],
      fields: [{ name: "reply" }],
      rowCount: 1,
      command: undefined,
    });
  });

  it("normalizes a non-scalar reply the same way", async () => {
    behavior.sendCommandResult = ["a", "b", "c"];
    const res = await new RedisAdapter().execute(opts(), ["KEYS", "*"]);
    expect(res.rows).toEqual([["a", "b", "c"]]);
    expect(res.rowCount).toBe(1);
  });

  it("destroys the client after a successful command", async () => {
    await new RedisAdapter().execute(opts(), ["PING"]);
    expect(lastClient?.destroy).toHaveBeenCalledTimes(1);
  });

  it("destroys the client even when the command rejects, and propagates the error", async () => {
    behavior.sendCommandError = new Error("boom");
    await expect(new RedisAdapter().execute(opts(), ["PING"])).rejects.toThrow("boom");
    expect(lastClient?.destroy).toHaveBeenCalledTimes(1);
  });

  it("propagates a connect failure without ever calling sendCommand", async () => {
    behavior.connectError = new Error("ECONNREFUSED");
    await expect(new RedisAdapter().execute(opts(), ["PING"])).rejects.toThrow("ECONNREFUSED");
    expect(lastClient?.sendCommand).not.toHaveBeenCalled();
  });

  // A sendCommand rejection — here node-redis's SocketTimeoutError, raised
  // when an idle read outlives socketTimeout — propagates as it is (mapped to
  // DB_QUERY_FAILED by the injector) and the client is still destroyed; the
  // fake models the rejection directly since a fake socket cannot fire a
  // real timer.
  it("a socket-timeout rejection from sendCommand still destroys the client and propagates", async () => {
    const timeoutError = new Error("Socket timeout");
    timeoutError.name = "SocketTimeoutError";
    behavior.sendCommandError = timeoutError;
    await expect(
      new RedisAdapter().execute(opts({ timeoutMs: 50 }), ["BLPOP", "key", "0"]),
    ).rejects.toThrow("Socket timeout");
    expect(lastClient?.destroy).toHaveBeenCalledTimes(1);
  });
});

describe("RedisAdapter one deadline over the whole use, the client destroyed", () => {
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

  it("a connect that never settles ends at the budget with the deadline's text, no command sent, the client destroyed once, no unhandled rejection", async () => {
    process.on("unhandledRejection", countUnhandled);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.connectHangs = true;
    const connecting = nextConnect();
    let outcome: unknown = "pending";
    void new RedisAdapter().execute(opts({ timeoutMs: 1500 }), ["PING"]).then(
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
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toBe("command did not complete within 1500 ms");
    expect(lastClient?.sendCommand).not.toHaveBeenCalled();
    expect(lastClient?.destroy).toHaveBeenCalledTimes(1);
  });

  it("a command that never settles ends at the budget with the deadline's text, the client destroyed once", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.sendCommandHangs = true;
    const issued = nextCommand();
    let outcome: unknown = "pending";
    void new RedisAdapter().execute(opts({ timeoutMs: 1500 }), ["BLPOP", "key", "0"]).then(
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
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toBe("command did not complete within 1500 ms");
    expect(lastClient?.destroy).toHaveBeenCalledTimes(1);
  });

  it("the deadline leaves no timer behind when the command settles in time", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    await new RedisAdapter().execute(opts({ timeoutMs: 1500 }), ["PING"]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("every path destroys the client once and never closes it", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const paths: FakeClientBehavior[] = [
      {},
      { sendCommandError: new Error("boom") },
      { connectError: new Error("ECONNREFUSED") },
      { connectTimeoutError: new Error("Connection timeout") },
      { connectHangs: true },
      { sendCommandHangs: true },
    ];
    for (const path of paths) {
      behavior = path;
      const connecting = nextConnect();
      void new RedisAdapter().execute(opts({ timeoutMs: 1500 }), ["PING"]).catch(() => undefined);
      await connecting;
      await vi.advanceTimersByTimeAsync(1500);
      await flushed();
      expect(lastClient?.destroy).toHaveBeenCalledTimes(1);
      expect(lastClient?.close).not.toHaveBeenCalled();
    }
  });

  it("a connect the driver times out at its own connect timer keeps the driver's cause, not the deadline's text", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const cause = new Error("Connection timeout");
    behavior.connectTimeoutError = cause;
    const connecting = nextConnect();
    let outcome: unknown = "pending";
    void new RedisAdapter().execute(opts({ timeoutMs: 1500 }), ["PING"]).then(
      () => {
        outcome = "resolved";
      },
      (err: unknown) => {
        outcome = err;
      },
    );
    await connecting;
    await vi.advanceTimersByTimeAsync(1500);
    await flushed();
    expect(outcome).toBe(cause);
  });
});
