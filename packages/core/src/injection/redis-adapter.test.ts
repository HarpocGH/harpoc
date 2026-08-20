import { beforeEach, describe, expect, it, vi } from "vitest";
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
  connectError?: Error;
  closeError?: Error;
}

interface FakeClient {
  connect: ReturnType<typeof vi.fn>;
  sendCommand: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
}

const createClientCalls: unknown[] = [];
let behavior: FakeClientBehavior = {};
let lastClient: FakeClient | undefined;

vi.mock("redis", () => ({
  createClient: vi.fn((cfg: unknown) => {
    createClientCalls.push(cfg);
    const client: FakeClient = {
      connect: vi.fn(() =>
        behavior.connectError ? Promise.reject(behavior.connectError) : Promise.resolve(client),
      ),
      sendCommand: vi.fn(() =>
        behavior.sendCommandError
          ? Promise.reject(behavior.sendCommandError)
          : Promise.resolve(behavior.sendCommandResult ?? "PONG"),
      ),
      close: vi.fn(() =>
        behavior.closeError ? Promise.reject(behavior.closeError) : Promise.resolve(undefined),
      ),
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

beforeEach(() => {
  createClientCalls.length = 0;
  behavior = {};
  lastClient = undefined;
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

  // Review finding (Important): timeoutMs is documented (constants.ts) as a
  // connect+query budget, mirroring PostgresAdapter's statement_timeout and
  // MysqlAdapter's per-query timeout. Without socketTimeout, a blocking
  // command (BLPOP key 0, WAIT, XREAD BLOCK 0, SUBSCRIBE, DEBUG SLEEP — the
  // schema allows any string[] command, no denylist) hangs sendCommand
  // forever and the finally/close() is never reached: an agent-triggerable
  // hang of the vault process.
  it("bounds command execution with socketTimeout, not just the connect handshake", async () => {
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

  it("leaves the database index unset for a non-numeric value (defaults to DB 0)", async () => {
    await new RedisAdapter().execute(opts({ database: "app" }), ["PING"]);
    const cfg = createClientCalls[0] as RedisClientConfig;
    expect(cfg.database).toBeUndefined();
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

  it("closes the client after a successful command", async () => {
    await new RedisAdapter().execute(opts(), ["PING"]);
    expect(lastClient?.close).toHaveBeenCalledTimes(1);
  });

  it("closes the client even when the command rejects, and propagates the error", async () => {
    behavior.sendCommandError = new Error("boom");
    await expect(new RedisAdapter().execute(opts(), ["PING"])).rejects.toThrow("boom");
    expect(lastClient?.close).toHaveBeenCalledTimes(1);
  });

  it("propagates a connect failure without ever calling sendCommand", async () => {
    behavior.connectError = new Error("ECONNREFUSED");
    await expect(new RedisAdapter().execute(opts(), ["PING"])).rejects.toThrow("ECONNREFUSED");
    expect(lastClient?.sendCommand).not.toHaveBeenCalled();
  });

  it("a close failure does not mask the original command error", async () => {
    behavior.sendCommandError = new Error("boom");
    behavior.closeError = new Error("close failed");
    await expect(new RedisAdapter().execute(opts(), ["PING"])).rejects.toThrow("boom");
  });

  // socketTimeout firing mid-command (e.g. a blocking BLPOP that outlives
  // opts.timeoutMs) surfaces to node-redis callers as a sendCommand
  // rejection, not a hang — the fake models that contract directly since a
  // fake socket cannot fire a real timer. What matters is that execute()
  // rejects (mapped to DB_QUERY_FAILED by the injector) and close() still
  // runs, rather than sendCommand's promise staying pending forever.
  it("a socket-timeout rejection from sendCommand still closes the client and propagates", async () => {
    const timeoutError = new Error("Socket timeout");
    timeoutError.name = "SocketTimeoutError";
    behavior.sendCommandError = timeoutError;
    await expect(
      new RedisAdapter().execute(opts({ timeoutMs: 50 }), ["BLPOP", "key", "0"]),
    ).rejects.toThrow("Socket timeout");
    expect(lastClient?.close).toHaveBeenCalledTimes(1);
  });
});
