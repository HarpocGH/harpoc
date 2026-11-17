import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { DatabaseInjector } from "./database-injector.js";
import type { DbConnectOptions, DbConnection, DbEngineAdapter } from "./db-adapters.js";
import { DB_CLOSE_GRACE_MS, defaultDbAdapters } from "./db-adapters.js";
import { SECRET, action, policy } from "./__fixtures__/database-injector-doubles.js";

interface FakeBehavior {
  queryError?: Error;
  endHangs?: boolean;
  endAfterMs?: number;
  endRejects?: boolean;
  endThrows?: boolean;
  destroyThrows?: boolean;
}

let behavior: FakeBehavior = {};
let connections = 0;
let queryIssued: () => void = () => undefined;

const socketDestroy: Mock<() => void> = vi.fn().mockName("socket destroy");
const driverDestroy: Mock<() => void> = vi
  .fn(() => {
    if (behavior.destroyThrows) throw new Error("destroy threw");
  })
  .mockName("driver destroy");
const driverEnd: Mock<() => Promise<void>> = vi
  .fn(() => {
    if (behavior.endThrows) throw new Error("end threw");
    if (behavior.endRejects) return Promise.reject(new Error("end failed"));
    if (behavior.endHangs) return new Promise<void>(() => undefined);
    const delay = behavior.endAfterMs;
    if (delay === undefined) return Promise.resolve();
    return new Promise<void>((resolve) => {
      setTimeout(resolve, delay);
    });
  })
  .mockName("driver end");
const driverQuery: Mock<(options: unknown, params?: unknown[]) => Promise<unknown>> = vi
  .fn(() => {
    queryIssued();
    if (behavior.queryError) return Promise.reject(behavior.queryError);
    return Promise.resolve([[{ one: 1 }], [{ name: "one" }]]);
  })
  .mockName("driver query");

vi.mock("node:net", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:net")>()),
  createConnection: () => ({ setNoDelay: () => undefined, destroy: socketDestroy }),
}));

vi.mock("mysql2/promise", () => ({
  createConnection: (config: { stream: () => unknown }) => {
    connections += 1;
    config.stream();
    return Promise.resolve({ query: driverQuery, end: driverEnd, destroy: driverDestroy });
  },
}));

function flushed(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

function nextQuery(): Promise<void> {
  return new Promise((resolve) => {
    queryIssued = resolve;
  });
}

function timedOut(): Error {
  return Object.assign(new Error("Query inactivity timeout"), {
    code: "PROTOCOL_SEQUENCE_TIMEOUT",
    errorno: "PROTOCOL_SEQUENCE_TIMEOUT",
    syscall: "query",
  });
}

function serverError(): Error {
  return Object.assign(new Error("Table 'app.missing' doesn't exist"), {
    code: "ER_NO_SUCH_TABLE",
    errno: 1146,
    sqlState: "42S02",
  });
}

function opts(): DbConnectOptions {
  return {
    host: "db.example.com",
    port: 3306,
    address: "203.0.113.7",
    user: "app",
    password: "pw-fixture",
    database: "app",
    tls: {},
    timeoutMs: 1500,
  };
}

function mysqlConnect(): Promise<DbConnection> {
  return (defaultDbAdapters().mysql as DbEngineAdapter).connect(opts());
}

beforeEach(() => {
  behavior = {};
  connections = 0;
  queryIssued = () => undefined;
  socketDestroy.mockClear();
  driverDestroy.mockClear();
  driverEnd.mockClear();
  driverQuery.mockClear();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("MysqlAdapter end() after an interrupted query: the dialled socket cut, the driver's end raced against the grace", () => {
  it("a timed-out query rejects with mysql2's error, then end() destroys the connection and its dialled socket at once: no driver end, no other query, one connection, no timer", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const error = timedOut();
    behavior.queryError = error;
    behavior.endHangs = true;
    const conn = await mysqlConnect();
    const queried = await conn.query("SELECT SLEEP(10)").then(
      () => "resolved",
      (err: unknown) => err,
    );
    expect(queried).toBe(error);
    let ended = false;
    void conn.end().then(() => {
      ended = true;
    });
    await flushed();
    expect(driverEnd).not.toHaveBeenCalled();
    expect(ended).toBe(true);
    expect(driverDestroy).toHaveBeenCalledTimes(1);
    expect(socketDestroy).toHaveBeenCalledTimes(1);
    expect(driverQuery).toHaveBeenCalledTimes(1);
    expect(connections).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("an end() that never settles is cut at the grace: the connection and its dialled socket destroyed", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.endHangs = true;
    const conn = await mysqlConnect();
    await conn.query("SELECT 1");
    let ended = false;
    void conn.end().then(() => {
      ended = true;
    });
    await flushed();
    await vi.advanceTimersByTimeAsync(DB_CLOSE_GRACE_MS - 1);
    await flushed();
    expect(ended).toBe(false);
    expect(driverDestroy).not.toHaveBeenCalled();
    expect(socketDestroy).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await flushed();
    expect(ended).toBe(true);
    expect(driverEnd).toHaveBeenCalledTimes(1);
    expect(driverDestroy).toHaveBeenCalledTimes(1);
    expect(socketDestroy).toHaveBeenCalledTimes(1);
  });

  it("an end() that settles within the grace destroys nothing and leaves no timer", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.endAfterMs = DB_CLOSE_GRACE_MS - 1;
    const conn = await mysqlConnect();
    await conn.query("SELECT 1");
    let ended = false;
    void conn.end().then(() => {
      ended = true;
    });
    await flushed();
    await vi.advanceTimersByTimeAsync(DB_CLOSE_GRACE_MS - 1);
    await flushed();
    expect(ended).toBe(true);
    expect(driverEnd).toHaveBeenCalledTimes(1);
    expect(driverDestroy).not.toHaveBeenCalled();
    expect(socketDestroy).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a query that failed with a server error rejects with the driver's error and ends with the driver's end(), nothing destroyed", async () => {
    const error = serverError();
    behavior.queryError = error;
    const conn = await mysqlConnect();
    const queried = await conn.query("SELECT * FROM missing").then(
      () => "resolved",
      (err: unknown) => err,
    );
    expect(queried).toBe(error);
    await conn.end();
    expect(driverEnd).toHaveBeenCalledTimes(1);
    expect(driverDestroy).not.toHaveBeenCalled();
    expect(socketDestroy).not.toHaveBeenCalled();
  });

  it("a successful query returns its rows and ends with the driver's end() alone: nothing destroyed, one connection", async () => {
    const conn = await mysqlConnect();
    await expect(conn.query("SELECT 1 AS one")).resolves.toEqual({
      rows: [{ one: 1 }],
      fields: [{ name: "one" }],
      rowCount: 1,
    });
    await conn.end();
    expect(driverEnd).toHaveBeenCalledTimes(1);
    expect(driverDestroy).not.toHaveBeenCalled();
    expect(socketDestroy).not.toHaveBeenCalled();
    expect(connections).toBe(1);
  });

  it("an end() that rejects resolves the adapter's end(), destroys nothing and leaves no timer", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.endRejects = true;
    const conn = await mysqlConnect();
    await conn.query("SELECT 1");
    const ended = await conn.end().then(
      () => "resolved",
      (err: unknown) => err,
    );
    expect(ended).toBe("resolved");
    expect(driverEnd).toHaveBeenCalledTimes(1);
    expect(driverDestroy).not.toHaveBeenCalled();
    expect(socketDestroy).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("an end() that throws synchronously resolves the adapter's end(), destroys nothing and leaves no timer", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.endThrows = true;
    const conn = await mysqlConnect();
    await conn.query("SELECT 1");
    const ended = await conn.end().then(
      () => "resolved",
      (err: unknown) => err,
    );
    expect(ended).toBe("resolved");
    expect(driverEnd).toHaveBeenCalledTimes(1);
    expect(driverDestroy).not.toHaveBeenCalled();
    expect(socketDestroy).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a timed-out use fails DB_QUERY_FAILED with mysql2's text and one failed row at once, without the driver's end, its dialled socket destroyed though the connection's destroy throws", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behavior.queryError = timedOut();
    behavior.endHangs = true;
    behavior.destroyThrows = true;
    const log = vi.fn();
    const injector = new DatabaseInjector({ log } as unknown as AuditLogger);
    const issued = nextQuery();
    let settled = false;
    const run = injector.executeWithSecret(
      action({ engine: "mysql", query: "SELECT SLEEP(10)", timeout_ms: 1500 }),
      SECRET,
      policy(),
      undefined,
    );
    void run.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await issued;
    await flushed();
    expect(settled).toBe(true);
    const err = await expectVaultError(() => run, ErrorCode.DB_QUERY_FAILED);
    expect(err.message).toBe("Database query failed: Query inactivity timeout");
    expect(socketDestroy).toHaveBeenCalledTimes(1);
    expect(driverDestroy).toHaveBeenCalledTimes(1);
    expect(driverEnd).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledTimes(1);
    const row = log.mock.calls[0]?.[0] as AuditLogOptions;
    expect(row.success).toBe(false);
    expect(row.detail).toEqual({
      context: "database",
      engine: "mysql",
      database: "app",
      host: "8.8.8.8",
      port: 3306,
      error: "DB_QUERY_FAILED",
    });
  });
});
