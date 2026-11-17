import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, DatabaseAction } from "@harpoc/shared";
import { DEFAULT_DB_TIMEOUT_MS, ErrorCode } from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { DatabaseInjector } from "./database-injector.js";
import {
  MockAdapter,
  MockCommandAdapter,
  SECRET,
  action,
  injectorWithRedis,
  policy,
  redisAction,
} from "./__fixtures__/database-injector-doubles.js";
import { validateHostPort } from "./url-validator.js";

vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return { ...actual, validateHostPort: vi.fn(actual.validateHostPort) };
});

// Lazy-driver pin (mirrors the pg mock in database-injector.tls.test.ts):
// running a non-redis action through the REAL default adapters must never
// load the redis driver — `defaultDbCommandAdapters()` only constructs a
// `RedisAdapter`, it does not import "redis" until `execute()` runs.
const redisCreateClientCalls: unknown[] = [];
vi.mock("redis", () => ({
  createClient: vi.fn((cfg: unknown) => {
    redisCreateClientCalls.push(cfg);
    throw new Error("redis driver must not load for a non-redis action");
  }),
}));

// v1.3 T11: a functional (not throwing) mongodb fake — used both for the
// lazy-load pin (asserting it is NEVER constructed for a non-mongodb action)
// and for a real end-to-end dispatch test proving `defaultDbCommandAdapters()`
// now routes engine `mongodb` through the wired `MongoAdapter`, not just a
// hand-registered mock adapter.
const mongoClientCalls: unknown[] = [];
const mongoCommandCalls: { name: string; command: unknown; options: unknown }[] = [];
let mongoCommandHangs = false;
let mongoCommandNeverSettles = false;
let mongoCloseCount = 0;
let mongoCommandIssued: () => void = () => undefined;
vi.mock("mongodb", () => {
  class MongoNetworkError extends Error {
    constructor(message: string) {
      super(message);
      this.name = "MongoNetworkError";
    }
  }
  class MongoClient {
    constructor(uri: string, options: unknown) {
      mongoClientCalls.push({ uri, options });
    }
    connect(): Promise<this> {
      return Promise.resolve(this);
    }
    close(): Promise<void> {
      mongoCloseCount += 1;
      return Promise.resolve(undefined);
    }
    db(name: string): {
      command: (command: unknown, options?: { signal?: AbortSignal }) => Promise<unknown>;
    } {
      return {
        command: (command: unknown, options?: { signal?: AbortSignal }) => {
          mongoCommandCalls.push({ name, command, options });
          mongoCommandIssued();
          if (mongoCommandNeverSettles) return new Promise(() => undefined);
          if (mongoCommandHangs) {
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
          return Promise.resolve({ ok: 1 });
        },
      };
    }
  }
  return { MongoClient, MongoNetworkError };
});

beforeEach(() => {
  mongoClientCalls.length = 0;
  mongoCommandCalls.length = 0;
  mongoCommandHangs = false;
  mongoCommandNeverSettles = false;
  mongoCloseCount = 0;
  mongoCommandIssued = () => undefined;
});

afterEach(() => {
  vi.useRealTimers();
});

const pgClientConfigsForLazyPin: unknown[] = [];
const DB_PASSWORD = "s3cr3t";
vi.mock("pg", () => ({
  default: {
    Client: class {
      constructor(cfg: unknown) {
        pgClientConfigsForLazyPin.push(cfg);
      }
      connect(): Promise<void> {
        return Promise.resolve();
      }
      query(): Promise<{
        rows: unknown[];
        fields: { name: string }[];
        rowCount: number;
        command: string;
      }> {
        return Promise.resolve({
          rows: [{ ok: 1 }],
          fields: [{ name: "ok" }],
          rowCount: 1,
          command: "SELECT",
        });
      }
      end(): Promise<void> {
        return Promise.resolve();
      }
    },
  },
}));

// v1.3 T10: redis dispatch routes engine `redis` through the DbCommandAdapter
// seam (`action.command`) rather than the SQL adapter's connect().query()
// path — this REPLACES Task 1's interim shim (which threw INVALID_DATABASE_CONFIG
// for every engine, since no engine could carry a schema-valid `command` yet).
describe("DatabaseInjector redis dispatch", () => {
  it("routes engine redis to the command adapter with the action's command array, never touching the SQL adapters", async () => {
    const sqlMock = new MockAdapter({ rows: [] });
    const cmd = new MockCommandAdapter();
    const res = await injectorWithRedis(cmd, sqlMock).executeWithSecret(
      redisAction(),
      SECRET,
      policy(),
      undefined,
    );
    expect(res.type).toBe("database");
    expect(cmd.lastExecute?.command).toEqual(["GET", "foo"]);
    expect(sqlMock.lastConnect).toBeUndefined();
    expect(sqlMock.lastQuery).toBeUndefined();
  });

  it("parses username:password the same way as the SQL path", async () => {
    const cmd = new MockCommandAdapter();
    await injectorWithRedis(cmd).executeWithSecret(redisAction(), SECRET, policy(), undefined);
    expect(cmd.lastExecute?.opts.user).toBe("admin");
    expect(cmd.lastExecute?.opts.password).toBe("s3cr3t");
  });

  it("normalizes a redis command result to rows/fields/rowCount", async () => {
    const cmd = new MockCommandAdapter({
      result: { rows: ["PONG"], fields: [{ name: "reply" }], rowCount: 1, command: undefined },
    });
    const res = await injectorWithRedis(cmd).executeWithSecret(
      redisAction({ command: ["PING"] }),
      SECRET,
      policy(),
      undefined,
    );
    expect(res.rows).toEqual(["PONG"]);
    expect(res.fields).toEqual([{ name: "reply" }]);
    expect(res.row_count).toBe(1);
    expect(res.command).toBeUndefined();
  });

  it("requires TLS by default for a redis action too, disabled only via the opt-out", async () => {
    const cmd1 = new MockCommandAdapter();
    await injectorWithRedis(cmd1).executeWithSecret(redisAction(), SECRET, policy(), undefined);
    expect(cmd1.lastExecute?.opts.tls).not.toBe(false);

    const cmd2 = new MockCommandAdapter();
    const config: ConnectionConfig = { database: { tls_mode: "disable" } };
    await injectorWithRedis(cmd2).executeWithSecret(redisAction(), SECRET, policy(), config);
    expect(cmd2.lastExecute?.opts.tls).toBe(false);
  });

  it("passes the SSRF-pinned address through to the command adapter", async () => {
    const cmd = new MockCommandAdapter();
    await injectorWithRedis(cmd).executeWithSecret(
      redisAction({ host: "8.8.8.8" }),
      SECRET,
      policy(),
      undefined,
    );
    expect(cmd.lastExecute?.opts.host).toBe("8.8.8.8");
    expect(cmd.lastExecute?.opts.address).toBe("8.8.8.8");
  });

  it("rejects a host:port outside the allowlist before invoking the command adapter", async () => {
    const cmd = new MockCommandAdapter();
    await expect(
      injectorWithRedis(cmd).executeWithSecret(
        redisAction(),
        SECRET,
        policy({ host_allowlist: ["9.9.9.9"] }),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
    expect(cmd.lastExecute).toBeUndefined();
  });

  it("blocks SSRF to a private target before invoking the command adapter", async () => {
    const cmd = new MockCommandAdapter();
    await expect(
      injectorWithRedis(cmd).executeWithSecret(
        redisAction({ host: "10.0.0.1" }),
        SECRET,
        policy(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSRF_BLOCKED });
    expect(cmd.lastExecute).toBeUndefined();
  });

  it("redacts the credential from a redis command error and maps to DB_QUERY_FAILED", async () => {
    const cmd = new MockCommandAdapter({ error: new Error("WRONGPASS s3cr3t") });
    const err = await expectVaultError(
      () => injectorWithRedis(cmd).executeWithSecret(redisAction(), SECRET, policy(), undefined),
      ErrorCode.DB_QUERY_FAILED,
    );
    expectAbsent(err.message, DB_PASSWORD);
  });

  it("rejects an engine with no command adapter configured on this injector instance", async () => {
    const cmd = new MockCommandAdapter();
    const inj = new DatabaseInjector(null, {}, { redis: cmd });
    await expect(
      inj.executeWithSecret(redisAction({ engine: "mongodb" }), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.UNSUPPORTED_DB_ENGINE });
  });
});

const NON_ARRAY_REDIS_COMMANDS: ReadonlyArray<readonly [string, unknown]> = [
  ["null", null],
  ["undefined", undefined],
  ["a string", "PING"],
  ["an array-like record", { 0: "SET", 1: "k", 2: "v", length: 3 }],
  ["an empty array", []],
  ["an array with a non-string entry", ["ECHO", 1]],
  ["an array with a hole", Object.assign(new Array<string>(3), { 0: "GET", 2: "k" })],
];

const NON_INDEX_REDIS_DATABASES: readonly string[] = ["app", "-1"];

const ACCEPTED_REDIS_DATABASES: readonly string[] = ["0", "15"];

const ACCEPTED_REDIS_COMMANDS: ReadonlyArray<readonly [string, string[]]> = [
  ["one entry", ["PING"]],
  ["1000 entries", Array.from({ length: 1_000 }, () => "x")],
  ["one empty string", [""]],
];

describe("DatabaseInjector — an unparsed caller's redis action is judged before any lookup or client", () => {
  function auditedRedisInjector(): { inj: DatabaseInjector; cmd: MockCommandAdapter; log: Mock } {
    vi.mocked(validateHostPort).mockClear();
    const log = vi.fn();
    const cmd = new MockCommandAdapter();
    const inj = new DatabaseInjector({ log } as unknown as AuditLogger, {}, { redis: cmd });
    return { inj, cmd, log };
  }

  async function expectRefusedBeforeLookup(
    overrides: Partial<DatabaseAction>,
    message: string,
    detail: Record<string, unknown>,
  ): Promise<void> {
    const { inj, cmd, log } = auditedRedisInjector();
    const err = await expectVaultError(
      () => inj.executeWithSecret(redisAction(overrides), SECRET, policy(), undefined, "secret-1"),
      ErrorCode.INVALID_DATABASE_CONFIG,
    );
    expect(err.message === message).toBe(true);
    expect(vi.mocked(validateHostPort)).not.toHaveBeenCalled();
    expect(cmd.lastExecute).toBeUndefined();
    expect(log).toHaveBeenCalledTimes(1);
    const row = log.mock.calls[0]?.[0] as AuditLogOptions;
    expect(row.success).toBe(false);
    expect(row.secretId).toBe("secret-1");
    expect(row.detail).toStrictEqual(detail);
  }

  it.each(NON_ARRAY_REDIS_COMMANDS)(
    "a redis command that is %s: INVALID_DATABASE_CONFIG 'command must be a string array for redis', one failed row { context, engine, database, error } without host or port, no validateHostPort call, no adapter call",
    async (_label, value) => {
      await expectRefusedBeforeLookup(
        { command: value as DatabaseAction["command"] },
        "command must be a string array for redis",
        { context: "database", engine: "redis", database: "0", error: "INVALID_DATABASE_CONFIG" },
      );
    },
  );

  it.each(NON_INDEX_REDIS_DATABASES)(
    "a redis database of '%s': INVALID_DATABASE_CONFIG 'database must be a non-negative integer index for redis', one failed row { context, engine, database, error } without host or port, no validateHostPort call, no adapter call",
    async (value) => {
      await expectRefusedBeforeLookup(
        { database: value },
        "database must be a non-negative integer index for redis",
        { context: "database", engine: "redis", database: value, error: "INVALID_DATABASE_CONFIG" },
      );
    },
  );

  it("two faults, a redis command that is a string and a database with a slash: 'command must be a string array for redis' wins, INVALID_DATABASE_CONFIG, one failed row { context, engine, error } without database, host or port, no validateHostPort call, no adapter call", async () => {
    await expectRefusedBeforeLookup(
      { command: "PING" as unknown as string[], database: "a/b" },
      "command must be a string array for redis",
      { context: "database", engine: "redis", error: "INVALID_DATABASE_CONFIG" },
    );
  });

  it("a redis database with a slash, which the index check would refuse too: 'Invalid database name' wins, INVALID_DATABASE_CONFIG, one failed row { context, engine, error } without database, host or port, no validateHostPort call, no adapter call", async () => {
    await expectRefusedBeforeLookup({ database: "a/b" }, "Invalid database name", {
      context: "database",
      engine: "redis",
      error: "INVALID_DATABASE_CONFIG",
    });
  });

  it("two faults, a redis database of 'app' and a timeout_ms of 0: 'database must be a non-negative integer index for redis' wins, INVALID_DATABASE_CONFIG, one failed row { context, engine, database, error } without host or port, no validateHostPort call, no adapter call", async () => {
    await expectRefusedBeforeLookup(
      { database: "app", timeout_ms: 0 },
      "database must be a non-negative integer index for redis",
      { context: "database", engine: "redis", database: "app", error: "INVALID_DATABASE_CONFIG" },
    );
  });

  it.each(ACCEPTED_REDIS_DATABASES)(
    "a redis database of '%s' passes the guard and reaches the adapter with it, one successful row",
    async (value) => {
      const { inj, cmd, log } = auditedRedisInjector();
      await inj.executeWithSecret(
        redisAction({ database: value }),
        SECRET,
        policy(),
        undefined,
        "secret-1",
      );
      expect(cmd.lastExecute?.opts.database).toBe(value);
      expect(log).toHaveBeenCalledTimes(1);
      expect((log.mock.calls[0]?.[0] as AuditLogOptions).success).toBe(true);
    },
  );

  it.each(ACCEPTED_REDIS_COMMANDS)(
    "a redis command of %s passes the guard and reaches the adapter as given, one successful row",
    async (_label, value) => {
      const { inj, cmd, log } = auditedRedisInjector();
      await inj.executeWithSecret(
        redisAction({ command: value }),
        SECRET,
        policy(),
        undefined,
        "secret-1",
      );
      expect(cmd.lastExecute?.command).toBe(value);
      expect(log).toHaveBeenCalledTimes(1);
      expect((log.mock.calls[0]?.[0] as AuditLogOptions).success).toBe(true);
    },
  );
});

// v1.3 T11: mongodb dispatch mirrors the redis dispatch above, but exercised
// against the REAL `defaultDbCommandAdapters()` (i.e. no hand-registered mock
// command adapter) to prove the actual wiring: `defaultDbCommandAdapters()`
// now constructs a `MongoAdapter` for engine `mongodb`, and the shared
// dispatch logic (COMMAND_ENGINES already included mongodb since Task 10)
// reaches it end to end.
const NON_DOCUMENT_COMMANDS: ReadonlyArray<readonly [string, unknown]> = [
  ["null", null],
  ["undefined", undefined],
  ["a string", "ping"],
  ["an array", ["ping"]],
];

describe("DatabaseInjector mongodb dispatch (Task 11 wiring)", () => {
  function mongoAction(overrides: Partial<DatabaseAction> = {}): DatabaseAction {
    return {
      type: "database",
      engine: "mongodb",
      host: "8.8.8.8",
      database: "app_db",
      command: { ping: 1 },
      ...overrides,
    };
  }

  it("routes engine mongodb through the real default command adapters (MongoAdapter)", async () => {
    const injector = new DatabaseInjector(null); // real defaultDbAdapters() + defaultDbCommandAdapters()
    const res = await injector.executeWithSecret(mongoAction(), SECRET, policy(), undefined);
    expect(res.type).toBe("database");
    expect(res.row_count).toBe(1);
    expect(res.rows).toEqual([{ ok: 1 }]);
    expect(mongoCommandCalls).toHaveLength(1);
    expect(mongoCommandCalls[0]?.name).toBe("app_db");
    expect(mongoCommandCalls[0]?.command).toEqual({ ping: 1, maxTimeMS: DEFAULT_DB_TIMEOUT_MS });
  });

  it("a command that never settles ends at the action's timeout_ms as DB_QUERY_FAILED", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    mongoCommandHangs = true;
    const issued = new Promise<void>((resolve) => {
      mongoCommandIssued = resolve;
    });
    const flushed = (): Promise<void> =>
      new Promise((resolve) => {
        setImmediate(resolve);
      });
    let settled = false;
    const run = new DatabaseInjector(null).executeWithSecret(
      mongoAction({ timeout_ms: 1500 }),
      SECRET,
      policy(),
      undefined,
    );
    run.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await issued;
    await vi.advanceTimersByTimeAsync(1499);
    await flushed();
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await flushed();
    expect(settled).toBe(true);
    const err = await expectVaultError(() => run, ErrorCode.DB_QUERY_FAILED);
    expect(err.message).toContain("command did not complete within 1500 ms");
  });

  it("a command that never settles even after the abort ends at timeout_ms as DB_QUERY_FAILED, the client closed once", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    mongoCommandNeverSettles = true;
    const issued = new Promise<void>((resolve) => {
      mongoCommandIssued = resolve;
    });
    const flushed = (): Promise<void> =>
      new Promise((resolve) => {
        setImmediate(resolve);
      });
    let settled = false;
    const run = new DatabaseInjector(null).executeWithSecret(
      mongoAction({ timeout_ms: 1500 }),
      SECRET,
      policy(),
      undefined,
    );
    run.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await issued;
    await vi.advanceTimersByTimeAsync(1499);
    await flushed();
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await flushed();
    expect(settled).toBe(true);
    const err = await expectVaultError(() => run, ErrorCode.DB_QUERY_FAILED);
    expect(err.message).toContain("command did not complete within 1500 ms");
    expect(mongoCloseCount).toBe(1);
  });

  it.each(NON_DOCUMENT_COMMANDS)(
    "a command that is %s: INVALID_DATABASE_CONFIG 'command must be a document for mongodb', one failed row, no client",
    async (_label, value) => {
      const log = vi.fn();
      const inj = new DatabaseInjector({ log } as unknown as AuditLogger);
      const err = await expectVaultError(
        () =>
          inj.executeWithSecret(
            mongoAction({ command: value as DatabaseAction["command"] }),
            SECRET,
            policy(),
            undefined,
            "secret-1",
          ),
        ErrorCode.INVALID_DATABASE_CONFIG,
      );
      expect(err.message === "command must be a document for mongodb").toBe(true);
      expect(mongoClientCalls).toHaveLength(0);
      expect(log).toHaveBeenCalledTimes(1);
      const row = log.mock.calls[0]?.[0] as AuditLogOptions;
      expect(row.success).toBe(false);
      expect(row.detail).toStrictEqual({
        context: "database",
        engine: "mongodb",
        database: "app_db",
        error: "INVALID_DATABASE_CONFIG",
      });
    },
  );

  it("two faults, a mongodb command that is a string and a database with a slash: 'command must be a document for mongodb' wins, INVALID_DATABASE_CONFIG, one failed row { context, engine, error } without database, host or port, no validateHostPort call, no client", async () => {
    vi.mocked(validateHostPort).mockClear();
    const log = vi.fn();
    const inj = new DatabaseInjector({ log } as unknown as AuditLogger);
    const err = await expectVaultError(
      () =>
        inj.executeWithSecret(
          mongoAction({ command: "ping" as unknown as DatabaseAction["command"], database: "a/b" }),
          SECRET,
          policy(),
          undefined,
          "secret-1",
        ),
      ErrorCode.INVALID_DATABASE_CONFIG,
    );
    expect(err.message === "command must be a document for mongodb").toBe(true);
    expect(vi.mocked(validateHostPort)).not.toHaveBeenCalled();
    expect(mongoClientCalls).toHaveLength(0);
    expect(log).toHaveBeenCalledTimes(1);
    const row = log.mock.calls[0]?.[0] as AuditLogOptions;
    expect(row.success).toBe(false);
    expect(row.detail).toStrictEqual({
      context: "database",
      engine: "mongodb",
      error: "INVALID_DATABASE_CONFIG",
    });
  });

  it("parses username:password and pins the SSRF-validated address for mongodb too", async () => {
    const injector = new DatabaseInjector(null);
    await injector.executeWithSecret(mongoAction(), SECRET, policy(), undefined);
    const cfg = mongoClientCalls[0] as { uri: string; options: { directConnection?: boolean } };
    expect(cfg.uri).toContain("8.8.8.8:27017");
    expect(cfg.options.directConnection).toBe(true);
  });

  it("rejects mongodb SSRF to a private target before ever constructing the client", async () => {
    const injector = new DatabaseInjector(null);
    await expect(
      injector.executeWithSecret(mongoAction({ host: "10.0.0.1" }), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.SSRF_BLOCKED });
    expect(mongoClientCalls).toHaveLength(0);
  });
});

// Lazy-driver pin: a vault that never runs a redis/mongodb action never
// loads that driver (mirrors the pg/mysql2 lazy-import pattern — the drivers
// are dynamically imported only inside connect()/execute(), never at adapter
// construction time).
describe("DatabaseInjector lazy driver loading (redis, mongodb)", () => {
  it("never loads the redis or mongodb driver when running a postgresql action through the real default adapters", async () => {
    const injector = new DatabaseInjector(null); // real defaultDbAdapters() + defaultDbCommandAdapters()
    const res = await injector.executeWithSecret(action(), SECRET, policy(), undefined);
    expect(res.row_count).toBe(1);
    expect(redisCreateClientCalls).toHaveLength(0);
    expect(mongoClientCalls).toHaveLength(0);
    expect(pgClientConfigsForLazyPin).toHaveLength(1);
  });

  // The `redis` mock above is itself a "must not load" tripwire (it throws
  // on construction), so a redis action through the real adapters rejects —
  // that rejection is exactly what proves the redis driver load was
  // attempted; what this test additionally pins is that the *mongodb* driver
  // was never touched by that same call.
  it("never loads the mongodb driver when attempting a redis action through the real default adapters", async () => {
    const injector = new DatabaseInjector(null);
    await expectVaultError(
      () => injector.executeWithSecret(redisAction(), SECRET, policy(), undefined),
      ErrorCode.DB_QUERY_FAILED,
    );
    expect(mongoClientCalls).toHaveLength(0);
  });
});
