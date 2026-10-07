import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, DatabaseAction } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
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
vi.mock("mongodb", () => {
  class MongoClient {
    constructor(uri: string, options: unknown) {
      mongoClientCalls.push({ uri, options });
    }
    connect(): Promise<this> {
      return Promise.resolve(this);
    }
    close(): Promise<void> {
      return Promise.resolve(undefined);
    }
    db(name: string): { command: (command: unknown, options?: unknown) => Promise<unknown> } {
      return {
        command: (command: unknown, options?: unknown) => {
          mongoCommandCalls.push({ name, command, options });
          return Promise.resolve({ ok: 1 });
        },
      };
    }
  }
  return { MongoClient };
});

beforeEach(() => {
  mongoClientCalls.length = 0;
  mongoCommandCalls.length = 0;
});

const pgClientConfigsForLazyPin: unknown[] = [];
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
    expect(err.message).not.toContain("s3cr3t");
  });

  it("rejects an engine with no command adapter configured on this injector instance", async () => {
    const cmd = new MockCommandAdapter();
    const inj = new DatabaseInjector(null, {}, { redis: cmd });
    await expect(
      inj.executeWithSecret(redisAction({ engine: "mongodb" }), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.UNSUPPORTED_DB_ENGINE });
  });
});

// v1.3 T11: mongodb dispatch mirrors the redis dispatch above, but exercised
// against the REAL `defaultDbCommandAdapters()` (i.e. no hand-registered mock
// command adapter) to prove the actual wiring: `defaultDbCommandAdapters()`
// now constructs a `MongoAdapter` for engine `mongodb`, and the shared
// dispatch logic (COMMAND_ENGINES already included mongodb since Task 10)
// reaches it end to end.
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
    expect(mongoCommandCalls[0]?.command).toEqual({ ping: 1 });
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
