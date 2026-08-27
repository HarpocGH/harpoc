import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, DatabaseAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, MAX_DB_RESULT_BYTES } from "@harpoc/shared";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { DatabaseInjector } from "./database-injector.js";
import type {
  DbCommandAdapter,
  DbConnectOptions,
  DbConnection,
  DbEngineAdapter,
  DbQueryResult,
} from "./db-adapters.js";
import { expectVaultError } from "../test-helpers/expect-vault-error.js";

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

interface MockBehavior {
  rows?: unknown[];
  fields?: { name: string }[];
  command?: string;
  connectError?: Error;
  queryError?: Error;
}

class MockAdapter implements DbEngineAdapter {
  lastConnect: DbConnectOptions | undefined;
  lastQuery: { sql: string; params?: unknown[] } | undefined;

  constructor(private readonly behavior: MockBehavior = {}) {}

  connect(opts: DbConnectOptions): Promise<DbConnection> {
    this.lastConnect = opts;
    if (this.behavior.connectError) return Promise.reject(this.behavior.connectError);
    const b = this.behavior;
    const conn: DbConnection = {
      query: (sql: string, params?: unknown[]): Promise<DbQueryResult> => {
        this.lastQuery = { sql, params };
        if (b.queryError) return Promise.reject(b.queryError);
        const rows = b.rows ?? [];
        return Promise.resolve({
          rows,
          fields: b.fields ?? [],
          rowCount: rows.length,
          command: b.command ?? "SELECT",
        });
      },
      end: (): Promise<void> => Promise.resolve(),
    };
    return Promise.resolve(conn);
  }
}

const SECRET = new Uint8Array(Buffer.from("admin:s3cr3t"));

function policy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return {
    url_allowlist: [],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    ...overrides,
  };
}

function action(overrides: Partial<DatabaseAction> = {}): DatabaseAction {
  return {
    type: "database",
    engine: "postgresql",
    host: "8.8.8.8",
    database: "app",
    query: "SELECT 1",
    ...overrides,
  };
}

function injector(mock: MockAdapter): DatabaseInjector {
  return new DatabaseInjector(null, { postgresql: mock, mysql: mock });
}

interface CommandMockBehavior {
  result?: DbQueryResult;
  error?: Error;
}

class MockCommandAdapter implements DbCommandAdapter {
  lastExecute: { opts: DbConnectOptions; command: unknown } | undefined;

  constructor(private readonly behavior: CommandMockBehavior = {}) {}

  execute(opts: DbConnectOptions, command: unknown): Promise<DbQueryResult> {
    this.lastExecute = { opts, command };
    if (this.behavior.error) return Promise.reject(this.behavior.error);
    return Promise.resolve(
      this.behavior.result ?? {
        rows: ["PONG"],
        fields: [{ name: "reply" }],
        rowCount: 1,
        command: undefined,
      },
    );
  }
}

function redisAction(overrides: Partial<DatabaseAction> = {}): DatabaseAction {
  return {
    type: "database",
    engine: "redis",
    host: "8.8.8.8",
    database: "0",
    command: ["GET", "foo"],
    ...overrides,
  };
}

function injectorWithRedis(
  commandAdapter: MockCommandAdapter,
  sqlMock: MockAdapter = new MockAdapter(),
): DatabaseInjector {
  return new DatabaseInjector(
    null,
    { postgresql: sqlMock, mysql: sqlMock },
    { redis: commandAdapter },
  );
}

describe("DatabaseInjector", () => {
  it("parses username:password and runs the query", async () => {
    const mock = new MockAdapter({ rows: [{ id: 1 }], fields: [{ name: "id" }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(res.type).toBe("database");
    expect(res.row_count).toBe(1);
    expect(mock.lastConnect?.user).toBe("admin");
    expect(mock.lastConnect?.password).toBe("s3cr3t");
    expect(mock.lastQuery?.sql).toBe("SELECT 1");
  });

  it("requires TLS by default and disables it only via the opt-out", async () => {
    const mock1 = new MockAdapter({ rows: [] });
    await injector(mock1).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(mock1.lastConnect?.tls).not.toBe(false);

    const mock2 = new MockAdapter({ rows: [] });
    const config: ConnectionConfig = { database: { tls_mode: "disable" } };
    await injector(mock2).executeWithSecret(action(), SECRET, policy(), config);
    expect(mock2.lastConnect?.tls).toBe(false);
  });

  it("rejects a host:port outside the allowlist before connecting", async () => {
    const mock = new MockAdapter({ rows: [] });
    await expect(
      injector(mock).executeWithSecret(
        action(),
        SECRET,
        policy({ host_allowlist: ["9.9.9.9"] }),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
    expect(mock.lastConnect).toBeUndefined();
  });

  it("allows a matching host:port allowlist entry", async () => {
    const mock = new MockAdapter({ rows: [] });
    await injector(mock).executeWithSecret(
      action(),
      SECRET,
      policy({ host_allowlist: ["8.8.8.8:5432"] }),
      undefined,
    );
    expect(mock.lastConnect?.host).toBe("8.8.8.8");
    expect(mock.lastConnect?.port).toBe(5432);
    expect(mock.lastConnect?.address).toBe("8.8.8.8");
  });

  it("blocks SSRF to a private target before connecting", async () => {
    const mock = new MockAdapter({ rows: [] });
    await expect(
      injector(mock).executeWithSecret(action({ host: "10.0.0.1" }), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.SSRF_BLOCKED });
    expect(mock.lastConnect).toBeUndefined();
  });

  it("rejects an unsupported engine", async () => {
    const mock = new MockAdapter({ rows: [] });
    const inj = new DatabaseInjector(null, { postgresql: mock });
    await expect(
      inj.executeWithSecret(action({ engine: "mysql" }), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.UNSUPPORTED_DB_ENGINE });
  });

  // The adapter is resolved ahead of every pre-connect step: a target that
  // would fail all three of them (an out-of-range embedded port that
  // `parseHostPort` would refuse, a host:port `parseHostPort` would produce
  // that the allowlist wouldn't match, and a private address the SSRF floor
  // would block) still refuses as UNSUPPORTED_DB_ENGINE, with exactly one
  // audit row whose detail names no host or port — so a reorder past any one
  // of the three steps would change the error code or the row.
  it("refuses an unsupported engine before parsing, allowlisting or resolving the host", async () => {
    const log = vi.fn();
    const inj = new DatabaseInjector({ log } as unknown as AuditLogger, {
      postgresql: new MockAdapter(),
    });
    await expectVaultError(
      () =>
        inj.executeWithSecret(
          action({ engine: "mysql", host: "10.0.0.1:0" }),
          SECRET,
          policy({ host_allowlist: ["db.example.com:5432"] }),
          undefined,
          "secret-1",
        ),
      ErrorCode.UNSUPPORTED_DB_ENGINE,
    );
    expect(log).toHaveBeenCalledTimes(1);
    const row = log.mock.calls[0]?.[0] as AuditLogOptions;
    expect(row.success).toBe(false);
    expect(row.secretId).toBe("secret-1");
    expect(Object.keys(row.detail ?? {}).sort()).toEqual([
      "context",
      "database",
      "engine",
      "error",
    ]);
    expect(row.detail).toMatchObject({
      context: "database",
      engine: "mysql",
      database: "app",
      error: "UNSUPPORTED_DB_ENGINE",
    });
  });

  it("refuses an unknown SQL engine key in the adapter registry (compile-time)", () => {
    const mock = new MockAdapter({ rows: [] });
    // Compile-time pin: the registry is keyed by DbSqlEngine, so the
    // `"postgres"` fixture that once passed for months is a type error now.
    // @ts-expect-error "postgres" is not a DbSqlEngine
    const inj = new DatabaseInjector(null, { postgres: mock });
    expect(inj).toBeInstanceOf(DatabaseInjector);
  });

  it("refuses a command engine key in the SQL adapter registry (compile-time)", () => {
    const mock = new MockAdapter({ rows: [] });
    // @ts-expect-error redis is a command engine, not a SQL engine
    const inj = new DatabaseInjector(null, { redis: mock });
    expect(inj).toBeInstanceOf(DatabaseInjector);
  });

  it("refuses a SQL engine key in the command-adapter registry (compile-time)", () => {
    const cmd = new MockCommandAdapter();
    // @ts-expect-error postgresql is a SQL engine, not a command engine
    const inj = new DatabaseInjector(null, {}, { postgresql: cmd });
    expect(inj).toBeInstanceOf(DatabaseInjector);
  });

  it("redacts the credential from the result rows", async () => {
    const mock = new MockAdapter({ rows: [{ note: "value is s3cr3t here" }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(JSON.stringify(res.rows)).not.toContain("s3cr3t");
    expect(JSON.stringify(res.rows)).toContain("[REDACTED]");
  });

  // L1: column names and the command tag are endpoint-authored, so an alias
  // (`SELECT 1 AS "<credential>"`) put the value where no redactor looked while
  // the same string in a row value was redacted.
  it("redacts the credential from a column name", async () => {
    const mock = new MockAdapter({ rows: [{ x: 1 }], fields: [{ name: "s3cr3t" }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(JSON.stringify(res.fields)).not.toContain("s3cr3t");
    expect(JSON.stringify(res.fields)).toContain("[REDACTED]");
  });

  it("redacts an encoded credential from a column name", async () => {
    const encoded = Buffer.from("s3cr3t", "utf8").toString("base64");
    const mock = new MockAdapter({ rows: [], fields: [{ name: `alias_${encoded}` }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(JSON.stringify(res.fields)).not.toContain(encoded);
  });

  it("redacts the credential from the command tag", async () => {
    const mock = new MockAdapter({ rows: [], command: "SELECT s3cr3t" });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(res.command).not.toContain("s3cr3t");
    expect(res.command).toContain("[REDACTED]");
  });

  it("leaves ordinary column names and command tags untouched", async () => {
    const mock = new MockAdapter({
      rows: [{ id: 1 }],
      fields: [{ name: "id" }, { name: "created_at" }],
      command: "SELECT",
    });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(res.fields).toEqual([{ name: "id" }, { name: "created_at" }]);
    expect(res.command).toBe("SELECT");
  });

  it("redacts the credential from a query error and maps to DB_QUERY_FAILED", async () => {
    const mock = new MockAdapter({ queryError: new Error("auth failed for admin:s3cr3t") });
    const err = await expectVaultError(
      () => injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
      ErrorCode.DB_QUERY_FAILED,
    );
    expect(err.message).not.toContain("s3cr3t");
  });

  it("maps a connection failure to DB_CONNECTION_FAILED", async () => {
    const mock = new MockAdapter({ connectError: new Error("ECONNREFUSED") });
    await expect(
      injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.DB_CONNECTION_FAILED });
  });

  it("redacts the username half from the result rows", async () => {
    const mock = new MockAdapter({ rows: [{ note: "logged in as admin just now" }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(JSON.stringify(res.rows)).not.toContain("admin");
    expect(JSON.stringify(res.rows)).toContain("[REDACTED]");
  });

  it("redacts the username half from a query error", async () => {
    const mock = new MockAdapter({ queryError: new Error("permission denied for role admin") });
    const err = await expectVaultError(
      () => injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
      ErrorCode.DB_QUERY_FAILED,
    );
    expect(err.message).not.toContain("admin");
  });

  it("redacts the username half from a connection error", async () => {
    const mock = new MockAdapter({
      connectError: new Error('password authentication failed for user "admin"'),
    });
    const err = await expectVaultError(
      () => injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
      ErrorCode.DB_CONNECTION_FAILED,
    );
    expect(err.message).not.toContain("admin");
  });

  it("leaves a 1-2 char username unredacted (would shred unrelated output)", async () => {
    const mock = new MockAdapter({ rows: [{ note: "a value about nothing" }] });
    const res = await injector(mock).executeWithSecret(
      action(),
      new Uint8Array(Buffer.from("ab:s3cr3t")),
      policy(),
      undefined,
    );
    expect(JSON.stringify(res.rows)).toContain("a value about nothing");
  });

  it("refuses an out-of-range embedded port before any connection work", async () => {
    const mock = new MockAdapter({ rows: [] });
    await expect(
      injector(mock).executeWithSecret(
        action({ host: "8.8.8.8:70000" }),
        SECRET,
        policy(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_DATABASE_CONFIG });
    expect(mock.lastConnect).toBeUndefined();
  });

  it("throws for a secret that is not username:password", async () => {
    const mock = new MockAdapter({ rows: [] });
    await expect(
      injector(mock).executeWithSecret(
        action(),
        new Uint8Array(Buffer.from("no-colon")),
        policy(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_DATABASE_CONFIG });
  });

  it("flags truncation past the row cap", async () => {
    const rows = Array.from({ length: 10_001 }, (_, i) => ({ i }));
    const mock = new MockAdapter({ rows });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(res.truncated).toBe(true);
    expect(res.rows.length).toBeLessThanOrEqual(10_000);
  });

  // H5: the byte-cap loop halved with Math.ceil, so a single row larger than the
  // cap never shrank and the loop spun forever. It is synchronous, so this hung
  // the whole vault process — reachable with one agent-chosen query.
  describe("byte cap always terminates (H5)", () => {
    const oversized = (n: number): string => "x".repeat(MAX_DB_RESULT_BYTES + n);

    it("drops a single row that exceeds the byte cap on its own", async () => {
      const mock = new MockAdapter({ rows: [{ blob: oversized(1000) }] });
      const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
      expect(res.truncated).toBe(true);
      expect(res.rows).toEqual([]);
    });

    it("drops the last row when halving bottoms out at one oversized row", async () => {
      const mock = new MockAdapter({
        rows: [{ blob: oversized(1000) }, { blob: oversized(1000) }, { i: 3 }],
      });
      const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
      expect(res.truncated).toBe(true);
      expect(res.rows).toEqual([]);
    });

    it("still returns as many rows as fit under the cap", async () => {
      // 40 rows of ~64 KiB: some fit, so the result must not be emptied.
      const rows = Array.from({ length: 40 }, (_, i) => ({ i, pad: "y".repeat(64 * 1024) }));
      const mock = new MockAdapter({ rows });
      const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
      expect(res.truncated).toBe(true);
      expect(res.rows.length).toBeGreaterThan(0);
      expect(Buffer.byteLength(JSON.stringify(res.rows), "utf8")).toBeLessThanOrEqual(
        MAX_DB_RESULT_BYTES,
      );
    });

    it("negative control: a small result set is returned untruncated", async () => {
      const mock = new MockAdapter({ rows: [{ i: 1 }, { i: 2 }] });
      const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
      expect(res.truncated).toBeFalsy();
      expect(res.rows).toHaveLength(2);
    });
  });
});

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
    await expect(
      injector.executeWithSecret(redisAction(), SECRET, policy(), undefined),
    ).rejects.toThrow();
    expect(mongoClientCalls).toHaveLength(0);
  });
});
