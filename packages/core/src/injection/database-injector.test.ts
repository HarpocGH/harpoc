import { describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, DatabaseAction } from "@harpoc/shared";
import { DEFAULT_DB_TIMEOUT_MS, ErrorCode, MAX_DB_RESULT_BYTES, VaultError } from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { DatabaseInjector } from "./database-injector.js";
import {
  MockAdapter,
  MockCommandAdapter,
  SECRET,
  action,
  injector,
  policy,
  redisAction,
} from "./__fixtures__/database-injector-doubles.js";
import { validateHostPort } from "./url-validator.js";

const NON_ASCII_HOST = vi.hoisted(() => "b\u00fccher.example");

vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return {
    ...actual,
    validateHostPort: vi.fn(async (host: string, port: number) => {
      if (host === NON_ASCII_HOST) {
        return { host, port, resolvedAddress: "203.0.113.7" };
      }
      return actual.validateHostPort(host, port);
    }),
  };
});

const driverQueries = vi.hoisted(() => [] as { engine: string; args: unknown[] }[]);
const DB_PASSWORD = "s3cr3t";
const DB_USERNAME = "admin";
const FLOOR_USERNAME = "abc";
const COLONLESS_CREDENTIAL = "admins3cr3t";
vi.mock("pg", () => ({
  default: {
    Client: class {
      connect(): Promise<void> {
        return Promise.resolve();
      }
      query(...args: unknown[]): Promise<unknown> {
        driverQueries.push({ engine: "postgresql", args });
        return Promise.resolve({ rows: [], fields: [], rowCount: 0, command: "SELECT" });
      }
      end(): Promise<void> {
        return Promise.resolve();
      }
    },
  },
}));
vi.mock("mysql2/promise", () => ({
  createConnection: vi.fn(() =>
    Promise.resolve({
      query: vi.fn((...args: unknown[]) => {
        driverQueries.push({ engine: "mysql", args });
        return Promise.resolve([[], []]);
      }),
      end: vi.fn(() => Promise.resolve()),
    }),
  ),
}));

const COERCING_ENGINES: ReadonlyArray<readonly [string, unknown]> = [
  ["an array holding postgresql", ["postgresql"]],
  ["an array holding mysql", ["mysql"]],
  ["a boxed String", new String("postgresql")],
  ["an object with toString", { toString: () => "postgresql" }],
];

const PROTOTYPE_MEMBER_ENGINES: readonly string[] = [
  "constructor",
  "__proto__",
  "toString",
  "hasOwnProperty",
];

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

  it("a live signal sends as before", async () => {
    const mock = new MockAdapter({ rows: [{ id: 1 }], fields: [{ name: "id" }] });
    const res = await injector(mock).executeWithSecret(
      action(),
      SECRET,
      policy(),
      undefined,
      undefined,
      undefined,
      new AbortController().signal,
    );
    expect(res.row_count).toBe(1);
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

  it("refuses an unparsed host carrying a non-ASCII letter HOST_NOT_ALLOWED with its row, before the SSRF floor", async () => {
    const spy = vi.mocked(validateHostPort);
    spy.mockClear();
    const log = vi.fn();
    const mock = new MockAdapter({ rows: [] });
    const inj = new DatabaseInjector({ log } as unknown as AuditLogger, { postgresql: mock });
    await expectVaultError(
      () =>
        inj.executeWithSecret(
          action({ host: NON_ASCII_HOST }),
          SECRET,
          policy({ host_allowlist: [NON_ASCII_HOST] }),
          undefined,
          "secret-1",
        ),
      ErrorCode.HOST_NOT_ALLOWED,
    );
    expect(spy).not.toHaveBeenCalled();
    expect(mock.lastConnect).toBeUndefined();
    expect(log).toHaveBeenCalledTimes(1);
    const row = log.mock.calls[0]?.[0] as AuditLogOptions;
    expect(row.success).toBe(false);
    expect(row.secretId).toBe("secret-1");
    expect(row.detail).toEqual({
      context: "database",
      engine: "postgresql",
      database: "app",
      host: NON_ASCII_HOST,
      port: 5432,
      error: "HOST_NOT_ALLOWED",
    });
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

  it.each([
    ["a sql engine's connect", action(), "postgresql", "app", 5432],
    ["a command engine's execute", redisAction(), "redis", "0", 6379],
  ] as const)("an aborted signal sends nothing: %s", async (_arm, act, engine, db, port) => {
    const controller = new AbortController();
    const real = await vi.importActual<typeof import("./url-validator.js")>("./url-validator.js");
    vi.mocked(validateHostPort).mockImplementationOnce(async (host, hostPort) => {
      const answer = await real.validateHostPort(host, hostPort);
      controller.abort();
      return answer;
    });
    const log = vi.fn();
    const sql = new MockAdapter({ rows: [] });
    const cmd = new MockCommandAdapter();
    const inj = new DatabaseInjector(
      { log } as unknown as AuditLogger,
      { postgresql: sql },
      { redis: cmd },
    );

    await expectVaultError(
      () =>
        inj.executeWithSecret(
          act,
          SECRET,
          policy(),
          undefined,
          "secret-1",
          undefined,
          controller.signal,
        ),
      ErrorCode.VAULT_LOCKED,
    );

    expect(sql.lastConnect === undefined).toBe(true);
    expect(cmd.lastExecute === undefined).toBe(true);
    expect(log.mock.calls).toStrictEqual([
      [
        {
          eventType: "secret.use",
          secretId: "secret-1",
          detail: {
            context: "database",
            engine,
            database: db,
            host: "8.8.8.8",
            port,
            error: ErrorCode.VAULT_LOCKED,
          },
          success: false,
        },
      ],
    ]);
  });

  it.each([
    ["a sql engine's connect", action(), "postgresql", "app", 5432],
    ["a command engine's execute", redisAction(), "redis", "0", 6379],
  ] as const)(
    "an adapter's VAULT_LOCKED leaves as VAULT_LOCKED with its one row, the adapter handed the signal: %s",
    async (_arm, act, engine, db, port) => {
      const signal = new AbortController().signal;
      const log = vi.fn();
      const sql = new MockAdapter({ connectError: VaultError.vaultLocked() });
      const cmd = new MockCommandAdapter({ error: VaultError.vaultLocked() });
      const inj = new DatabaseInjector(
        { log } as unknown as AuditLogger,
        { postgresql: sql },
        { redis: cmd },
      );

      await expectVaultError(
        () =>
          inj.executeWithSecret(act, SECRET, policy(), undefined, "secret-1", undefined, signal),
        ErrorCode.VAULT_LOCKED,
      );

      expect((sql.lastConnect ?? cmd.lastExecute?.opts)?.signal === signal).toBe(true);
      expect(log.mock.calls).toStrictEqual([
        [
          {
            eventType: "secret.use",
            secretId: "secret-1",
            detail: {
              context: "database",
              engine,
              database: db,
              host: "8.8.8.8",
              port,
              error: ErrorCode.VAULT_LOCKED,
            },
            success: false,
          },
        ],
      ]);
    },
  );

  it.each([
    ["a sql engine's connect", action(), ErrorCode.DB_CONNECTION_FAILED],
    ["a command engine's execute", redisAction(), ErrorCode.DB_QUERY_FAILED],
  ] as const)(
    "an adapter's other VaultError still maps as before: %s",
    async (_arm, act, mapped) => {
      const log = vi.fn();
      const refusal = VaultError.invalidDatabaseConfig("refused by the adapter");
      const sql = new MockAdapter({ connectError: refusal });
      const cmd = new MockCommandAdapter({ error: refusal });
      const inj = new DatabaseInjector(
        { log } as unknown as AuditLogger,
        { postgresql: sql },
        { redis: cmd },
      );

      await expectVaultError(
        () => inj.executeWithSecret(act, SECRET, policy(), undefined, "secret-1"),
        mapped,
      );

      const row = log.mock.calls[0]?.[0] as AuditLogOptions;
      expect(log).toHaveBeenCalledTimes(1);
      expect(row.detail?.error).toBe(mapped);
    },
  );

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

  async function expectUnsupportedEngine(
    overrides: Partial<DatabaseAction>,
    message: string,
    detail: Record<string, unknown>,
  ): Promise<void> {
    vi.mocked(validateHostPort).mockClear();
    const log = vi.fn();
    const mock = new MockAdapter({ rows: [] });
    const cmd = new MockCommandAdapter();
    const inj = new DatabaseInjector(
      { log } as unknown as AuditLogger,
      { postgresql: mock, mysql: mock },
      { redis: cmd },
    );
    const err = await expectVaultError(
      () => inj.executeWithSecret(action(overrides), SECRET, policy(), undefined, "secret-1"),
      ErrorCode.UNSUPPORTED_DB_ENGINE,
    );
    expect(err.message === message).toBe(true);
    expect(vi.mocked(validateHostPort)).not.toHaveBeenCalled();
    expect(mock.lastConnect).toBeUndefined();
    expect(cmd.lastExecute).toBeUndefined();
    expect(log).toHaveBeenCalledTimes(1);
    const row = log.mock.calls[0]?.[0] as AuditLogOptions;
    expect(row.success).toBe(false);
    expect(row.secretId).toBe("secret-1");
    expect(row.detail).toStrictEqual(detail);
  }

  it.each(COERCING_ENGINES)(
    "an engine that is %s, sent with a query object: UNSUPPORTED_DB_ENGINE 'Unsupported database engine: (not a string)', one failed row { context, database, error } without engine, host or port, no validateHostPort call, no adapter, no connect",
    async (_label, value) => {
      await expectUnsupportedEngine(
        {
          engine: value as DatabaseAction["engine"],
          query: { text: "SELECT 1" } as unknown as string,
        },
        "Unsupported database engine: (not a string)",
        { context: "database", database: "app", error: "UNSUPPORTED_DB_ENGINE" },
      );
    },
  );

  it.each(PROTOTYPE_MEMBER_ENGINES)(
    "an engine named after the Object.prototype member '%s': UNSUPPORTED_DB_ENGINE 'Unsupported database engine: ' and the name, one failed row { context, engine, database, error } without host or port, no validateHostPort call, no adapter, no connect",
    async (name) => {
      await expectUnsupportedEngine(
        { engine: name as DatabaseAction["engine"] },
        `Unsupported database engine: ${name}`,
        { context: "database", engine: name, database: "app", error: "UNSUPPORTED_DB_ENGINE" },
      );
    },
  );

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
    const mock = new MockAdapter({ rows: [{ note: `value is ${DB_PASSWORD} here` }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expectAbsent(JSON.stringify(res.rows), DB_PASSWORD);
    expect(JSON.stringify(res.rows)).toContain("[REDACTED]");
  });

  // L1: column names and the command tag are endpoint-authored, so an alias
  // (`SELECT 1 AS "<credential>"`) put the value where no redactor looked while
  // the same string in a row value was redacted.
  it("redacts the credential from a column name", async () => {
    const mock = new MockAdapter({ rows: [{ x: 1 }], fields: [{ name: DB_PASSWORD }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expectAbsent(JSON.stringify(res.fields), DB_PASSWORD);
    expect(JSON.stringify(res.fields)).toContain("[REDACTED]");
  });

  it("redacts an encoded credential from a column name", async () => {
    const encoded = Buffer.from("s3cr3t", "utf8").toString("base64");
    const mock = new MockAdapter({ rows: [], fields: [{ name: `alias_${encoded}` }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expectAbsent(JSON.stringify(res.fields), encoded);
  });

  it("redacts the credential from the command tag", async () => {
    const mock = new MockAdapter({ rows: [], command: `SELECT ${DB_PASSWORD}` });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expectAbsent(res.command, DB_PASSWORD);
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
    expectAbsent(err.message, DB_PASSWORD);
  });

  it("maps a connection failure to DB_CONNECTION_FAILED", async () => {
    const mock = new MockAdapter({ connectError: new Error("ECONNREFUSED") });
    await expect(
      injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.DB_CONNECTION_FAILED });
  });

  it("redacts the username half from the result rows", async () => {
    const mock = new MockAdapter({ rows: [{ note: `logged in as ${DB_USERNAME} just now` }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expectAbsent(JSON.stringify(res.rows), DB_USERNAME);
    expect(JSON.stringify(res.rows)).toContain("[REDACTED]");
  });

  it("redacts the username half from a query error", async () => {
    const mock = new MockAdapter({ queryError: new Error("permission denied for role admin") });
    const err = await expectVaultError(
      () => injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
      ErrorCode.DB_QUERY_FAILED,
    );
    expectAbsent(err.message, DB_USERNAME);
  });

  it("redacts the username half from a connection error", async () => {
    const mock = new MockAdapter({
      connectError: new Error('password authentication failed for user "admin"'),
    });
    const err = await expectVaultError(
      () => injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
      ErrorCode.DB_CONNECTION_FAILED,
    );
    expectAbsent(err.message, DB_USERNAME);
  });

  it("redacts a username at the shared floor (MIN_REDACTABLE_FRAGMENT)", async () => {
    const mock = new MockAdapter({ rows: [{ note: "logged in as abc just now" }] });
    const res = await injector(mock).executeWithSecret(
      action(),
      new Uint8Array(Buffer.from("abc:s3cr3t")),
      policy(),
      undefined,
    );
    expectAbsent(JSON.stringify(res.rows), FLOOR_USERNAME);
    expect(JSON.stringify(res.rows)).toContain("[REDACTED]");
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

  it("an explicit port overrides the port embedded in host — allowlisted and dialed at it (I22)", async () => {
    const mock = new MockAdapter({ rows: [] });
    await injector(mock).executeWithSecret(
      action({ host: "8.8.8.8:1111", port: 2222 }),
      SECRET,
      policy({ host_allowlist: ["8.8.8.8:2222"] }),
      undefined,
    );
    expect(mock.lastConnect?.host).toBe("8.8.8.8");
    expect(mock.lastConnect?.port).toBe(2222);
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

  describe("SQL params reach the driver's query call by value (I21)", () => {
    const params = [42, "o'brien", null, true];

    it("postgresql: the params array is pg's second query argument", async () => {
      driverQueries.length = 0;
      await new DatabaseInjector(null).executeWithSecret(
        action({ query: "SELECT $1, $2, $3, $4", params }),
        SECRET,
        policy(),
        undefined,
      );
      expect(driverQueries).toEqual([
        { engine: "postgresql", args: ["SELECT $1, $2, $3, $4", [42, "o'brien", null, true]] },
      ]);
    });

    it("mysql: the params array is mysql2's second query argument", async () => {
      driverQueries.length = 0;
      await new DatabaseInjector(null).executeWithSecret(
        action({ engine: "mysql", query: "SELECT ?, ?, ?, ?", params, timeout_ms: 5_000 }),
        SECRET,
        policy(),
        undefined,
      );
      expect(driverQueries).toEqual([
        {
          engine: "mysql",
          args: [{ sql: "SELECT ?, ?, ?, ?", timeout: 5_000 }, [42, "o'brien", null, true]],
        },
      ]);
    });
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

const NON_STRING_HOSTS: ReadonlyArray<readonly [string, unknown]> = [
  ["a number", 123],
  ["null", null],
  ["an object", {}],
  ["an array", ["db.example:5432"]],
];

describe("DatabaseInjector — a refusal of the host field writes one failed row", () => {
  function auditedInjector(): { inj: DatabaseInjector; mock: MockAdapter; log: Mock } {
    vi.mocked(validateHostPort).mockClear();
    const log = vi.fn();
    const mock = new MockAdapter({ rows: [] });
    const inj = new DatabaseInjector({ log } as unknown as AuditLogger, { postgresql: mock });
    return { inj, mock, log };
  }

  it.each(NON_STRING_HOSTS)(
    "a host that is %s: INVALID_DATABASE_CONFIG 'host must be a string', one failed row without host, no connect",
    async (_label, value) => {
      const { inj, mock, log } = auditedInjector();
      const err = await expectVaultError(
        () =>
          inj.executeWithSecret(
            action({ host: value as string }),
            SECRET,
            policy(),
            undefined,
            "secret-1",
          ),
        ErrorCode.INVALID_DATABASE_CONFIG,
      );
      expect(err.message === "host must be a string").toBe(true);
      expect(vi.mocked(validateHostPort)).not.toHaveBeenCalled();
      expect(mock.lastConnect).toBeUndefined();
      expect(log).toHaveBeenCalledTimes(1);
      const row = log.mock.calls[0]?.[0] as AuditLogOptions;
      expect(row.success).toBe(false);
      expect(row.secretId).toBe("secret-1");
      expect(row.detail).toStrictEqual({
        context: "database",
        engine: "postgresql",
        database: "app",
        error: "INVALID_DATABASE_CONFIG",
      });
    },
  );

  it("an embedded port out of range: INVALID_DATABASE_CONFIG as today, exactly one failed row without host, no connect", async () => {
    const { inj, mock, log } = auditedInjector();
    const err = await expectVaultError(
      () =>
        inj.executeWithSecret(
          action({ host: "db.example:99999" }),
          SECRET,
          policy(),
          undefined,
          "secret-1",
        ),
      ErrorCode.INVALID_DATABASE_CONFIG,
    );
    expect(err.message).toBe("embedded port out of range (1-65535)");
    expect(vi.mocked(validateHostPort)).not.toHaveBeenCalled();
    expect(mock.lastConnect).toBeUndefined();
    expect(log).toHaveBeenCalledTimes(1);
    const row = log.mock.calls[0]?.[0] as AuditLogOptions;
    expect(row.success).toBe(false);
    expect(row.secretId).toBe("secret-1");
    expect(row.detail).toStrictEqual({
      context: "database",
      engine: "postgresql",
      database: "app",
      error: "INVALID_DATABASE_CONFIG",
    });
  });

  it("control: a string host outside the allowlist keeps today's outcome, message and row", async () => {
    const { inj, mock, log } = auditedInjector();
    const err = await expectVaultError(
      () =>
        inj.executeWithSecret(
          action({ host: "8.8.8.8" }),
          SECRET,
          policy({ host_allowlist: ["9.9.9.9"] }),
          undefined,
          "secret-1",
        ),
      ErrorCode.HOST_NOT_ALLOWED,
    );
    expect(err.message).toBe("Host not in secret allowlist: 8.8.8.8:5432");
    expect(mock.lastConnect).toBeUndefined();
    expect(log).toHaveBeenCalledTimes(1);
    const row = log.mock.calls[0]?.[0] as AuditLogOptions;
    expect(row.success).toBe(false);
    expect(row.detail).toStrictEqual({
      context: "database",
      engine: "postgresql",
      database: "app",
      host: "8.8.8.8",
      port: 5432,
      error: "HOST_NOT_ALLOWED",
    });
  });
});

const REFUSED_QUERIES: ReadonlyArray<readonly [string, unknown]> = [
  ["undefined", undefined],
  ["an empty string", ""],
  ["a number", 7],
  ["an object with text", { text: "SELECT 1" }],
];

const REFUSED_PARAMS: ReadonlyArray<readonly [string, unknown]> = [
  ["a string", "abc"],
  ["an object", { a: 1 }],
  ["an array of 1001 values", Array.from({ length: 1_001 }, (_, i) => i)],
];

const REFUSED_DATABASES: ReadonlyArray<readonly [string, unknown]> = [
  ["an empty string", ""],
  ["a number", 42],
  ["an object", {}],
  ["a name with a slash", "a/b"],
  ["a name of 256 characters", "x".repeat(256)],
];

const REFUSED_TIMEOUTS: ReadonlyArray<readonly [string, unknown]> = [
  ["0", 0],
  ["-1", -1],
  ["1.5", 1.5],
  ["300001", 300_001],
  ["the string '100'", "100"],
];

const ACCEPTED_TIMEOUTS: ReadonlyArray<readonly [string, Partial<DatabaseAction>, number]> = [
  ["1", { timeout_ms: 1 }, 1],
  ["300000", { timeout_ms: 300_000 }, 300_000],
  ["absent", {}, DEFAULT_DB_TIMEOUT_MS],
];

const ACCEPTED_PARAMS: ReadonlyArray<readonly [string, Partial<DatabaseAction>]> = [
  ["absent", {}],
  ["an empty array", { params: [] }],
  ["an array of 1000 values", { params: Array.from({ length: 1_000 }, (_, i) => i) }],
];

const ACCEPTED_DATABASES: ReadonlyArray<readonly [string, string]> = [
  ["'$external'", "$external"],
  ["a name of 255 characters", "x".repeat(255)],
];

describe("DatabaseInjector — an unparsed caller's input is refused with one failed row before any connection", () => {
  function auditedSqlInjector(): { inj: DatabaseInjector; mock: MockAdapter; log: Mock } {
    vi.mocked(validateHostPort).mockClear();
    const log = vi.fn();
    const mock = new MockAdapter({ rows: [] });
    const inj = new DatabaseInjector({ log } as unknown as AuditLogger, {
      postgresql: mock,
      mysql: mock,
    });
    return { inj, mock, log };
  }

  async function expectRefusedBeforeLookup(
    overrides: Partial<DatabaseAction>,
    message: string,
    detail: Record<string, unknown>,
  ): Promise<void> {
    const { inj, mock, log } = auditedSqlInjector();
    const err = await expectVaultError(
      () => inj.executeWithSecret(action(overrides), SECRET, policy(), undefined, "secret-1"),
      ErrorCode.INVALID_DATABASE_CONFIG,
    );
    expect(err.message === message).toBe(true);
    expect(vi.mocked(validateHostPort)).not.toHaveBeenCalled();
    expect(mock.lastConnect).toBeUndefined();
    expect(log).toHaveBeenCalledTimes(1);
    const row = log.mock.calls[0]?.[0] as AuditLogOptions;
    expect(row.success).toBe(false);
    expect(row.secretId).toBe("secret-1");
    expect(row.detail).toStrictEqual(detail);
  }

  it.each(REFUSED_QUERIES)(
    "a postgresql query that is %s: INVALID_DATABASE_CONFIG 'query is required for this engine', one failed row { context, engine, database, error } without host or port, no validateHostPort call, no connect",
    async (_label, value) => {
      await expectRefusedBeforeLookup(
        { query: value as string },
        "query is required for this engine",
        {
          context: "database",
          engine: "postgresql",
          database: "app",
          error: "INVALID_DATABASE_CONFIG",
        },
      );
    },
  );

  it.each(REFUSED_PARAMS)(
    "mysql params that are %s: INVALID_DATABASE_CONFIG 'params must be an array of at most 1000 values', one failed row { context, engine, database, error } without host or port, no validateHostPort call, no connect",
    async (_label, value) => {
      await expectRefusedBeforeLookup(
        { engine: "mysql", params: value as unknown[] },
        "params must be an array of at most 1000 values",
        { context: "database", engine: "mysql", database: "app", error: "INVALID_DATABASE_CONFIG" },
      );
    },
  );

  it.each(REFUSED_DATABASES)(
    "a database that is %s: INVALID_DATABASE_CONFIG 'Invalid database name', one failed row { context, engine, error } without database, host or port, no validateHostPort call, no connect",
    async (_label, value) => {
      await expectRefusedBeforeLookup({ database: value as string }, "Invalid database name", {
        context: "database",
        engine: "postgresql",
        error: "INVALID_DATABASE_CONFIG",
      });
    },
  );

  it.each(REFUSED_TIMEOUTS)(
    "a timeout_ms of %s: INVALID_DATABASE_CONFIG 'timeout_ms must be a positive integer up to 300000', one failed row { context, engine, database, error } without host or port, no validateHostPort call, no connect",
    async (_label, value) => {
      await expectRefusedBeforeLookup(
        { timeout_ms: value as number },
        "timeout_ms must be a positive integer up to 300000",
        {
          context: "database",
          engine: "postgresql",
          database: "app",
          error: "INVALID_DATABASE_CONFIG",
        },
      );
    },
  );

  it("two faults, a postgresql query that is a number and params that are a string: 'query is required for this engine' wins, INVALID_DATABASE_CONFIG, one failed row { context, engine, database, error } without host or port, no validateHostPort call, no connect", async () => {
    await expectRefusedBeforeLookup(
      { query: 7 as unknown as string, params: "x" as unknown as unknown[] },
      "query is required for this engine",
      {
        context: "database",
        engine: "postgresql",
        database: "app",
        error: "INVALID_DATABASE_CONFIG",
      },
    );
  });

  it("two faults, postgresql params that are a string and an empty database: 'params must be an array of at most 1000 values' wins, INVALID_DATABASE_CONFIG, one failed row { context, engine, error } without database, host or port, no validateHostPort call, no connect", async () => {
    await expectRefusedBeforeLookup(
      { params: "x" as unknown as unknown[], database: "" },
      "params must be an array of at most 1000 values",
      { context: "database", engine: "postgresql", error: "INVALID_DATABASE_CONFIG" },
    );
  });

  it.each(ACCEPTED_TIMEOUTS)(
    "a timeout_ms of %s passes the guard and reaches the adapter as its budget, one successful row",
    async (_label, overrides, budget) => {
      const { inj, mock, log } = auditedSqlInjector();
      await inj.executeWithSecret(action(overrides), SECRET, policy(), undefined, "secret-1");
      expect(mock.lastConnect?.timeoutMs).toBe(budget);
      expect(log).toHaveBeenCalledTimes(1);
      expect((log.mock.calls[0]?.[0] as AuditLogOptions).success).toBe(true);
    },
  );

  it.each(ACCEPTED_PARAMS)(
    "mysql params that are %s pass the guard and reach the adapter as given, one successful row",
    async (_label, overrides) => {
      const { inj, mock, log } = auditedSqlInjector();
      await inj.executeWithSecret(
        action({ engine: "mysql", ...overrides }),
        SECRET,
        policy(),
        undefined,
        "secret-1",
      );
      expect(mock.lastQuery?.params).toBe(overrides.params);
      expect(log).toHaveBeenCalledTimes(1);
      expect((log.mock.calls[0]?.[0] as AuditLogOptions).success).toBe(true);
    },
  );

  it.each(ACCEPTED_DATABASES)(
    "a database of %s passes the guard and reaches the adapter with it, one successful row carrying it",
    async (_label, value) => {
      const { inj, mock, log } = auditedSqlInjector();
      await inj.executeWithSecret(
        action({ database: value }),
        SECRET,
        policy(),
        undefined,
        "secret-1",
      );
      expect(mock.lastConnect?.database).toBe(value);
      expect(log).toHaveBeenCalledTimes(1);
      const row = log.mock.calls[0]?.[0] as AuditLogOptions;
      expect(row.success).toBe(true);
      expect(row.detail?.database).toBe(value);
    },
  );

  it("a postgresql query of one character passes the guard and reaches the adapter as given, one successful row", async () => {
    const { inj, mock, log } = auditedSqlInjector();
    await inj.executeWithSecret(action({ query: "x" }), SECRET, policy(), undefined, "secret-1");
    expect(mock.lastQuery?.sql).toBe("x");
    expect(log).toHaveBeenCalledTimes(1);
    expect((log.mock.calls[0]?.[0] as AuditLogOptions).success).toBe(true);
  });

  it("a credential without a colon: INVALID_DATABASE_CONFIG \"database secret must be in 'username:password' form\" as today, nothing of the credential in the refusal or the row, one failed row past the lookup with host, port and the TLS opt-out stamp, no connect", async () => {
    const { inj, mock, log } = auditedSqlInjector();
    const err = await expectVaultError(
      () =>
        inj.executeWithSecret(
          action(),
          new Uint8Array(Buffer.from(COLONLESS_CREDENTIAL)),
          policy(),
          { database: { tls_mode: "disable" } },
          "secret-1",
        ),
      ErrorCode.INVALID_DATABASE_CONFIG,
    );
    expectAbsent(err.message, COLONLESS_CREDENTIAL, "the refusal");
    expectAbsent(JSON.stringify(log.mock.calls), COLONLESS_CREDENTIAL, "the audit calls");
    expect(err.message).toBe("database secret must be in 'username:password' form");
    expect(vi.mocked(validateHostPort)).toHaveBeenCalledTimes(1);
    expect(mock.lastConnect).toBeUndefined();
    expect(log).toHaveBeenCalledTimes(1);
    const row = log.mock.calls[0]?.[0] as AuditLogOptions;
    expect(row.success).toBe(false);
    expect(row.secretId).toBe("secret-1");
    expect(row.detail).toStrictEqual({
      context: "database",
      engine: "postgresql",
      database: "app",
      host: "8.8.8.8",
      port: 5432,
      error: "INVALID_DATABASE_CONFIG",
      tls_opt_out: true,
    });
  });
});
