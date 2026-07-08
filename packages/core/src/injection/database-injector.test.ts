import { describe, expect, it } from "vitest";
import type { ConnectionConfig, DatabaseAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { DatabaseInjector } from "./database-injector.js";
import type { DbConnectOptions, DbConnection, DbEngineAdapter, DbQueryResult } from "./db-adapters.js";

interface MockBehavior {
  rows?: unknown[];
  fields?: { name: string }[];
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
          command: "SELECT",
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
      injector(mock).executeWithSecret(action(), SECRET, policy({ host_allowlist: ["9.9.9.9"] }), undefined),
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

  it("redacts the credential from the result rows", async () => {
    const mock = new MockAdapter({ rows: [{ note: "value is s3cr3t here" }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(JSON.stringify(res.rows)).not.toContain("s3cr3t");
    expect(JSON.stringify(res.rows)).toContain("[REDACTED]");
  });

  it("redacts the credential from a query error and maps to DB_QUERY_FAILED", async () => {
    const mock = new MockAdapter({ queryError: new Error("auth failed for admin:s3cr3t") });
    try {
      await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
      expect.fail("should throw");
    } catch (e) {
      const err = e as VaultError;
      expect(err.code).toBe(ErrorCode.DB_QUERY_FAILED);
      expect(err.message).not.toContain("s3cr3t");
    }
  });

  it("maps a connection failure to DB_CONNECTION_FAILED", async () => {
    const mock = new MockAdapter({ connectError: new Error("ECONNREFUSED") });
    await expect(
      injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.DB_CONNECTION_FAILED });
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
});
