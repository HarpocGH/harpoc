import type { DatabaseAction, InjectionPolicy } from "@harpoc/shared";
import { DatabaseInjector } from "../database-injector.js";
import type {
  DbCommandAdapter,
  DbConnectOptions,
  DbConnection,
  DbEngineAdapter,
  DbQueryResult,
} from "../db-adapters.js";

export interface MockBehavior {
  rows?: unknown[];
  fields?: { name: string }[];
  command?: string;
  connectError?: Error;
  queryError?: Error;
}

export class MockAdapter implements DbEngineAdapter {
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

export const SECRET = new Uint8Array(Buffer.from("admin:s3cr3t"));

export function policy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return {
    url_allowlist: [],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: ["8.8.8.8", "10.0.0.1", "127.0.0.1"],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    ...overrides,
  };
}

export function action(overrides: Partial<DatabaseAction> = {}): DatabaseAction {
  return {
    type: "database",
    engine: "postgresql",
    host: "8.8.8.8",
    database: "app",
    query: "SELECT 1",
    ...overrides,
  };
}

export function injector(mock: MockAdapter): DatabaseInjector {
  return new DatabaseInjector(null, { postgresql: mock, mysql: mock });
}

export interface CommandMockBehavior {
  result?: DbQueryResult;
  error?: Error;
}

export class MockCommandAdapter implements DbCommandAdapter {
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

export function redisAction(overrides: Partial<DatabaseAction> = {}): DatabaseAction {
  return {
    type: "database",
    engine: "redis",
    host: "8.8.8.8",
    database: "0",
    command: ["GET", "foo"],
    ...overrides,
  };
}

export function injectorWithRedis(
  commandAdapter: MockCommandAdapter,
  sqlMock: MockAdapter = new MockAdapter(),
): DatabaseInjector {
  return new DatabaseInjector(
    null,
    { postgresql: sqlMock, mysql: sqlMock },
    { redis: commandAdapter },
  );
}
