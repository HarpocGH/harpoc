import { createConnection as netConnect } from "node:net";
import type { DatabaseEngine } from "@harpoc/shared";

/**
 * Engine-agnostic database access seam. Each adapter assembles the connection
 * in-process (request-mediated injection, thesis §4.5.5) with TLS + server-cert
 * verification by default, executes a single query and normalizes the result.
 * Drivers are imported lazily so a vault that never runs a database action does
 * not pay their load cost.
 */

/** TLS policy for a connection: `false` disables TLS (audited opt-out); an object requires it. */
export type DbTlsOptions = false | { ca?: string };

export interface DbConnectOptions {
  /** Logical target host as requested — TLS identity is verified against this name. */
  host: string;
  port: number;
  /**
   * Network address to dial: the SSRF-validated address from the pre-flight DNS
   * lookup when `host` is a hostname, otherwise `host` itself. Adapters must
   * connect to this address — never re-resolve `host` — so DNS rebinding cannot
   * retarget the connection between validation and connect.
   */
  address: string;
  user: string;
  password: string;
  database: string;
  tls: DbTlsOptions;
  timeoutMs: number;
}

export interface DbQueryResult {
  rows: unknown[];
  fields: { name: string }[];
  rowCount: number | null;
  command?: string;
}

export interface DbConnection {
  query(sql: string, params?: unknown[]): Promise<DbQueryResult>;
  end(): Promise<void>;
}

export interface DbEngineAdapter {
  connect(opts: DbConnectOptions): Promise<DbConnection>;
}

class PostgresAdapter implements DbEngineAdapter {
  async connect(opts: DbConnectOptions): Promise<DbConnection> {
    const { default: pg } = await import("pg");
    // Dial the pinned address; `servername` keeps SNI + certificate hostname
    // verification on the logical host (pg self-derives servername only for
    // hostname dials, so it must be explicit when connecting by IP).
    const pinned = opts.address !== opts.host;
    const client = new pg.Client({
      host: opts.address,
      port: opts.port,
      user: opts.user,
      password: opts.password,
      database: opts.database,
      ssl:
        opts.tls === false
          ? false
          : {
              rejectUnauthorized: true,
              ca: opts.tls.ca,
              ...(pinned ? { servername: opts.host } : {}),
            },
      connectionTimeoutMillis: opts.timeoutMs,
      statement_timeout: opts.timeoutMs,
      query_timeout: opts.timeoutMs,
    });
    await client.connect();
    return {
      async query(sql: string, params?: unknown[]): Promise<DbQueryResult> {
        const res = await client.query(sql, params as unknown[] | undefined);
        return {
          rows: res.rows as unknown[],
          fields: (res.fields ?? []).map((f) => ({ name: f.name })),
          rowCount: res.rowCount,
          command: res.command,
        };
      },
      async end(): Promise<void> {
        await client.end();
      },
    };
  }
}

class MysqlAdapter implements DbEngineAdapter {
  async connect(opts: DbConnectOptions): Promise<DbConnection> {
    const mysql = await import("mysql2/promise");
    // mysql2 derives the TLS servername from `host` and offers no override, so
    // `host` stays the logical name and the pinned address goes in through a
    // custom socket factory. `verifyIdentity` must be explicit: without it
    // mysql2 swaps checkServerIdentity for a no-op and never verifies the
    // certificate hostname.
    const pinned = opts.address !== opts.host;
    const conn = await mysql.createConnection({
      host: opts.host,
      port: opts.port,
      user: opts.user,
      password: opts.password,
      database: opts.database,
      ssl:
        opts.tls === false
          ? undefined
          : {
              rejectUnauthorized: true,
              ca: opts.tls.ca,
              ...(pinned ? { verifyIdentity: true } : {}),
            },
      connectTimeout: opts.timeoutMs,
      ...(pinned
        ? {
            stream: () => {
              const socket = netConnect(opts.port, opts.address);
              socket.setNoDelay(true);
              return socket;
            },
          }
        : {}),
    });
    return {
      async query(sql: string, params?: unknown[]): Promise<DbQueryResult> {
        const [rows, fields] = await conn.query({ sql, timeout: opts.timeoutMs }, params);
        const rowArray = Array.isArray(rows) ? (rows as unknown[]) : [];
        const fieldArray = Array.isArray(fields)
          ? (fields as { name: string }[]).map((f) => ({ name: f.name }))
          : [];
        return {
          rows: rowArray,
          fields: fieldArray,
          rowCount: Array.isArray(rows) ? rowArray.length : null,
        };
      },
      async end(): Promise<void> {
        await conn.end();
      },
    };
  }
}

/** Default engine adapters. Callers may substitute a mock adapter in tests. */
export function defaultDbAdapters(): Record<DatabaseEngine, DbEngineAdapter> {
  return {
    postgresql: new PostgresAdapter(),
    mysql: new MysqlAdapter(),
  };
}

/** Default TCP port for an engine when the action omits one. */
export function defaultDbPort(engine: DatabaseEngine): number {
  return engine === "mysql" ? 3306 : 5432;
}
