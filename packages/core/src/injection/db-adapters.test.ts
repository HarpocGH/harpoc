import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DbConnectOptions } from "./db-adapters.js";
import { defaultDbAdapters } from "./db-adapters.js";

// Driver mocks capture the connection config the adapters assemble; no real
// connection is made. node:net is mocked so the mysql2 pinned-stream factory
// can be invoked and its dial target asserted.
const pgClientConfigs: unknown[] = [];
vi.mock("pg", () => ({
  default: {
    Client: class {
      constructor(cfg: unknown) {
        pgClientConfigs.push(cfg);
      }
      connect(): Promise<void> {
        return Promise.resolve();
      }
    },
  },
}));

const mysqlConfigs: unknown[] = [];
vi.mock("mysql2/promise", () => ({
  createConnection: vi.fn((cfg: unknown) => {
    mysqlConfigs.push(cfg);
    return Promise.resolve({ query: vi.fn(), end: vi.fn() });
  }),
}));

const netConnectCalls: unknown[][] = [];
const setNoDelay = vi.fn();
vi.mock("node:net", () => ({
  createConnection: vi.fn((...args: unknown[]) => {
    netConnectCalls.push(args);
    return { setNoDelay };
  }),
}));

interface PgConfig {
  host: string;
  ssl: false | { rejectUnauthorized: boolean; ca?: string; servername?: string };
}

interface MysqlConfig {
  host: string;
  ssl?: { rejectUnauthorized: boolean; ca?: string; verifyIdentity?: boolean };
  stream?: () => { setNoDelay: (v: boolean) => void };
}

function opts(overrides: Partial<DbConnectOptions> = {}): DbConnectOptions {
  return {
    host: "db.example.com",
    port: 5432,
    address: "203.0.113.7",
    user: "u",
    password: "p",
    database: "app",
    tls: {},
    timeoutMs: 1000,
    ...overrides,
  };
}

beforeEach(() => {
  pgClientConfigs.length = 0;
  mysqlConfigs.length = 0;
  netConnectCalls.length = 0;
  setNoDelay.mockClear();
});

describe("PostgresAdapter connection config", () => {
  it("dials the pinned address and verifies TLS against the logical hostname", async () => {
    await defaultDbAdapters().postgresql.connect(opts());
    const cfg = pgClientConfigs[0] as PgConfig;
    expect(cfg.host).toBe("203.0.113.7");
    expect(cfg.ssl).toMatchObject({ rejectUnauthorized: true, servername: "db.example.com" });
  });

  it("sets no servername when the target was not pinned (literal IP)", async () => {
    await defaultDbAdapters().postgresql.connect(opts({ host: "8.8.8.8", address: "8.8.8.8" }));
    const cfg = pgClientConfigs[0] as PgConfig;
    expect(cfg.host).toBe("8.8.8.8");
    expect(cfg.ssl).not.toBe(false);
    expect(cfg.ssl).not.toHaveProperty("servername");
  });

  it("still dials the pinned address with TLS disabled", async () => {
    await defaultDbAdapters().postgresql.connect(opts({ tls: false }));
    const cfg = pgClientConfigs[0] as PgConfig;
    expect(cfg.host).toBe("203.0.113.7");
    expect(cfg.ssl).toBe(false);
  });
});

describe("MysqlAdapter connection config", () => {
  it("keeps the logical hostname for TLS and dials the pin via the stream factory", async () => {
    await defaultDbAdapters().mysql.connect(opts({ port: 3306 }));
    const cfg = mysqlConfigs[0] as MysqlConfig;
    expect(cfg.host).toBe("db.example.com");
    expect(cfg.ssl).toMatchObject({ rejectUnauthorized: true, verifyIdentity: true });
    expect(typeof cfg.stream).toBe("function");

    (cfg.stream as () => unknown)();
    expect(netConnectCalls[0]).toEqual([3306, "203.0.113.7"]);
    expect(setNoDelay).toHaveBeenCalledWith(true);
  });

  it("uses the driver's own dialer when the target was not pinned (literal IP)", async () => {
    await defaultDbAdapters().mysql.connect(
      opts({ host: "8.8.8.8", address: "8.8.8.8", port: 3306 }),
    );
    const cfg = mysqlConfigs[0] as MysqlConfig;
    expect(cfg.host).toBe("8.8.8.8");
    expect(cfg).not.toHaveProperty("stream");
    expect(cfg.ssl).not.toHaveProperty("verifyIdentity");
  });

  it("still dials the pinned address with TLS disabled", async () => {
    await defaultDbAdapters().mysql.connect(opts({ port: 3306, tls: false }));
    const cfg = mysqlConfigs[0] as MysqlConfig;
    expect(cfg.ssl).toBeUndefined();
    expect(typeof cfg.stream).toBe("function");
    (cfg.stream as () => unknown)();
    expect(netConnectCalls[0]).toEqual([3306, "203.0.113.7"]);
  });
});
