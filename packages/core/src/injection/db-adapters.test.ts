import { beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { DbConnectOptions, DbEngineAdapter, DbSqlEngine } from "./db-adapters.js";
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

function adapterFor(engine: DbSqlEngine): DbEngineAdapter {
  const adapter = defaultDbAdapters()[engine];
  if (!adapter) throw new Error(`no default adapter for ${engine}`);
  return adapter;
}

beforeEach(() => {
  pgClientConfigs.length = 0;
  mysqlConfigs.length = 0;
  netConnectCalls.length = 0;
  setNoDelay.mockClear();
});

describe("PostgresAdapter connection config", () => {
  it("dials the pinned address and verifies TLS against the logical hostname", async () => {
    const adapter = adapterFor("postgresql");
    await adapter.connect(opts());
    const cfg = pgClientConfigs[0] as PgConfig;
    expect(cfg.host).toBe("203.0.113.7");
    expect(cfg.ssl).toMatchObject({ rejectUnauthorized: true, servername: "db.example.com" });
  });

  it("sets no servername when the target was not pinned (literal IP)", async () => {
    const adapter = adapterFor("postgresql");
    await adapter.connect(opts({ host: "8.8.8.8", address: "8.8.8.8" }));
    const cfg = pgClientConfigs[0] as PgConfig;
    expect(cfg.host).toBe("8.8.8.8");
    expect(cfg.ssl).not.toBe(false);
    expect(cfg.ssl).not.toHaveProperty("servername");
  });

  it("still dials the pinned address with TLS disabled", async () => {
    const adapter = adapterFor("postgresql");
    await adapter.connect(opts({ tls: false }));
    const cfg = pgClientConfigs[0] as PgConfig;
    expect(cfg.host).toBe("203.0.113.7");
    expect(cfg.ssl).toBe(false);
  });

  it("a signal aborted while pg loads: VAULT_LOCKED, no client built", async () => {
    const controller = new AbortController();
    const suiteModule = await import("pg");
    vi.doMock("pg", () => {
      controller.abort();
      return suiteModule;
    });
    try {
      await expectVaultError(
        () => adapterFor("postgresql").connect(opts({ signal: controller.signal })),
        ErrorCode.VAULT_LOCKED,
      );
      expect(pgClientConfigs.length).toBe(0);
    } finally {
      vi.doMock("pg", () => suiteModule);
    }
  });

  it("a live signal connects as before", async () => {
    await adapterFor("postgresql").connect(opts({ signal: new AbortController().signal }));
    expect(pgClientConfigs.length).toBe(1);
  });
});

describe("MysqlAdapter connection config", () => {
  it("keeps the logical hostname for TLS and dials the pin via the stream factory", async () => {
    const adapter = adapterFor("mysql");
    await adapter.connect(opts({ port: 3306 }));
    const cfg = mysqlConfigs[0] as MysqlConfig;
    expect(cfg.host).toBe("db.example.com");
    expect(cfg.ssl).toMatchObject({ rejectUnauthorized: true, verifyIdentity: true });
    expect(typeof cfg.stream).toBe("function");

    (cfg.stream as () => unknown)();
    expect(netConnectCalls[0]).toEqual([3306, "203.0.113.7"]);
    expect(setNoDelay).toHaveBeenCalledWith(true);
  });

  // M3: an IP-literal target used to skip both the stream factory and
  // `verifyIdentity` — and without the latter mysql2 replaces
  // checkServerIdentity with a no-op, so the certificate name was never checked
  // at all. Identity verification is unconditional now, and the socket carries
  // the logical host so Node checks against the actual target.
  it("verifies the certificate identity for a literal-IP target too", async () => {
    const adapter = adapterFor("mysql");
    await adapter.connect(opts({ host: "8.8.8.8", address: "8.8.8.8", port: 3306 }));
    const cfg = mysqlConfigs[0] as MysqlConfig;
    expect(cfg.host).toBe("8.8.8.8");
    expect(cfg.ssl).toMatchObject({ rejectUnauthorized: true, verifyIdentity: true });
    expect(typeof cfg.stream).toBe("function");

    (cfg.stream as () => unknown)();
    expect(netConnectCalls[0]).toEqual([3306, "8.8.8.8"]);
  });

  it("still dials the pinned address with TLS disabled", async () => {
    const adapter = adapterFor("mysql");
    await adapter.connect(opts({ port: 3306, tls: false }));
    const cfg = mysqlConfigs[0] as MysqlConfig;
    expect(cfg.ssl).toBeUndefined();
    expect(typeof cfg.stream).toBe("function");
    (cfg.stream as () => unknown)();
    expect(netConnectCalls[0]).toEqual([3306, "203.0.113.7"]);
  });

  it("a signal aborted while mysql2 loads: VAULT_LOCKED, no connection created", async () => {
    const controller = new AbortController();
    const suiteModule = await import("mysql2/promise");
    vi.doMock("mysql2/promise", () => {
      controller.abort();
      return suiteModule;
    });
    try {
      await expectVaultError(
        () => adapterFor("mysql").connect(opts({ port: 3306, signal: controller.signal })),
        ErrorCode.VAULT_LOCKED,
      );
      expect(mysqlConfigs.length).toBe(0);
    } finally {
      vi.doMock("mysql2/promise", () => suiteModule);
    }
  });

  it("a live signal connects as before", async () => {
    await adapterFor("mysql").connect(opts({ port: 3306, signal: new AbortController().signal }));
    expect(mysqlConfigs.length).toBe(1);
  });
});
