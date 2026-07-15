import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DatabaseAction, InjectionPolicy } from "@harpoc/shared";
import { DatabaseInjector } from "./database-injector.js";

// Driver mocks capture the connection config the real adapters assemble; no
// live connection is made. Unlike database-injector.test.ts (MockAdapter seam,
// which stops at the injector→adapter boundary), this suite composes the
// injector with the REAL adapters so the default TLS posture is asserted where
// it matters: in the driver config (code review 2026-07-07, M13).
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

const mysqlConfigs: unknown[] = [];
vi.mock("mysql2/promise", () => ({
  createConnection: vi.fn((cfg: unknown) => {
    mysqlConfigs.push(cfg);
    return Promise.resolve({
      query: vi.fn().mockResolvedValue([[{ ok: 1 }], [{ name: "ok" }]]),
      end: vi.fn().mockResolvedValue(undefined),
    });
  }),
}));

const SECRET = new Uint8Array(Buffer.from("dbuser:dbpass"));
const CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIBpinned\n-----END CERTIFICATE-----";

function policy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return {
    url_allowlist: [],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
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

interface TlsConfig {
  ssl?: false | { rejectUnauthorized?: boolean; ca?: string };
}

describe("DatabaseInjector default TLS posture through the real adapters", () => {
  const injector = new DatabaseInjector(null);

  beforeEach(() => {
    pgClientConfigs.length = 0;
    mysqlConfigs.length = 0;
  });

  it("pg: the default policy reaches the driver as rejectUnauthorized:true", async () => {
    const result = await injector.executeWithSecret(action(), SECRET, policy(), undefined);
    expect(result.row_count).toBe(1);

    const cfg = pgClientConfigs[0] as TlsConfig;
    expect(cfg.ssl).toMatchObject({ rejectUnauthorized: true });
  });

  it("pg: a pinned CA is forwarded end-to-end alongside certificate verification", async () => {
    await injector.executeWithSecret(action(), SECRET, policy(), {
      database: { tls_mode: "require", ca_pem: CA_PEM },
    });

    const cfg = pgClientConfigs[0] as TlsConfig;
    expect(cfg.ssl).toMatchObject({ rejectUnauthorized: true, ca: CA_PEM });
  });

  it("mysql: the default policy reaches the driver as rejectUnauthorized:true", async () => {
    const result = await injector.executeWithSecret(
      action({ engine: "mysql" }),
      SECRET,
      policy(),
      undefined,
    );
    expect(result.row_count).toBe(1);

    const cfg = mysqlConfigs[0] as TlsConfig;
    expect(cfg.ssl).toMatchObject({ rejectUnauthorized: true });
  });

  it("mysql: a pinned CA is forwarded end-to-end alongside certificate verification", async () => {
    await injector.executeWithSecret(action({ engine: "mysql" }), SECRET, policy(), {
      database: { tls_mode: "require", ca_pem: CA_PEM },
    });

    const cfg = mysqlConfigs[0] as TlsConfig;
    expect(cfg.ssl).toMatchObject({ rejectUnauthorized: true, ca: CA_PEM });
  });
});
