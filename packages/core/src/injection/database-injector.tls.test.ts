import { createServer } from "node:net";
import type { AddressInfo, Server, Socket } from "node:net";
import type { PeerCertificate } from "node:tls";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
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
  ssl?:
    | false
    | {
        rejectUnauthorized?: boolean;
        ca?: string;
        verifyIdentity?: boolean;
        servername?: string;
        checkServerIdentity?: (host: string, cert: PeerCertificate) => Error | undefined;
      };
  stream?: () => Socket;
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

/**
 * M3. Server-identity verification was conditional on the target being a
 * hostname (`opts.address !== opts.host`). For an IP-literal target mysql2
 * received no `verifyIdentity`, swapped `checkServerIdentity` for a no-op and
 * never verified the certificate name — so any certificate from any trusted CA
 * was accepted and a pinned `ca_pem` degraded from "this endpoint" to "anything
 * holding a cert from this CA". `rejectUnauthorized` alone only checks the
 * chain, never the name.
 */
describe("database TLS server-identity binding (M3)", () => {
  const injector = new DatabaseInjector(null);
  let echo: Server;
  let echoPort: number;

  beforeAll(async () => {
    // A real listener so the mysql stream factory can be exercised.
    echo = createServer((s) => s.end());
    await new Promise<void>((r) => echo.listen(0, "127.0.0.1", () => r()));
    echoPort = (echo.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((r) => echo.close(() => r()));
  });

  beforeEach(() => {
    pgClientConfigs.length = 0;
    mysqlConfigs.length = 0;
  });

  it("mysql: an IP-literal target still verifies the certificate identity", async () => {
    await injector.executeWithSecret(
      action({ engine: "mysql", host: "8.8.8.8" }),
      SECRET,
      policy(),
    );

    const cfg = mysqlConfigs[0] as TlsConfig;
    expect(cfg.ssl).toMatchObject({ rejectUnauthorized: true, verifyIdentity: true });
  });

  it("mysql: the socket presents the logical host, so Node checks the right name", async () => {
    await injector.executeWithSecret(
      action({ engine: "mysql", host: `127.0.0.1:${echoPort}` }),
      SECRET,
      policy(),
    );

    const cfg = mysqlConfigs[0] as TlsConfig;
    expect(typeof cfg.stream).toBe("function");
    const socket = (cfg.stream as () => Socket)();
    try {
      // Node derives the verified name as
      // `servername || options.host || socket._host || "localhost"`, and mysql2
      // supplies no servername for an IP literal. Without this binding the
      // check would run against "localhost" — net.connect leaves `_host` unset
      // when dialing an IP (verified against Node v24.13.1).
      expect((socket as Socket & { _host?: string })._host).toBe("127.0.0.1");
    } finally {
      socket.destroy();
    }
  });

  it("pg: the identity check is bound to the logical host, not Node's default", async () => {
    await injector.executeWithSecret(action({ host: "8.8.8.8" }), SECRET, policy());

    const cfg = pgClientConfigs[0] as TlsConfig;
    const ssl = cfg.ssl as {
      checkServerIdentity: (h: string, c: PeerCertificate) => Error | undefined;
    };
    expect(typeof ssl.checkServerIdentity).toBe("function");

    // A certificate for an unrelated name must be refused even though Node's
    // own derivation for an IP-literal dial would have said "localhost".
    const foreign = { subject: { CN: "localhost" }, subjectaltname: "DNS:localhost" };
    expect(
      ssl.checkServerIdentity("localhost", foreign as unknown as PeerCertificate),
    ).toBeInstanceOf(Error);

    const matching = { subject: { CN: "8.8.8.8" }, subjectaltname: "IP Address:8.8.8.8" };
    expect(
      ssl.checkServerIdentity("localhost", matching as unknown as PeerCertificate),
    ).toBeUndefined();
  });

  it("control: tls_mode disable still opts out entirely", async () => {
    await injector.executeWithSecret(
      action({ engine: "mysql", host: "8.8.8.8" }),
      SECRET,
      policy(),
      {
        database: { tls_mode: "disable" },
      },
    );
    expect((mysqlConfigs[0] as TlsConfig).ssl).toBeUndefined();

    await injector.executeWithSecret(action({ host: "8.8.8.8" }), SECRET, policy(), {
      database: { tls_mode: "disable" },
    });
    expect((pgClientConfigs[0] as TlsConfig).ssl).toBe(false);
  });
});
