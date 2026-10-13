import tls from "node:tls";
import type { ConnectionOptions, PeerCertificate } from "node:tls";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import type { DatabaseAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";

// The .pinning partial mock: the logical host validates and pins to the
// loopback listener; every other host goes through the real validator.
vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return {
    ...actual,
    validateHostPort: vi.fn(async (host: string, port: number) => {
      if (host === "db.pinned.test") {
        return { host, port, resolvedAddress: "127.0.0.1" };
      }
      return actual.validateHostPort(host, port);
    }),
  };
});

import { DatabaseInjector } from "./database-injector.js";
import type { DbTlsEngine, DbTlsServer } from "./__fixtures__/db-tls-servers.js";
import { FIXTURE_CERT_PEM, FIXTURE_NAME, startDbTlsServer } from "./__fixtures__/db-tls-servers.js";

const SECRET = new Uint8Array(Buffer.from("dbuser:dbpass"));
const LOGICAL = "db.pinned.test";

const POLICY: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: [],
  env_allowlist: [],
  host_allowlist: [LOGICAL, "127.0.0.1"],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: false,
  fs_isolation: false,
  smtp_recipient_allowlist: [],
  imap_read_only: false,
  strict_tree_exit: false,
};

function action(engine: DbTlsEngine, host: string, port: number): DatabaseAction {
  const base = { type: "database" as const, engine, host, port, timeout_ms: 2_000 };
  if (engine === "redis") return { ...base, database: "0", command: ["PING"] };
  if (engine === "mongodb") return { ...base, database: "app", command: { ping: 1 } };
  return { ...base, database: "app", query: "SELECT 1" };
}

const certFor = (name: string): PeerCertificate =>
  ({ subject: { CN: name }, subjectaltname: `DNS:${name}` }) as unknown as PeerCertificate;

/**
 * I16 (test-review-2026-10-09): `database.servername` is the TLS identity —
 * the SNI name and the certificate-verification name — in place of the
 * logical host, through all four real drivers. A `node:tls` `connect` spy
 * reads what each driver hands Node; the loopback listener presents a leaf
 * for the override only and records the SNI it received.
 */
describe("database.servername — the TLS identity override (I16)", () => {
  const injector = new DatabaseInjector(null);
  const servers = new Map<DbTlsEngine, DbTlsServer>();
  let connectSpy: MockInstance<typeof tls.connect>;

  beforeAll(async () => {
    for (const engine of ["postgresql", "mysql", "redis", "mongodb"] as const) {
      servers.set(engine, await startDbTlsServer(engine));
    }
  });

  afterAll(async () => {
    for (const server of servers.values()) await server.close();
  });

  afterEach(() => {
    connectSpy.mockRestore();
  });

  const sentOptions = (): ConnectionOptions[] =>
    connectSpy.mock.calls.map((call) => call[0] as ConnectionOptions);

  it.each([
    ["postgresql", ErrorCode.DB_CONNECTION_FAILED],
    ["mysql", ErrorCode.DB_CONNECTION_FAILED],
    ["redis", "database"],
    ["mongodb", ErrorCode.DB_QUERY_FAILED],
  ] as const)(
    "%s: a pinned logical host with the override sends it as SNI and verifies the certificate by it",
    async (engine, code) => {
      const server = servers.get(engine) as DbTlsServer;
      server.sni.length = 0;
      server.accepted = 0;
      connectSpy = vi.spyOn(tls, "connect");
      const outcome = await injector
        .executeWithSecret(action(engine, LOGICAL, server.port), SECRET, POLICY, {
          database: { ca_pem: FIXTURE_CERT_PEM, servername: FIXTURE_NAME },
        })
        .then(
          (result) => result.type,
          (err: unknown) => (err as { code?: string }).code,
        );
      expect(outcome).toBe(code);
      const sent = sentOptions();
      expect(sent.length).toBeGreaterThan(0);
      for (const options of sent) {
        expect(options.servername).toBe(FIXTURE_NAME);
        if (engine === "mysql") {
          // mysql's certificate-by-override check is carried by the control case below.
          expect(options.checkServerIdentity).toBe(tls.checkServerIdentity);
          continue;
        }
        const check = options.checkServerIdentity as (
          host: string,
          cert: PeerCertificate,
        ) => Error | undefined;
        expect(check(FIXTURE_NAME, certFor(FIXTURE_NAME))).toBeUndefined();
        expect(check(FIXTURE_NAME, certFor(LOGICAL))).toBeInstanceOf(Error);
      }
      expect(server.sni.length).toBeGreaterThan(0);
      expect(new Set(server.sni)).toEqual(new Set([FIXTURE_NAME]));
      expect(server.accepted).toBeGreaterThan(0);
    },
  );

  it("postgresql: an IP-literal target with the override now sends SNI and verifies by name", async () => {
    const server = servers.get("postgresql") as DbTlsServer;
    server.sni.length = 0;
    server.accepted = 0;
    connectSpy = vi.spyOn(tls, "connect");
    await expectVaultError(
      () =>
        injector.executeWithSecret(action("postgresql", "127.0.0.1", server.port), SECRET, POLICY, {
          database: { ca_pem: FIXTURE_CERT_PEM, servername: FIXTURE_NAME },
        }),
      ErrorCode.DB_CONNECTION_FAILED,
    );
    expect(sentOptions().map((options) => options.servername)).toEqual([FIXTURE_NAME]);
    expect(server.sni).toEqual([FIXTURE_NAME]);
    expect(server.accepted).toBe(1);
  });

  it("mysql: verifyIdentity checks the override — one the certificate does not name is refused before any byte crosses TLS", async () => {
    const server = servers.get("mysql") as DbTlsServer;
    server.sni.length = 0;
    server.accepted = 0;
    connectSpy = vi.spyOn(tls, "connect");
    await expectVaultError(
      () =>
        injector.executeWithSecret(action("mysql", LOGICAL, server.port), SECRET, POLICY, {
          database: { ca_pem: FIXTURE_CERT_PEM, servername: "other.example.com" },
        }),
      ErrorCode.DB_CONNECTION_FAILED,
    );
    expect(sentOptions().map((options) => options.servername)).toEqual(["other.example.com"]);
    expect(server.accepted).toBe(0);
  });
});
