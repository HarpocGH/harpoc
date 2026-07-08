import { describe, expect, it, vi } from "vitest";
import type { DatabaseAction, InjectionPolicy } from "@harpoc/shared";
import type { DbConnectOptions, DbConnection, DbEngineAdapter } from "./db-adapters.js";

// Partial mock: hostnames under *.pinned.test validate successfully and pin to
// a fixed public test address; everything else uses the real validator. The
// .test TLD never resolves in real DNS — the adapter can only receive an IP if
// the injector forwards the address from the pre-flight validation.
vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return {
    ...actual,
    validateHostPort: vi.fn(async (host: string, port: number) => {
      if (host.endsWith(".pinned.test")) {
        return { host, port, resolvedAddress: "203.0.113.7" };
      }
      return actual.validateHostPort(host, port);
    }),
  };
});

import { DatabaseInjector } from "./database-injector.js";

class CapturingAdapter implements DbEngineAdapter {
  lastConnect: DbConnectOptions | undefined;

  connect(opts: DbConnectOptions): Promise<DbConnection> {
    this.lastConnect = opts;
    return Promise.resolve({
      query: () => Promise.resolve({ rows: [], fields: [], rowCount: 0 }),
      end: () => Promise.resolve(),
    });
  }
}

const SECRET = new Uint8Array(Buffer.from("admin:s3cr3t"));

const POLICY: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: [],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
};

function action(overrides: Partial<DatabaseAction> = {}): DatabaseAction {
  return {
    type: "database",
    engine: "postgresql",
    host: "db.pinned.test",
    database: "app",
    query: "SELECT 1",
    ...overrides,
  };
}

describe("database DNS-rebinding pinning", () => {
  it("dials the address resolved at validation time, never the raw hostname", async () => {
    const adapter = new CapturingAdapter();
    const inj = new DatabaseInjector(null, { postgresql: adapter, mysql: adapter });
    await inj.executeWithSecret(action(), SECRET, POLICY, undefined);
    expect(adapter.lastConnect?.address).toBe("203.0.113.7");
    expect(adapter.lastConnect?.host).toBe("db.pinned.test");
  });

  it("matches the host allowlist on the logical hostname while dialing the pin", async () => {
    const adapter = new CapturingAdapter();
    const inj = new DatabaseInjector(null, { postgresql: adapter, mysql: adapter });
    const allowed: InjectionPolicy = { ...POLICY, host_allowlist: ["db.pinned.test:5432"] };
    await inj.executeWithSecret(action(), SECRET, allowed, undefined);
    expect(adapter.lastConnect?.address).toBe("203.0.113.7");
  });
});
