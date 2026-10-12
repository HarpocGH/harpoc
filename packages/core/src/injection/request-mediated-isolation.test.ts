import { spawn } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DatabaseAction, InjectionPolicy } from "@harpoc/shared";
import { DatabaseInjector } from "./database-injector.js";
import type { DbEngineAdapter } from "./db-adapters.js";
import { forceFsIsolationUnavailableForTests } from "./fs-isolation.js";
import { HttpInjector } from "./http-injector.js";
import { requireIsolation } from "./isolation.js";
import { forceNetworkIsolationUnavailableForTests } from "./network-isolation.js";
import { spawnCaptured } from "./spawn-captured.js";

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});
vi.mock("./isolation.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./isolation.js")>();
  return { ...actual, requireIsolation: vi.fn(actual.requireIsolation) };
});
vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn(actual.spawnCaptured) };
});

const SECRET = new Uint8Array(Buffer.from("rm-isolation-secret-123456", "utf8"));

const ISOLATED: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: [],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: true,
  fs_isolation: true,
  smtp_recipient_allowlist: [],
  imap_read_only: false,
  strict_tree_exit: false,
};

function expectNoSpawnSeamTouched(): void {
  expect(vi.mocked(requireIsolation)).not.toHaveBeenCalled();
  expect(vi.mocked(spawnCaptured)).not.toHaveBeenCalled();
  expect(vi.mocked(spawn)).not.toHaveBeenCalled();
}

// "Request-mediated actions spawn no child and are unaffected" by the isolation flags
// (isolation-spawn.md, M-T2a-6): both tiers are forced unavailable, so a context that
// consulted the composer would refuse, and the spawn seams are spies over the real ones.
describe("request-mediated contexts spawn no child under the isolation flags (M-T2a-6; MCP-over-HTTP in mcp-injector.isolation.test.ts)", () => {
  beforeEach(() => {
    vi.mocked(requireIsolation).mockClear();
    vi.mocked(spawnCaptured).mockClear();
    vi.mocked(spawn).mockClear();
    forceNetworkIsolationUnavailableForTests("forced: no network tier");
    forceFsIsolationUnavailableForTests("forced: no filesystem tier");
  });

  afterEach(() => {
    forceNetworkIsolationUnavailableForTests(null);
    forceFsIsolationUnavailableForTests(null);
  });

  // The http injector takes no policy: the engine's http arm hands it none of the flags.
  it("http: a loopback request answers 200 and touches no spawn seam", async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    try {
      const result = await new HttpInjector(null).executeWithSecret(
        { method: "GET", url: `http://127.0.0.1:${port}/` },
        SECRET,
        { type: "bearer" },
      );
      expect(result.status).toBe(200);
      expectNoSpawnSeamTouched();
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("database: a query under both flags succeeds and touches no spawn seam", async () => {
    const adapter: DbEngineAdapter = {
      connect: async () => ({
        query: async () => ({ rows: [{ ok: 1 }], fields: [{ name: "ok" }], rowCount: 1 }),
        end: async () => undefined,
      }),
    };
    const action: DatabaseAction = {
      type: "database",
      engine: "postgresql",
      host: "8.8.8.8",
      database: "app",
      query: "SELECT 1",
    };
    const result = await new DatabaseInjector(null, { postgresql: adapter }).executeWithSecret(
      action,
      new Uint8Array(Buffer.from("dbuser:dbpassword", "utf8")),
      { ...ISOLATED, host_allowlist: ["8.8.8.8"] },
      undefined,
    );
    expect(result).toMatchObject({ type: "database", row_count: 1 });
    expectNoSpawnSeamTouched();
  });
});
