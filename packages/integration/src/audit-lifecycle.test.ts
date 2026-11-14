import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { VaultEngine } from "@harpoc/core";
import type { DecryptedAuditEvent } from "@harpoc/core";
import { createMcpServer } from "@harpoc/mcp-server";
import { createApp } from "@harpoc/rest-api";
import { RestClient } from "@harpoc/sdk";
import {
  AuditEventType,
  ErrorCode,
  SESSION_FILE_NAME,
  SecretType,
  VAULT_DB_NAME,
} from "@harpoc/shared";
import {
  createTestVault,
  destroyTestVault,
  grantOn,
  registerAgents,
} from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";
import {
  CLI_ENTRY,
  freePort,
  runCli,
  runCommand,
  startCliServer,
  startCliServerOnFreePort,
  startNode,
  type CliServer,
} from "./helpers/spawn-cli.js";
import {
  connectInMemoryClient,
  connectModernInMemoryClient,
  silenceAuditLines,
  expectVaultError,
} from "@harpoc/test-utils";

silenceAuditLines();

const PASSWORD = "audit-lifecycle-pw";
const VALUE = new Uint8Array(Buffer.from("lifecycle-value"));

// R4/D67 and E75i through the real binary: the CLI process writes the rows,
// an in-process engine on the same vault reads them back.
describe("server lifecycle rows through the spawned CLI", () => {
  let vaultDir: string;
  let engine: VaultEngine | undefined;

  beforeAll(async () => {
    vaultDir = mkdtempSync(join(tmpdir(), "harpoc-lifecycle-"));
    const init = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    try {
      await init.initVault(PASSWORD);
    } finally {
      await init.destroy();
    }
    const unlock = await runCli(["unlock"], {
      vaultDir,
      stdin: `${PASSWORD}\n`,
      timeoutMs: 110_000,
    });
    expect(unlock.code).toBe(0);
    engine = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    expect(await engine.loadSession()).toBe(true);
  }, 120_000);

  afterAll(async () => {
    await engine?.destroy();
    rmSync(vaultDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("stdin EOF is a graceful stop: a server.stop row with trigger transport_closed, exit 0", async () => {
    registerAgents(engine as VaultEngine, "eof-agent");
    const token = (engine as VaultEngine).createToken("eof-agent", ["read", "list"]);
    const tokenFile = join(vaultDir, "launch-token");
    writeFileSync(tokenFile, `${token}\n`, { encoding: "utf8", mode: 0o600 });
    const env = { ...process.env };
    delete env.HARPOC_TOKEN;
    const server = startCliServer(["server", "start", "--mcp", "--token-file", tokenFile], {
      vaultDir,
      stdin: "pipe",
      env,
    });
    try {
      await server.waitForStderr(/MCP server running on stdio/, 30_000);

      server.child.stdin?.end();
      const { code } = await server.closed();
      expect(code).toBe(0);
    } finally {
      await server.stop();
    }
    expect(server.stdoutSoFar()).toBe("");

    const start = (engine as VaultEngine)
      .queryAudit({ eventType: AuditEventType.SERVER_START })
      .find((r) => r.detail?.subject === "eof-agent");
    expect(start?.detail).toMatchObject({
      transport: "stdio",
      tokenless: false,
    });
    const stops = (engine as VaultEngine).queryAudit({ eventType: AuditEventType.SERVER_STOP });
    expect(stops).toHaveLength(1);
    expect(stops[0]?.detail).toMatchObject({
      transport: "stdio",
      tokenless: false,
      trigger: "transport_closed",
    });
    expect(stops[0]?.principal_type).toBeNull();
    expect((engine as VaultEngine).verifyAuditChain().valid).toBe(true);
  }, 60_000);

  it("a REST request's socket peer lands in ip_address (E75i)", async () => {
    registerAgents(engine as VaultEngine, "ip-agent");
    await (engine as VaultEngine).createSecret({
      name: "ip-key",
      type: SecretType.API_KEY,
      value: VALUE,
    });
    await grantOn(engine as VaultEngine, "secret://ip-key", "ip-agent", ["read", "list"]);
    const token = (engine as VaultEngine).createToken("ip-agent", ["read", "list", "admin"]);

    const { server, port } = await startCliServerOnFreePort(
      (p) => ["server", "start", "--rest", "--port", String(p)],
      { vaultDir },
    );
    try {
      const auth = { Authorization: `Bearer ${token}` };
      const info = await fetch(`http://127.0.0.1:${String(port)}/api/v1/secrets/ip-key`, {
        headers: auth,
      });
      expect(info.status).toBe(200);

      const audit = await fetch(
        `http://127.0.0.1:${String(port)}/api/v1/audit?event_type=secret.read`,
        { headers: auth },
      );
      expect(audit.status).toBe(200);
      const rows = (
        (await audit.json()) as {
          data: Array<{
            principal_id: string | null;
            ip_address: string | null;
          }>;
        }
      ).data;
      const mine = rows.filter((r) => r.principal_id === "ip-agent");
      expect(mine.length).toBeGreaterThan(0);
      for (const row of mine) expect(row.ip_address).toBe("127.0.0.1");

      const restStart = (engine as VaultEngine)
        .queryAudit({ eventType: AuditEventType.SERVER_START })
        .find((r) => r.detail?.transport === "rest");
      expect(restStart?.detail).toMatchObject({ tokenless: false, port });
    } finally {
      await server.stop();
    }
  }, 60_000);

  // D9/R26: the start row is written after the bind now, so a bind that fails
  // leaves nothing behind and the operator gets the error instead of an
  // unhandled 'error' event killing the process mid-start.
  it("a REST start on an occupied port leaves no start row and reports the bind error", async () => {
    const port = await freePort();
    const blocker = createServer();
    await new Promise<void>((resolve) => blocker.listen(port, "127.0.0.1", () => resolve()));
    const server = startCliServer(["server", "start", "--rest", "--port", String(port)], {
      vaultDir,
    });
    try {
      const { code } = await server.closed();
      expect(code).not.toBe(0);
      expect(server.stderrSoFar()).toMatch(/EADDRINUSE/);
    } finally {
      await server.stop();
      await new Promise<void>((resolve) => blocker.close(() => resolve()));
    }

    const starts = (engine as VaultEngine)
      .queryAudit({ eventType: AuditEventType.SERVER_START })
      .filter((r) => r.detail?.port === port);
    expect(starts).toHaveLength(0);
    expect((engine as VaultEngine).verifyAuditChain().valid).toBe(true);
  }, 60_000);
});

// D7 over the REST wire: an unknown-handle probe on a route that resolves
// before its id-addressed call leaves an attributed row; an ambiguous handle
// reads like an unknown one to a grantless token and stays 409 to a holder.
describe("unknown-handle probes and ambiguity over the REST wire", () => {
  let vault: TestVault;
  let app: ReturnType<typeof createApp>;

  const auth = (token: string) => ({ authorization: `Bearer ${token}`, host: "localhost" });

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "probe-agent", "holder");
    app = createApp(vault.engine);
  });

  afterAll(async () => {
    await destroyTestVault(vault);
  });

  it("an unknown handle on the oauth status route writes an attributed failed secret.read row", async () => {
    const token = vault.engine.createToken("probe-agent", ["read", "list"]);
    const res = await app.request("/api/v1/oauth/ghost/status", {
      headers: auth(token),
    });
    expect(res.status).toBe(404);

    const row = vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find((r) => !r.success && r.principal_id === "probe-agent");
    expect(row?.detail).toMatchObject({
      handle: "secret://ghost",
      error: ErrorCode.SECRET_NOT_FOUND,
      interface: "rest",
    });
  });

  // D3/R19: the six routes whose semantics are not a read pass their own event
  // type to resolveSecretId, so an operator filtering `--event secret.read` no
  // longer sees a renewal attempt, and `--event cert.renew` finally does.
  it("an unknown handle on the certificate renew route writes a failed cert.renew row, not a read", async () => {
    const token = vault.engine.createToken("probe-agent", ["rotate"]);
    const res = await app.request("/api/v1/certificates/ghost-cert/renew", {
      method: "POST",
      headers: auth(token),
    });
    expect(res.status).toBe(404);

    const renew = vault.engine
      .queryAudit({ eventType: AuditEventType.CERT_RENEW })
      .find((r) => !r.success && r.principal_id === "probe-agent");
    expect(renew?.detail).toMatchObject({
      handle: "secret://ghost-cert",
      error: ErrorCode.SECRET_NOT_FOUND,
      interface: "rest",
    });
    const reads = vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((r) => r.detail?.handle === "secret://ghost-cert");
    expect(reads).toHaveLength(0);
  });

  it("two revoked secrets of one name: a grantless token reads the unknown-handle 404, a holder reads 409", async () => {
    await vault.engine.createSecret({
      name: "twice",
      type: SecretType.API_KEY,
      value: VALUE,
    });
    await grantOn(vault.engine, "secret://twice", "holder", ["read"]);
    await vault.engine.revokeSecret("secret://twice");
    await vault.engine.createSecret({
      name: "twice",
      type: SecretType.API_KEY,
      value: VALUE,
    });
    await vault.engine.revokeSecret("secret://twice");

    const grantless = vault.engine.createToken("probe-agent", ["read", "list"]);
    const ambiguous = await app.request("/api/v1/secrets/twice", {
      headers: auth(grantless),
    });
    expect(ambiguous.status).toBe(404);
    const body = (await ambiguous.json()) as { error: string; message: string };
    expect(body.error).toBe(ErrorCode.SECRET_NOT_FOUND);
    expect(body.message).toBe("Secret not found: secret://twice");

    const holder = vault.engine.createToken("holder", ["read", "list"]);
    const kept = await app.request("/api/v1/secrets/twice", {
      headers: auth(holder),
    });
    expect(kept.status).toBe(409);

    const row = vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find(
        (r) =>
          !r.success && r.principal_id === "probe-agent" && r.detail?.handle === "secret://twice",
      );
    expect(row?.detail?.error).toBe(ErrorCode.AMBIGUOUS_HANDLE);
  });

  it("a policy revoke leaves no NULL-principal access_policies read row (E75a fallout)", async () => {
    await vault.engine.createSecret({
      name: "revocable",
      type: SecretType.API_KEY,
      value: VALUE,
    });
    await grantOn(vault.engine, "secret://revocable", "revoker", ["admin"]);
    const doomed = await grantOn(vault.engine, "secret://revocable", "grantee", ["read"]);
    const token = vault.engine.createToken("revoker", ["admin"]);

    const res = await app.request(`/api/v1/secrets/revocable/policies/${doomed.id}`, {
      method: "DELETE",
      headers: auth(token),
    });
    expect(res.status).toBe(200);

    const unattributed = vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((r) => r.principal_type === null && r.detail?.config === "access_policies");
    expect(unattributed).toHaveLength(0);

    const revoked = vault.engine
      .queryAudit({ eventType: AuditEventType.POLICY_REVOKE })
      .find((r) => r.detail?.policy_id === doomed.id);
    expect(revoked?.principal_type).toBe("agent");
    expect(revoked?.principal_id).toBe("revoker");
  });

  it("a cross-secret policy revoke over REST is refused POLICY_NOT_FOUND before the caller check, with one failed policy.revoke row on the probed policy's own secret that names neither the policy nor the prober's secret", async () => {
    await vault.engine.createSecret({ name: "own", type: SecretType.API_KEY, value: VALUE });
    await vault.engine.createSecret({ name: "other", type: SecretType.API_KEY, value: VALUE });
    const target = await grantOn(vault.engine, "secret://other", "grantee", ["read"]);
    await grantOn(vault.engine, "secret://own", "prober", ["admin"]);
    const token = vault.engine.createToken("prober", ["admin"]);

    const res = await app.request(`/api/v1/secrets/own/policies/${target.id}`, {
      method: "DELETE",
      headers: auth(token),
    });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe(ErrorCode.POLICY_NOT_FOUND);

    const ownId = await vault.engine.resolveSecretId("secret://own");
    const probed = vault.engine
      .queryAudit({ eventType: AuditEventType.POLICY_REVOKE })
      .filter((r) => r.principal_id === "prober");
    const serialized = JSON.stringify(probed.map((r) => r.detail));
    expect(serialized.includes(target.id)).toBe(false);
    expect(serialized.includes(ownId)).toBe(false);
    expect(probed.map((r) => [r.success, r.secret_id, r.detail])).toEqual([
      [false, target.secret_id, { error: ErrorCode.POLICY_NOT_FOUND, interface: "rest" }],
    ]);
    expect(vault.engine.listPolicies(target.secret_id).some((p) => p.id === target.id)).toBe(true);
  });
});

const MCP_ENTRY = join(
  dirname(createRequire(import.meta.url).resolve("@harpoc/mcp-server/package.json")),
  "dist",
  "index.js",
);

// R23/D9: `harpoc server start --mcp` has had its stdin-EOF twin since R4/D67,
// but the standalone `harpoc-mcp` binary — the entry an MCP host actually
// launches — had no test of its own at all. Same shape as the CLI twin above:
// the built binary, the real banner, the row read back by an in-process engine.
describe("server lifecycle rows through the spawned harpoc-mcp binary", () => {
  let vaultDir: string;
  let engine: VaultEngine | undefined;
  let tokenFile: string;

  // Both pipes are drained from the first tick (R4, 2026-09-07): an undrained
  // stdout blocks the child once the pipe buffer fills and `close` then never
  // fires — the twin would hang to its timeout instead of failing. The bytes
  // are kept: a shutdown twin sends no request, so its stdout must stay empty.
  function spawnMcp(): CliServer {
    const env = { ...process.env };
    delete env.HARPOC_TOKEN;
    return startNode([MCP_ENTRY, "--vault-dir", vaultDir, "--token-file", tokenFile], {
      stdin: "pipe",
      env,
    });
  }

  async function awaitBanner(mcp: CliServer): Promise<void> {
    await mcp.waitForStderr(/Harpoc MCP server running on stdio/, 30_000);
  }

  beforeAll(async () => {
    vaultDir = mkdtempSync(join(tmpdir(), "harpoc-mcp-lifecycle-"));
    const init = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    try {
      await init.initVault(PASSWORD);
    } finally {
      await init.destroy();
    }
    // `harpoc-mcp` opens an existing session and refuses a locked vault, so the
    // twin unlocks through the CLI exactly as the one above does.
    const unlock = await runCli(["unlock"], {
      vaultDir,
      stdin: `${PASSWORD}\n`,
      timeoutMs: 110_000,
    });
    expect(unlock.code).toBe(0);
    engine = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    expect(await engine.loadSession()).toBe(true);
    registerAgents(engine, "mcp-eof-agent");
    const token = engine.createToken("mcp-eof-agent", ["read", "list"]);
    tokenFile = join(vaultDir, "launch-token");
    writeFileSync(tokenFile, `${token}\n`, { encoding: "utf8", mode: 0o600 });
  }, 120_000);

  afterAll(async () => {
    await engine?.destroy();
    rmSync(vaultDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("stdin EOF is a graceful stop: exit 0 and one transport_closed row", async () => {
    const mcp = spawnMcp();
    try {
      await awaitBanner(mcp);
      mcp.child.stdin?.end();
      const { code } = await mcp.closed();
      expect(code).toBe(0);
    } finally {
      await mcp.stop();
    }
    // No request was sent, so the JSON-RPC stream carried nothing.
    expect(mcp.stdoutSoFar()).toBe("");

    const start = (engine as VaultEngine)
      .queryAudit({ eventType: AuditEventType.SERVER_START })
      .find((r) => r.detail?.subject === "mcp-eof-agent");
    expect(start?.detail).toMatchObject({ transport: "stdio", tokenless: false });
    const stops = (engine as VaultEngine).queryAudit({ eventType: AuditEventType.SERVER_STOP });
    expect(stops).toHaveLength(1);
    expect(stops[0]?.detail).toMatchObject({
      transport: "stdio",
      tokenless: false,
      trigger: "transport_closed",
    });
    expect(stops[0]?.principal_type).toBeNull();
    expect((engine as VaultEngine).verifyAuditChain().valid).toBe(true);
  }, 60_000);

  // win32 `child.kill("SIGTERM")` terminates the process without delivering a
  // signal, so there is no handler to observe there.
  it.runIf(process.platform !== "win32")(
    "SIGTERM is a graceful stop: exit 0 and a SIGTERM row",
    async () => {
      const mcp = spawnMcp();
      try {
        await awaitBanner(mcp);
        mcp.child.kill("SIGTERM");
        const { code } = await mcp.closed();
        expect(code).toBe(0);
      } finally {
        await mcp.stop();
      }
      expect(mcp.stdoutSoFar()).toBe("");

      const stops = (engine as VaultEngine).queryAudit({ eventType: AuditEventType.SERVER_STOP });
      expect(stops.filter((r) => r.detail?.trigger === "SIGTERM")).toHaveLength(1);
      const sigterm = stops.find((r) => r.detail?.trigger === "SIGTERM");
      expect(sigterm?.detail).toMatchObject({ transport: "stdio", tokenless: false });
      expect((engine as VaultEngine).verifyAuditChain().valid).toBe(true);
    },
    60_000,
  );
});

interface SqliteHandle {
  prepare(sql: string): { get(...params: unknown[]): unknown };
}

interface ListedRow {
  id: number;
  event_type: string;
  principal_id: string | null;
}

interface ChildExit {
  code: number | null;
  stdout: string;
  stderr: string;
}

describe("the trail's own reads write one vault.read row per call on every interface (A3)", () => {
  let vaultDir: string;
  let engine: VaultEngine | undefined;
  let server: TestServer | undefined;
  let adminToken: string;
  let financeToken: string;
  let tokenFile: string;

  beforeAll(async () => {
    vaultDir = mkdtempSync(join(tmpdir(), "harpoc-trail-reads-"));
    const init = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    try {
      await init.initVault(PASSWORD);
    } finally {
      await init.destroy();
    }
    const unlock = await runCli(["unlock"], {
      vaultDir,
      stdin: `${PASSWORD}\n`,
      timeoutMs: 110_000,
    });
    expect(unlock.code).toBe(0);
    engine = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    expect(await engine.loadSession()).toBe(true);
    registerAgents(engine, "trail-admin", "finance-admin");
    for (const name of ["ledger", "payroll"]) {
      await engine.createSecret({
        name,
        type: SecretType.API_KEY,
        project: "finance",
        value: VALUE,
      });
    }
    await engine.createSecret({ name: "db-prod", type: SecretType.API_KEY, value: VALUE });
    adminToken = engine.createToken("trail-admin", ["admin"]);
    financeToken = engine.createToken("finance-admin", ["admin"], 3_600_000, {
      project: "finance",
    });
    tokenFile = join(vaultDir, "admin-token");
    writeFileSync(tokenFile, `${adminToken}\n`, { encoding: "utf8", mode: 0o600 });
    server = startTestServer(engine);
  }, 120_000);

  afterAll(async () => {
    await server?.close();
    await engine?.destroy();
    rmSync(vaultDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  function baseUrl(): string {
    return (server as TestServer).baseUrl;
  }

  function auditLog(): { count: number; newest: number } {
    const { db } = (engine as unknown as { store: { db: SqliteHandle } }).store;
    return db.prepare("SELECT COUNT(*) AS count, MAX(id) AS newest FROM audit_log").get() as {
      count: number;
      newest: number;
    };
  }

  function readsSince(mark: number): DecryptedAuditEvent[] {
    return (engine as VaultEngine)
      .queryAudit({ eventType: AuditEventType.VAULT_READ })
      .filter((r) => r.id > mark);
  }

  async function getAudit(token: string, query: string): Promise<ListedRow[]> {
    const res = await fetch(`${baseUrl()}/api/v1/audit${query}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    return ((await res.json()) as { data: ListedRow[] }).data;
  }

  function cliEnv(token?: string): NodeJS.ProcessEnv {
    const env = { ...process.env };
    delete env.HARPOC_TOKEN;
    if (token !== undefined) env.HARPOC_TOKEN = token;
    return env;
  }

  function local(args: string[], token?: string): Promise<ChildExit> {
    return runCommand(process.execPath, [CLI_ENTRY, "--vault-dir", vaultDir, ...args], {
      env: cliEnv(token),
    });
  }

  function overRest(args: string[]): Promise<ChildExit> {
    return runCommand(
      process.execPath,
      [CLI_ENTRY, "--url", baseUrl(), "--token-file", tokenFile, ...args],
      { env: cliEnv() },
    );
  }

  async function oneRead(
    run: () => Promise<ChildExit>,
  ): Promise<{ exit: ChildExit; before: number; row: DecryptedAuditEvent }> {
    const { count, newest } = auditLog();
    const exit = await run();
    expect(exit.code, exit.stderr).toBe(0);
    const rows = readsSince(newest);
    expect(rows).toHaveLength(1);
    return { exit, before: count, row: rows[0] as DecryptedAuditEvent };
  }

  it("REST GET /api/v1/audit writes one row after the read: the token's principal and peer, interface rest; the page does not hold it", async () => {
    const { newest } = auditLog();

    const page = await getAudit(adminToken, "?limit=5");

    const rows = readsSince(newest);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      secret_id: null,
      principal_type: "agent",
      principal_id: "trail-admin",
      ip_address: "127.0.0.1",
      success: true,
    });
    expect(rows[0]?.detail).toEqual({
      operation: "audit_query",
      count: 5,
      limit: 5,
      interface: "rest",
    });
    expect(page.every((r) => r.id <= newest)).toBe(true);
  });

  it("REST exclude_event_type=vault.read answers a page without read rows and records the exclusion on its own row", async () => {
    await getAudit(adminToken, "?limit=1");
    const { newest } = auditLog();

    const page = await getAudit(adminToken, "?exclude_event_type=vault.read");

    expect(page.length).toBeGreaterThan(0);
    expect(page.some((r) => r.event_type === AuditEventType.VAULT_READ)).toBe(false);
    expect(readsSince(newest).map((r) => r.detail)).toEqual([
      {
        operation: "audit_query",
        exclude_event_type: "vault.read",
        count: page.length,
        interface: "rest",
      },
    ]);
  });

  it("REST POST /api/v1/audit/verify writes audit_verify before the walk: checked counts it", async () => {
    const { count, newest } = auditLog();

    const res = await fetch(`${baseUrl()}/api/v1/audit/verify`, {
      method: "POST",
      headers: { Authorization: `Bearer ${adminToken}` },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { valid: boolean; checked: number } };
    expect(body.data).toMatchObject({ valid: true, checked: count + 1 });
    expect(readsSince(newest).map((r) => [r.principal_id, r.detail])).toEqual([
      ["trail-admin", { operation: "audit_verify", interface: "rest" }],
    ]);
  });

  it("a project-claimed admin's GET /api/v1/audit holds no vault.read row after an unscoped admin's query (A-2)", async () => {
    await getAudit(adminToken, "?limit=1");

    const pages = [await getAudit(financeToken, ""), await getAudit(financeToken, "")];

    for (const page of pages) {
      expect(page.length).toBeGreaterThan(0);
      expect(page.filter((r) => r.event_type === AuditEventType.VAULT_READ)).toEqual([]);
    }
    const reads = await getAudit(adminToken, "?event_type=vault.read&limit=3");
    expect(reads.map((r) => r.principal_id)).toEqual([
      "finance-admin",
      "finance-admin",
      "trail-admin",
    ]);
  });

  it("RestClient.queryAudit sends excludeEventType: no read row in the page, the exclusion on the row", async () => {
    const client = new RestClient({ baseUrl: baseUrl(), token: adminToken });
    await client.queryAudit({ limit: 1 });
    const { newest } = auditLog();

    const page = await client.queryAudit({ excludeEventType: AuditEventType.VAULT_READ });

    expect(page.length).toBeGreaterThan(0);
    expect(page.some((r) => r.event_type === AuditEventType.VAULT_READ)).toBe(false);
    expect(readsSince(newest).map((r) => r.detail)).toEqual([
      {
        operation: "audit_query",
        exclude_event_type: "vault.read",
        count: page.length,
        interface: "rest",
      },
    ]);
  });

  it("the CLI's local audit, verify and anchor each write one row with NULL principal columns and no interface key", async () => {
    const query = await oneRead(() =>
      local(["audit", "--json", "--limit", "3", "--exclude-event", "vault.read"]),
    );
    const page = JSON.parse(query.exit.stdout) as ListedRow[];
    expect(page).toHaveLength(3);
    expect(page.some((r) => r.event_type === AuditEventType.VAULT_READ)).toBe(false);
    expect([query.row.principal_type, query.row.principal_id, query.row.detail]).toEqual([
      null,
      null,
      { operation: "audit_query", exclude_event_type: "vault.read", count: 3, limit: 3 },
    ]);

    const verify = await oneRead(() => local(["audit", "verify", "--json"]));
    const report = JSON.parse(verify.exit.stdout) as { checked: number; tail: { last_id: number } };
    expect(report.checked).toBe(verify.before + 1);
    expect(report.tail.last_id).toBe(verify.row.id);
    expect([verify.row.principal_id, verify.row.detail]).toEqual([
      null,
      { operation: "audit_verify" },
    ]);

    const anchor = await oneRead(() => local(["audit", "anchor"]));
    expect((JSON.parse(anchor.exit.stdout) as { last_id: number }).last_id).toBe(anchor.row.id);
    expect([anchor.row.principal_id, anchor.row.detail]).toEqual([
      null,
      { operation: "audit_anchor" },
    ]);
  });

  it("under --token each writes it with the token's principal and the cli interface", async () => {
    const query = await oneRead(() => local(["audit", "--json", "--limit", "3"], adminToken));
    const verify = await oneRead(() => local(["audit", "verify", "--json"], adminToken));
    const anchor = await oneRead(() => local(["audit", "anchor"], adminToken));

    expect(
      [query, verify, anchor].map(({ row }) => [row.principal_type, row.principal_id, row.detail]),
    ).toEqual([
      ["agent", "trail-admin", { operation: "audit_query", count: 3, limit: 3, interface: "cli" }],
      ["agent", "trail-admin", { operation: "audit_verify", interface: "cli" }],
      ["agent", "trail-admin", { operation: "audit_anchor", interface: "cli" }],
    ]);
  });

  it("under --url the query and the verification write it through REST: the token's principal and peer, the rest interface", async () => {
    const query = await oneRead(() =>
      overRest(["audit", "--json", "--limit", "3", "--exclude-event", "vault.read"]),
    );
    const page = JSON.parse(query.exit.stdout) as ListedRow[];
    expect(page.some((r) => r.event_type === AuditEventType.VAULT_READ)).toBe(false);
    const verify = await oneRead(() => overRest(["audit", "verify", "--json"]));
    expect((JSON.parse(verify.exit.stdout) as { checked: number }).checked).toBe(verify.before + 1);

    expect(
      [query, verify].map(({ row }) => [row.principal_id, row.ip_address, row.detail]),
    ).toEqual([
      [
        "trail-admin",
        "127.0.0.1",
        {
          operation: "audit_query",
          exclude_event_type: "vault.read",
          count: 3,
          limit: 3,
          interface: "rest",
        },
      ],
      ["trail-admin", "127.0.0.1", { operation: "audit_verify", interface: "rest" }],
    ]);
  });
});

describe("the MCP server's refusals write their failed rows on a real engine (A7)", () => {
  let vault: TestVault;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "mcp-creator", "mcp-launcher");
  });

  afterAll(async () => {
    await destroyTestVault(vault);
  });

  function rowsOf(principalId: string, mark: number): DecryptedAuditEvent[] {
    return vault.engine
      .queryAudit({ principalId })
      .filter((row) => row.id > mark && row.detail?.operation !== "audit_query");
  }

  function newestId(): number {
    return Math.max(0, ...vault.engine.queryAudit({}).map((row) => row.id));
  }

  it.each(["modern", "legacy"] as const)(
    "create_secret on a taken name, %s leg: DUPLICATE_SECRET with the name check's vault.read row and one failed secret.create row, neither naming the secret",
    async (leg) => {
      const secretName = `taken-ledger-${leg}`;
      await vault.engine.createSecret({ name: secretName, type: SecretType.API_KEY });
      const launchToken = vault.engine.createToken("mcp-creator", ["create"]);
      const mark = newestId();
      const factory = () => createMcpServer({ engine: vault.engine, launchToken });
      const session =
        leg === "modern"
          ? await connectModernInMemoryClient(factory)
          : await connectInMemoryClient(factory());
      let text: string;
      try {
        const result = await session.callTool("create_secret", {
          name: secretName,
          type: "api_key",
        });
        expect(result.isError).toBe(true);
        text = result.content[0]?.text ?? "";
      } finally {
        await session.close();
      }

      expect(text.includes(`Secret already exists: ${secretName}`)).toBe(true);
      const rows = rowsOf("mcp-creator", mark);
      expect(JSON.stringify(rows.map((row) => row.detail)).includes(secretName)).toBe(false);
      expect(rows.map((row) => [row.event_type, row.success, row.secret_id, row.detail])).toEqual([
        [
          AuditEventType.SECRET_CREATE,
          false,
          null,
          { error: ErrorCode.DUPLICATE_SECRET, interface: "mcp" },
        ],
        [
          AuditEventType.VAULT_READ,
          true,
          null,
          { operation: "name_taken", found: true, interface: "mcp" },
        ],
      ]);
    },
  );

  it.each(["expired", "revoked", "forged"] as const)(
    "a stdio start with a launch token that is %s refuses and leaves one failed server.start row with the code alone — no token, no subject",
    async (kind) => {
      const issued = vault.engine.createToken("mcp-launcher", ["read"], 60_000);
      let launchToken = issued;
      let expected: ErrorCode = ErrorCode.INVALID_TOKEN;
      if (kind === "revoked") {
        vault.engine.revokeToken(vault.engine.verifyToken(issued).jti);
        expected = ErrorCode.TOKEN_REVOKED;
      } else if (kind === "forged") {
        const [header, payload, signature] = issued.split(".") as [string, string, string];
        launchToken = `${header}.${payload}.${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;
      } else {
        expected = ErrorCode.TOKEN_EXPIRED;
      }
      const mark = newestId();
      const pastExpiry = Date.now() + 120_000;

      if (kind === "expired") {
        vi.useFakeTimers({ toFake: ["Date"] });
        vi.setSystemTime(pastExpiry);
      }
      try {
        await expectVaultError(
          () => createMcpServer({ engine: vault.engine, launchToken }),
          expected,
        );
      } finally {
        vi.useRealTimers();
      }

      const starts = vault.engine
        .queryAudit({ eventType: AuditEventType.SERVER_START })
        .filter((row) => row.id > mark);
      const serialized = JSON.stringify(starts);
      expect(serialized.includes(launchToken)).toBe(false);
      expect(serialized.includes("mcp-launcher")).toBe(false);
      expect(starts.map((row) => [row.success, row.principal_id, row.detail])).toEqual([
        [false, null, { transport: "stdio", tokenless: false, tty_prompt: false, error: expected }],
      ]);
    },
  );
});
