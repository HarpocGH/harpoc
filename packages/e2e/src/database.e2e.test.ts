import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Permission } from "@harpoc/shared";
import { assertOpaque } from "./assert/opacity.js";
import { createHarnessVault, storeSecret } from "./harness/vault.js";
import type { HarnessVault } from "./harness/vault.js";
import { expectAttributedSuccess } from "./harness/audit.js";
import { recordArm } from "./harness/evidence.js";
import { startMcpHttpSurface } from "./harness/surfaces/mcp-http.js";
import type { McpHttpSurface } from "./harness/surfaces/mcp-http.js";
import { caPem } from "./harness/pki.js";
import { PG, assertFleetUp } from "./harness/backends.js";

const PASSWORD = "e2e-database-pw";
const DB_SECRET = `${PG.user}:${PG.password}`;

describe("database context — live PostgreSQL over fixture TLS", () => {
  let vault: HarnessVault;
  let surface: McpHttpSurface;
  let handle: string;

  beforeAll(async () => {
    assertFleetUp("postgres-tls");
    vault = await createHarnessVault(PASSWORD);
    handle = await storeSecret(vault, "pg-key", DB_SECRET);

    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [`${PG.host}:${PG.port}`],
    });
    await vault.engine.setConnectionConfig(handle, {
      database: { tls_mode: "require", ca_pem: caPem() },
    });

    surface = await startMcpHttpSurface(vault, "e2e-db-agent", [Permission.USE]);
  });

  afterAll(async () => {
    await surface?.close();
    await vault?.destroy();
  });

  it("executes a query against the live database and returns nothing readable as a credential", async () => {
    const outcome = await surface.callUseSecret(handle, {
      type: "database",
      engine: "postgresql",
      host: `${PG.host}:${PG.port}`,
      database: PG.database,
      query: "SELECT 42 AS answer",
    });

    expect(outcome.ok).toBe(true);
    // The query really ran against a real server over a real TLS handshake —
    // this is what no existing test in the repository can assert.
    expect(JSON.stringify(outcome.result)).toContain("42");

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    const observation = { result: outcome.result, auditRows, parentEnv: process.env };
    assertOpaque(DB_SECRET, observation);
    // Both halves: the password alone must not survive either.
    assertOpaque(PG.password, observation);

    const record = recordArm(
      { scenario: "database-happy-path", context: "database", surface: "mcp-http", arm: "harpoc" },
      "SUCCEEDED",
    );
    expect(record.match).toBe(true);
  });

  it("writes a successful audit row attributed to the mcp-http interface", () => {
    expectAttributedSuccess(vault, "database");
  });
});

describe("database context — M3: IP-literal targets have no name to verify", () => {
  let vault: HarnessVault;
  let surface: McpHttpSurface;
  let handle: string;

  beforeAll(async () => {
    assertFleetUp("postgres-tls");
    vault = await createHarnessVault(PASSWORD);
    handle = await storeSecret(vault, "pg-key-ip", DB_SECRET);

    // The IP literal is explicitly allowlisted: this arm must fail on identity
    // verification, not on the target allowlist, or it proves nothing.
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [`${PG.ip}:${PG.port}`],
    });
    await vault.engine.setConnectionConfig(handle, {
      database: { tls_mode: "require", ca_pem: caPem() },
    });

    surface = await startMcpHttpSurface(vault, "e2e-db-ip-agent", [Permission.USE]);
  });

  afterAll(async () => {
    await surface?.close();
    await vault?.destroy();
  });

  it("refuses an IP-literal target whose certificate carries no matching name", async () => {
    const outcome = await surface.callUseSecret(handle, {
      type: "database",
      engine: "postgresql",
      host: `${PG.ip}:${PG.port}`,
      database: PG.database,
      query: "SELECT 42 AS answer",
    });

    expect(outcome.ok).toBe(false);
    expect(JSON.stringify(outcome.result)).not.toContain("42");

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    const observation = { result: outcome.result, error: outcome.errorText, auditRows };
    assertOpaque(DB_SECRET, observation);
    assertOpaque(PG.password, observation);

    const record = recordArm(
      {
        scenario: "database-ip-literal-identity",
        context: "database",
        surface: "mcp-http",
        arm: "harpoc",
      },
      "REJECTED",
    );
    expect(record.match).toBe(true);
  });
});

describe("database context — a plaintext target is refused by default", () => {
  let vault: HarnessVault;
  let surface: McpHttpSurface;
  let handle: string;

  beforeAll(async () => {
    assertFleetUp("postgres-plain");
    vault = await createHarnessVault(PASSWORD);
    handle = await storeSecret(vault, "pg-key-plain", DB_SECRET);

    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [`${PG.host}:${PG.plainPort}`],
    });
    // No connection config at all: the DEFAULT posture is what is on trial.
    surface = await startMcpHttpSurface(vault, "e2e-db-plain-agent", [Permission.USE]);
  });

  afterAll(async () => {
    await surface?.close();
    await vault?.destroy();
  });

  it("does not fall back to an unencrypted connection", async () => {
    const outcome = await surface.callUseSecret(handle, {
      type: "database",
      engine: "postgresql",
      host: `${PG.host}:${PG.plainPort}`,
      database: PG.database,
      query: "SELECT 42 AS answer",
    });

    expect(outcome.ok).toBe(false);
    expect(JSON.stringify(outcome.result)).not.toContain("42");

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    const observation = { result: outcome.result, error: outcome.errorText, auditRows };
    assertOpaque(DB_SECRET, observation);
    assertOpaque(PG.password, observation);

    const record = recordArm(
      {
        scenario: "database-plaintext-target",
        context: "database",
        surface: "mcp-http",
        arm: "harpoc",
      },
      "REJECTED",
    );
    expect(record.match).toBe(true);
  });
});
