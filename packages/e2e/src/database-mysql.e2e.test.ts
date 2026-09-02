import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Permission } from "@harpoc/shared";
import { assertOpaque } from "./assert/opacity.js";
import { createHarnessVault, grantOn, storeSecret } from "./harness/vault.js";
import type { HarnessVault } from "./harness/vault.js";
import { recordArm } from "./harness/evidence.js";
import { startMcpHttpSurface } from "./harness/surfaces/mcp-http.js";
import type { McpHttpSurface } from "./harness/surfaces/mcp-http.js";
import { caPem } from "./harness/pki.js";
import { MYSQL, assertFleetUp } from "./harness/backends.js";

const PASSWORD = "e2e-mysql-pw";
const DB_SECRET = `${MYSQL.user}:${MYSQL.password}`;

/**
 * A second engine, because M3 is specifically a `mysql2` behaviour: it replaces
 * `checkServerIdentity` with a no-op unless `verifyIdentity` is set. A mocked
 * driver cannot exhibit that — only a real handshake can.
 */
describe("database context — live MySQL over fixture TLS", () => {
  let vault: HarnessVault;
  let surface: McpHttpSurface;
  let handle: string;

  beforeAll(async () => {
    assertFleetUp("mysql-tls");
    vault = await createHarnessVault(PASSWORD);
    handle = await storeSecret(vault, "mysql-key", DB_SECRET);

    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [`${MYSQL.host}:${MYSQL.port}`],
    });
    await vault.engine.setConnectionConfig(handle, {
      database: { tls_mode: "require", ca_pem: caPem() },
    });

    await grantOn(vault, handle, "e2e-mysql-agent", [Permission.USE]);

    surface = await startMcpHttpSurface(vault, "e2e-mysql-agent", [Permission.USE]);
  });

  afterAll(async () => {
    await surface?.close();
    await vault?.destroy();
  });

  it("executes a query and keeps the credential opaque", async () => {
    const outcome = await surface.callUseSecret(handle, {
      type: "database",
      engine: "mysql",
      host: `${MYSQL.host}:${MYSQL.port}`,
      database: MYSQL.database,
      query: "SELECT 42 AS answer",
    });

    expect(outcome.ok).toBe(true);
    expect(JSON.stringify(outcome.result)).toContain("42");

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    const observation = { result: outcome.result, auditRows, parentEnv: process.env };
    assertOpaque(DB_SECRET, observation);
    assertOpaque(MYSQL.password, observation);

    const record = recordArm(
      {
        scenario: "database-happy-path-mysql",
        context: "database",
        surface: "mcp-http",
        interface: "mcp",
        arm: "harpoc",
      },
      "SUCCEEDED",
    );
    expect(record.match).toBe(true);
  });
});
