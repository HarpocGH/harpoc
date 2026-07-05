import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { DirectClient } from "@harpoc/sdk";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

/**
 * Database context (thesis §4.5.5, §6.2 URL-manipulation analogue). Deterministic
 * enforcement: a prompt-injected redirect to an attacker host:port, or to a
 * private target, is rejected before any connection is opened. The baseline arm
 * (credential in a DSN, no vault) would reach the attacker endpoint; Harpoc
 * blocks. These are Tier-1 (scripted) enforcement tests — no live database.
 */

const PASSWORD = "integration-test-pw";
const DB_SECRET = "app_user:sk-db-secret-1234";

function dbAction(host: string) {
  return {
    type: "database" as const,
    engine: "postgresql" as const,
    host,
    database: "app",
    query: "SELECT 1",
  };
}

describe("Database context (request-mediated, §4.5.5)", () => {
  let vault: TestVault;
  let handle: string;
  let client: DirectClient;

  beforeEach(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    const created = await vault.engine.createSecret({
      name: "db-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from(DB_SECRET, "utf8")),
    });
    handle = created.handle;
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: ["db.internal:5432"],
    });
    await vault.engine.setConnectionConfig(handle, { database: { tls_mode: "require" } });
    client = new DirectClient(vault.engine);
  });

  afterEach(async () => {
    await destroyTestVault(vault);
  });

  it("blocks a redirected host:port before connecting (multi-interface: DirectClient)", async () => {
    await expect(
      client.useSecret(handle, dbAction("attacker.example.com:5432")),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
  });

  it("blocks SSRF even when the private host is allowlisted", async () => {
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: ["10.0.0.5:5432"],
    });
    await expect(client.useSecret(handle, dbAction("10.0.0.5:5432"))).rejects.toMatchObject({
      code: ErrorCode.SSRF_BLOCKED,
    });
  });

  it("I1: the credential never appears in a rejection", async () => {
    try {
      await client.useSecret(handle, dbAction("attacker.example.com:5432"));
      expect.fail("should throw");
    } catch (e) {
      expect(JSON.stringify(e)).not.toContain("sk-db-secret");
    }
  });

  it("records the denied use in the audit trail with context=database", async () => {
    try {
      await client.useSecret(handle, dbAction("attacker.example.com:5432"));
    } catch {
      /* expected */
    }
    const events = await client.queryAudit({ eventType: "secret.use" });
    const denied = events.find((e) => e.detail?.error === "HOST_NOT_ALLOWED");
    expect(denied?.success).toBe(false);
    expect(denied?.detail?.context).toBe("database");
  });
});
