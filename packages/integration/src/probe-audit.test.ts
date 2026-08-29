import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "@harpoc/rest-api";
import { createMcpServer } from "@harpoc/mcp-server";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { callTool } from "./helpers/mcp-helpers.js";

const PASSWORD = "probe-audit-pw-1";

const USE_ACTION = {
  type: "http",
  method: "GET",
  url: "https://8.8.8.8/",
  injection: { type: "bearer" },
};

/**
 * N3 / E76 (probes half): the rate limiter used to key on a pre-resolved
 * secret id, so resolving the handle before the engine's own audited path ran
 * meant an unknown-handle probe threw before any audit row was written — a
 * blind spot for exactly the traffic the audit trail exists to catch.
 */
describe("unknown-handle probes write an attributed denial row (N3)", () => {
  let vault: TestVault;
  let app: ReturnType<typeof createApp>;
  let token: string;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "prober");
    await vault.engine.createSecret({
      name: "real-key",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("v")),
    });
    app = createApp(vault.engine);
    token = vault.engine.createToken("prober", ["read", "use", "rotate", "revoke"]);
  });

  afterAll(async () => {
    await destroyTestVault(vault);
  });

  function deniedRows(eventType: AuditEventType) {
    return vault.engine
      .queryAudit({ eventType })
      .filter((r) => r.success === false && r.principal_id === "prober");
  }

  it("REST GET /secrets/:handle on an unknown name: 404 and one secret.read denial", async () => {
    const before = deniedRows(AuditEventType.SECRET_READ).length;
    const res = await app.request("/api/v1/secrets/nope", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(404);
    const rows = deniedRows(AuditEventType.SECRET_READ);
    expect(rows).toHaveLength(before + 1);
    expect(rows[0]?.detail).toMatchObject({
      error: ErrorCode.SECRET_NOT_FOUND,
      interface: "rest",
    });
  });

  it("REST POST /secrets/:handle/use on an unknown name: 404 and one secret.use denial", async () => {
    const before = deniedRows(AuditEventType.SECRET_USE).length;
    const res = await app.request("/api/v1/secrets/nope/use", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ action: USE_ACTION }),
    });
    expect(res.status).toBe(404);
    expect(deniedRows(AuditEventType.SECRET_USE)).toHaveLength(before + 1);
  });

  it("MCP use_secret on an unknown name: tool error and one secret.use denial", async () => {
    const mcp = createMcpServer({ engine: vault.engine, launchToken: token });
    const before = deniedRows(AuditEventType.SECRET_USE).length;
    const result = await callTool(mcp, "use_secret", {
      handle: "secret://nope",
      action: USE_ACTION,
    });
    expect(result.isError).toBe(true);
    expect(deniedRows(AuditEventType.SECRET_USE)).toHaveLength(before + 1);
  });
});
