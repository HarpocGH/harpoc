import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createMcpServer } from "@harpoc/mcp-server";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { callTool } from "./helpers/mcp-helpers.js";

describe("every MCP scope refusal writes an access.denied row (D2g)", () => {
  let vault: TestVault;
  let token: string;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault("mcp-scope-refusal-pw");
    registerAgents(vault.engine, "reader");
    token = vault.engine.createToken("reader", ["read", "list"]);
  });

  afterAll(async () => {
    await destroyTestVault(vault);
  });

  const denied = () => vault.engine.queryAudit({ eventType: AuditEventType.ACCESS_DENIED });

  it("a read-only token calling create_secret: a tool error and one row naming the tool and the reason", async () => {
    const mcp = createMcpServer({ engine: vault.engine, launchToken: token });
    const result = await callTool(mcp, "create_secret", { name: "x", type: "api_key" });
    expect(result.isError).toBe(true);
    const rows = denied();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.secret_id).toBeNull();
    expect(rows[0]?.principal_type).toBe("agent");
    expect(rows[0]?.principal_id).toBe("reader");
    expect(rows[0]?.detail).toEqual({
      operation: "create_secret",
      error: ErrorCode.ACCESS_DENIED,
      reason: "permission",
      interface: "mcp",
    });
  });

  it("an admitted call leaves no row", async () => {
    const before = denied().length;
    const mcp = createMcpServer({ engine: vault.engine, launchToken: token });
    const result = await callTool(mcp, "list_secrets", {});
    expect(result.isError).not.toBe(true);
    expect(denied()).toHaveLength(before);
  });
});
