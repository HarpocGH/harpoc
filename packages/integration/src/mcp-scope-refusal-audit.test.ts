import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { DecryptedAuditEvent } from "@harpoc/core";
import { createMcpServer, RateLimiter } from "@harpoc/mcp-server";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { callTool, readResource } from "./helpers/mcp-helpers.js";

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
    try {
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
    } finally {
      await mcp.close();
    }
  });

  it("an admitted call leaves no access.denied row", async () => {
    const before = denied().length;
    const mcp = createMcpServer({ engine: vault.engine, launchToken: token });
    try {
      const result = await callTool(mcp, "list_secrets", {});
      expect(result.isError).not.toBe(true);
      expect(denied()).toHaveLength(before);
    } finally {
      await mcp.close();
    }
  });

  it("past the global rate limit a refusal answers RATE_LIMIT_EXCEEDED and writes no row (D1d-1)", async () => {
    const before = denied().length;
    const mcp = createMcpServer({
      engine: vault.engine,
      launchToken: token,
      rateLimiter: new RateLimiter(2),
    });
    try {
      const first = await callTool(mcp, "create_secret", { name: "x", type: "api_key" });
      const second = await callTool(mcp, "create_secret", { name: "x", type: "api_key" });
      const third = await callTool(mcp, "create_secret", { name: "x", type: "api_key" });
      for (const refused of [first, second]) {
        expect(refused.isError).toBe(true);
        expect(refused.content[0]?.text).toContain("permission");
      }
      expect(third.isError).toBe(true);
      expect(third.content[0]?.text).toContain("rate limit");
      expect(third.content[0]?.text).not.toContain("permission");
      expect(denied()).toHaveLength(before + 2);
    } finally {
      await mcp.close();
    }
  });

  it("a resource read past the global rate limit is refused without a row (D1d-1)", async () => {
    const before = denied().length;
    const mcp = createMcpServer({
      engine: vault.engine,
      launchToken: token,
      rateLimiter: new RateLimiter(2),
    });
    try {
      const refusal = async (): Promise<string> => {
        try {
          await readResource(mcp, "secret://vault/audit/recent");
        } catch (err) {
          return err instanceof Error ? err.message : String(err);
        }
        throw new Error("resources/read secret://vault/audit/recent was admitted");
      };
      expect(await refusal()).toContain("permission");
      expect(await refusal()).toContain("permission");
      const third = await refusal();
      expect(third).toContain("rate limit");
      expect(third).not.toContain("permission");
      expect(denied()).toHaveLength(before + 2);
    } finally {
      await mcp.close();
    }
  });
});

describe("the MCP reads write their vault.read row on a real engine (A3-R2, A4)", () => {
  const NAMES = ["ledger", "payroll", "fresh-key"];
  let vault: TestVault;
  let auditor: string;
  let lister: string;
  let creator: string;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault("mcp-vault-read-pw");
    registerAgents(vault.engine, "auditor", "lister", "creator");
    await vault.engine.createSecret({
      name: "ledger",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("ledger-value")),
    });
    await vault.engine.createSecret({
      name: "payroll",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("payroll-value")),
    });
    const ledgerId = await vault.engine.resolveSecretId("secret://ledger");
    vault.engine.grantPolicy(
      { secretId: ledgerId, principalType: "agent", principalId: "lister", permissions: ["list"] },
      "it-admin",
    );
    auditor = vault.engine.createToken("auditor", ["admin"]);
    lister = vault.engine.createToken("lister", ["list"]);
    creator = vault.engine.createToken("creator", ["create"]);
  });

  afterAll(async () => {
    await destroyTestVault(vault);
  });

  function readsOf(principalId: string, operation: string): DecryptedAuditEvent[] {
    return vault.engine
      .queryAudit({ eventType: AuditEventType.VAULT_READ })
      .filter((row) => row.principal_id === principalId && row.detail?.operation === operation);
  }

  it("reading secret://vault/audit/recent leaves one audit_query row with the token's principal columns and interface mcp", async () => {
    const mcp = createMcpServer({ engine: vault.engine, launchToken: auditor });
    try {
      const result = await readResource(mcp, "secret://vault/audit/recent");
      const page = JSON.parse(result.contents[0]?.text ?? "[]") as unknown[];

      const rows = readsOf("auditor", "audit_query");
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ secret_id: null, principal_type: "agent", success: true });
      expect(rows[0]?.detail).toEqual({
        operation: "audit_query",
        exclude_event_type: AuditEventType.VAULT_READ,
        limit: 50,
        count: page.length,
        interface: "mcp",
      });
      for (const name of ["ledger", "payroll"]) {
        expect(JSON.stringify(rows[0]?.detail).includes(name)).toBe(false);
      }
    } finally {
      await mcp.close();
    }
  });

  it.each(["the list_secrets tool", "the secret://vault/secrets resource"])(
    "a listing through %s leaves one list_secrets row: count and withheld, interface mcp, naming no secret",
    async (surface) => {
      const before = readsOf("lister", "list_secrets").length;
      const mcp = createMcpServer({ engine: vault.engine, launchToken: lister });
      try {
        if (surface === "the list_secrets tool") {
          expect((await callTool(mcp, "list_secrets", {})).isError).not.toBe(true);
        } else {
          await readResource(mcp, "secret://vault/secrets");
        }

        const rows = readsOf("lister", "list_secrets");
        expect(rows).toHaveLength(before + 1);
        expect(rows[0]).toMatchObject({ secret_id: null, principal_type: "agent" });
        expect(rows[0]?.detail).toEqual({
          operation: "list_secrets",
          count: 1,
          withheld: 1,
          interface: "mcp",
        });
        for (const name of NAMES) {
          expect(JSON.stringify(rows[0]?.detail).includes(name)).toBe(false);
        }
      } finally {
        await mcp.close();
      }
    },
  );

  it("create_secret's name check leaves one name_taken row with the token's principal, found false, naming no secret", async () => {
    const mcp = createMcpServer({ engine: vault.engine, launchToken: creator });
    try {
      const result = await callTool(mcp, "create_secret", { name: "fresh-key", type: "api_key" });
      expect(result.isError).not.toBe(true);

      const rows = readsOf("creator", "name_taken");
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ secret_id: null, principal_type: "agent" });
      expect(rows[0]?.detail).toEqual({ operation: "name_taken", found: false, interface: "mcp" });
      expect(JSON.stringify(rows[0]?.detail).includes("fresh-key")).toBe(false);
    } finally {
      await mcp.close();
    }
  });

  it("an admitted resource read past the global rate limit is refused without a row, the bucket the tools' own", async () => {
    const before = readsOf("auditor", "audit_query").length;
    const mcp = createMcpServer({
      engine: vault.engine,
      launchToken: auditor,
      rateLimiter: new RateLimiter(1),
    });
    try {
      const refusal = async (): Promise<string> => {
        try {
          await readResource(mcp, "secret://vault/audit/recent");
        } catch (err) {
          return err instanceof Error ? err.message : String(err);
        }
        throw new Error("resources/read secret://vault/audit/recent was admitted");
      };
      const first = await callTool(mcp, "list_secrets", {});
      expect(first.isError).not.toBe(true);
      expect(await refusal()).toContain("rate limit");
      expect(await refusal()).toContain("rate limit");
      expect(readsOf("auditor", "audit_query")).toHaveLength(before);
    } finally {
      await mcp.close();
    }
  });
});
