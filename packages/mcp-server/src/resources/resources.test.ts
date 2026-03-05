import { describe, it, expect, vi, beforeEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SecretInfo } from "@harpoc/core";
import type { VaultEngine } from "@harpoc/core";
import type { VaultApiToken } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { ScopeGuard } from "../guards/scope-guard.js";
import { registerSecretsResource } from "./secrets.js";
import { registerHealthResource } from "./health.js";
import { registerAuditResource } from "./audit.js";
import { registerProjectsResource } from "./projects.js";

function mockEngine(): VaultEngine {
  return {
    listSecrets: vi.fn().mockReturnValue([
      {
        handle: "secret://my-key",
        name: "my-key",
        type: "api_key",
        project: null,
        status: "active",
        version: 1,
        createdAt: 1000,
        updatedAt: 2000,
        expiresAt: null,
        rotatedAt: null,
      },
      {
        handle: "secret://prod/db-pass",
        name: "db-pass",
        type: "api_key",
        project: "prod",
        status: "active",
        version: 2,
        createdAt: 1000,
        updatedAt: 3000,
        expiresAt: null,
        rotatedAt: 2000,
      },
    ] satisfies SecretInfo[]),
    getState: vi.fn().mockReturnValue("unlocked"),
    queryAudit: vi.fn().mockReturnValue([
      {
        id: 1,
        timestamp: 1000,
        event_type: "vault.unlock",
        secret_id: null,
        principal_type: null,
        principal_id: null,
        success: true,
        detail: null,
      },
    ]),
  } as unknown as VaultEngine;
}

function getResourceText(result: { contents: Array<{ uri: string; text?: string }> }): string {
  return (result.contents[0] as { text: string }).text;
}

async function readResource(
  server: McpServer,
  uri: string,
): Promise<{ contents: Array<{ uri: string; text?: string; mimeType?: string }> }> {
  const lowLevelServer = (
    server as unknown as { server: { _requestHandlers: Map<string, unknown> } }
  ).server;
  const handler = lowLevelServer._requestHandlers.get("resources/read") as (
    req: { method: string; params: { uri: string } },
    extra: unknown,
  ) => Promise<{ contents: Array<{ uri: string; text?: string; mimeType?: string }> }>;

  if (!handler) throw new Error("No resources/read handler found");

  return handler(
    { method: "resources/read", params: { uri } },
    { signal: new AbortController().signal, sessionId: "test" },
  );
}

describe("MCP Resources", () => {
  let server: McpServer;
  let engine: VaultEngine;
  let scopeGuard: ScopeGuard;

  beforeEach(() => {
    server = new McpServer({ name: "test", version: "0.0.0" });
    engine = mockEngine();
    scopeGuard = new ScopeGuard(null);
  });

  describe("secrets resource", () => {
    beforeEach(() => {
      registerSecretsResource(server, engine, scopeGuard);
    });

    it("returns list of secrets at secret://vault/secrets", async () => {
      const result = await readResource(server, "secret://vault/secrets");
      const data = JSON.parse(getResourceText(result));
      expect(data).toHaveLength(2);
      expect(data[0].handle).toBe("secret://my-key");
    });

    it("returns single secret by name", async () => {
      const result = await readResource(server, "secret://vault/secrets/my-key");
      const data = JSON.parse(getResourceText(result));
      expect(data.handle).toBe("secret://my-key");
      expect(data.name).toBe("my-key");
    });

    it("returns error for non-existent secret", async () => {
      const result = await readResource(server, "secret://vault/secrets/nonexistent");
      const data = JSON.parse(getResourceText(result));
      expect(data.error).toBe("Secret not found");
    });
  });

  describe("health resource", () => {
    beforeEach(() => {
      registerHealthResource(server, engine, scopeGuard);
    });

    it("returns vault state and secret counts", async () => {
      const result = await readResource(server, "secret://vault/health");
      const data = JSON.parse(getResourceText(result));
      expect(data.vault_state).toBe("unlocked");
      expect(data.total_secrets).toBe(2);
      expect(data.by_status.active).toBe(2);
    });
  });

  describe("audit resource", () => {
    beforeEach(() => {
      registerAuditResource(server, engine, scopeGuard);
    });

    it("returns recent audit events", async () => {
      const result = await readResource(server, "secret://vault/audit/recent");
      const data = JSON.parse(getResourceText(result));
      expect(data).toHaveLength(1);
      expect(data[0].event_type).toBe("vault.unlock");
    });
  });

  describe("projects resource", () => {
    beforeEach(() => {
      registerProjectsResource(server, engine, scopeGuard);
    });

    it("returns projects with secret counts", async () => {
      const result = await readResource(server, "secret://vault/projects");
      const data = JSON.parse(getResourceText(result)) as Array<{
        project: string;
        secret_count: number;
      }>;
      expect(data).toHaveLength(2);
      const none = data.find((d) => d.project === "(none)");
      const prod = data.find((d) => d.project === "prod");
      expect(none?.secret_count).toBe(1);
      expect(prod?.secret_count).toBe(1);
    });
  });

  describe("scope filtering on resources", () => {
    function makeScopedToken(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
      return {
        sub: "scoped-agent",
        vault_id: "vault-1",
        scope: ["list", "read", "admin"],
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        jti: "jti-scoped",
        ...overrides,
      };
    }

    it("secrets resource filters by project scope", async () => {
      const scoped = new ScopeGuard(makeScopedToken({ project: "prod" }));
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerSecretsResource(srv, engine, scoped);

      const result = await readResource(srv, "secret://vault/secrets");
      const data = JSON.parse(getResourceText(result));
      // Only "prod" project secrets should be visible
      expect(data).toHaveLength(1);
      expect(data[0].project).toBe("prod");
    });

    it("secrets resource filters by secret name scope", async () => {
      const scoped = new ScopeGuard(makeScopedToken({ secrets: ["my-key"] }));
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerSecretsResource(srv, engine, scoped);

      const result = await readResource(srv, "secret://vault/secrets");
      const data = JSON.parse(getResourceText(result));
      expect(data).toHaveLength(1);
      expect(data[0].name).toBe("my-key");
    });

    it("health resource respects scope filtering", async () => {
      const scoped = new ScopeGuard(makeScopedToken({ project: "prod" }));
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerHealthResource(srv, engine, scoped);

      const result = await readResource(srv, "secret://vault/health");
      const data = JSON.parse(getResourceText(result));
      expect(data.total_secrets).toBe(1);
    });

    it("projects resource respects scope filtering", async () => {
      const scoped = new ScopeGuard(makeScopedToken({ project: "prod" }));
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerProjectsResource(srv, engine, scoped);

      const result = await readResource(srv, "secret://vault/projects");
      const data = JSON.parse(getResourceText(result)) as Array<{
        project: string;
        secret_count: number;
      }>;
      expect(data).toHaveLength(1);
      expect(data[0].project).toBe("prod");
    });

    it("audit resource requires admin permission", async () => {
      const listOnly = new ScopeGuard(makeScopedToken({ scope: ["list"] }));
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerAuditResource(srv, engine, listOnly);

      await expect(readResource(srv, "secret://vault/audit/recent")).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
      );
    });
  });
});
