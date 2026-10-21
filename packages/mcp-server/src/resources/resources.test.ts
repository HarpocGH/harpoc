import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/server";
import {
  connectModernInMemoryClient,
  expectVaultError,
  inMemoryClientFor,
  invokeHandler,
} from "@harpoc/test-utils";
import type { SecretInfo } from "@harpoc/core";
import type { VaultEngine } from "@harpoc/core";
import type { Permission, VaultApiToken } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { ScopeGuard } from "../guards/scope-guard.js";
import { registerSecretsResource } from "./secrets.js";
import { registerHealthResource } from "./health.js";
import { registerAuditResource } from "./audit.js";
import { registerProjectsResource } from "./projects.js";

const SENTINEL = "ZZ-sentinel-9f3";

/** Row fields no projection may forward — a snake_case marker and a camelCase one. */
const OPACITY_EXTRA = { zz_sentinel: SENTINEL, encryptedValue: SENTINEL };

const LISTED_SECRETS: SecretInfo[] = [
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
    ...OPACITY_EXTRA,
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
    ...OPACITY_EXTRA,
  },
];

function mockEngine(secrets: SecretInfo[] = LISTED_SECRETS): VaultEngine {
  return {
    // W2/D5: the by-name resource reads through getSecretInfo (per-secret
    // `read` gate) instead of answering out of the listing.
    getSecretInfo: vi.fn(async (handle: string) => {
      const found = secrets.find((s) => s.handle === handle);
      if (!found) throw VaultError.secretNotFound(handle);
      return found;
    }),
    listSecrets: vi.fn().mockReturnValue(secrets),
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

async function readResource(server: McpServer, uri: string) {
  return (await inMemoryClientFor(server)).readResource(uri);
}

const servers: McpServer[] = [];

/** A per-test server, closed (with its in-memory client) after the test. */
function track(server: McpServer): McpServer {
  servers.push(server);
  return server;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

function makeScopedToken(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "scoped-agent",
    vault_id: "vault-1",
    scope: ["list", "read", "admin"],
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: "jti-scoped",
    principal_type: "agent",
    ...overrides,
  };
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

  afterEach(async () => {
    await server.close();
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

    it("the list answers exactly six metadata keys per row, never the row", async () => {
      const text = getResourceText(await readResource(server, "secret://vault/secrets"));
      const data = JSON.parse(text) as Record<string, unknown>[];
      expect(data).toHaveLength(2);
      for (const row of data) {
        expect(Object.keys(row).sort()).toEqual([
          "handle",
          "name",
          "project",
          "status",
          "type",
          "version",
        ]);
      }
      expect(text).not.toContain(SENTINEL);
    });

    it("the by-name read answers exactly the ten metadata keys, never the row", async () => {
      const text = getResourceText(await readResource(server, "secret://vault/secrets/my-key"));
      expect(Object.keys(JSON.parse(text) as Record<string, unknown>).sort()).toEqual([
        "created_at",
        "expires_at",
        "handle",
        "name",
        "project",
        "rotated_at",
        "status",
        "type",
        "updated_at",
        "version",
      ]);
      expect(text).not.toContain(SENTINEL);
    });

    it("answers the engine's SECRET_NOT_FOUND for a nonexistent secret", async () => {
      await expectVaultError(
        () =>
          invokeHandler(server, "resources/read", { uri: "secret://vault/secrets/nonexistent" }),
        ErrorCode.SECRET_NOT_FOUND,
      );
      await expect(readResource(server, "secret://vault/secrets/nonexistent")).rejects.toThrow(
        "Secret not found: secret://nonexistent",
      );
    });

    it("answers the same not-found error on the 2026-07-28 leg", async () => {
      const modern = await connectModernInMemoryClient(() => server);
      try {
        expect(modern.client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
        await expect(modern.readResource("secret://vault/secrets/nonexistent")).rejects.toThrow(
          "Secret not found: secret://nonexistent",
        );
      } finally {
        await modern.close();
      }
    });

    it("lists an unprojected secret at its name and a projected one at its handle path, %2F-encoded", async () => {
      const { resources } = await (await inMemoryClientFor(server)).client.listResources();
      expect(resources.map(({ uri, name, description }) => ({ uri, name, description }))).toEqual([
        {
          uri: "secret://vault/secrets",
          name: "secrets-list",
          description: "List of all secret handles with metadata (never values)",
        },
        {
          uri: "secret://vault/secrets/my-key",
          name: "my-key",
          description: "Secret: my-key (api_key, active)",
        },
        {
          uri: "secret://vault/secrets/prod%2Fdb-pass",
          name: "db-pass",
          description: "Secret: prod/db-pass (api_key, active)",
        },
      ]);
    });

    it("reads every listed secret back at exactly the URI the list advertised", async () => {
      const { client } = await inMemoryClientFor(server);
      const { resources } = await client.listResources();
      const read: unknown[] = [];
      for (const { uri } of resources.filter((r) => r.uri !== "secret://vault/secrets")) {
        const data = JSON.parse(getResourceText(await client.readResource({ uri }))) as {
          handle: string;
          project: string | null;
        };
        read.push([uri, data.handle, data.project]);
      }
      expect(read).toEqual([
        ["secret://vault/secrets/my-key", "secret://my-key", null],
        ["secret://vault/secrets/prod%2Fdb-pass", "secret://prod/db-pass", "prod"],
      ]);
      expect(vi.mocked(engine.getSecretInfo).mock.calls.map(([handle]) => handle)).toEqual([
        "secret://my-key",
        "secret://prod/db-pass",
      ]);
    });

    it("answers SECRET_NOT_FOUND for the bare name of a secret that exists only inside a project", async () => {
      await expectVaultError(
        () => invokeHandler(server, "resources/read", { uri: "secret://vault/secrets/db-pass" }),
        ErrorCode.SECRET_NOT_FOUND,
      );
      expect(engine.getSecretInfo).toHaveBeenCalledExactlyOnceWith(
        "secret://db-pass",
        expect.anything(),
      );
      expect(engine.listSecrets).not.toHaveBeenCalled();
    });

    it("reads two same-name secrets in two projects each at its own advertised URI", async () => {
      const prod = LISTED_SECRETS[1] as SecretInfo;
      const staging: SecretInfo = {
        ...prod,
        handle: "secret://staging/db-pass",
        project: "staging",
        createdAt: 5000,
        updatedAt: 5000,
      };
      const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
      registerSecretsResource(srv, mockEngine([staging, prod]), scopeGuard);
      const { client } = await inMemoryClientFor(srv);
      const uris = (await client.listResources()).resources.map((r) => r.uri);
      expect(uris).toEqual([
        "secret://vault/secrets",
        "secret://vault/secrets/staging%2Fdb-pass",
        "secret://vault/secrets/prod%2Fdb-pass",
      ]);
      const handles: string[] = [];
      for (const uri of uris.slice(1)) {
        const data = JSON.parse(getResourceText(await client.readResource({ uri }))) as {
          handle: string;
        };
        handles.push(data.handle);
      }
      expect(handles).toEqual(["secret://staging/db-pass", "secret://prod/db-pass"]);
    });

    it.each([
      "secret://vault/secrets/prod%252Fdb-pass",
      "secret://vault/secrets/a%2Fb%2Fc",
      "secret://vault/secrets/db%20pass",
      "secret://vault/secrets/%E0%A4%A",
    ])(
      "refuses the malformed handle path %s as INVALID_HANDLE before the scope check and any engine call",
      async (uri) => {
        const seen = vi.fn();
        const scoped = new ScopeGuard(
          makeScopedToken({ project: "prod", scope: ["list", "read"] }),
          "mcp",
          undefined,
          undefined,
          seen,
        );
        const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
        registerSecretsResource(srv, engine, scoped);

        await expectVaultError(
          () => invokeHandler(srv, "resources/read", { uri }),
          ErrorCode.INVALID_HANDLE,
        );
        expect(seen).not.toHaveBeenCalled();
        expect(engine.getSecretInfo).not.toHaveBeenCalled();
        expect(engine.listSecrets).not.toHaveBeenCalled();
      },
    );
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

    it("answers exactly the four aggregate keys and two-key expiring entries, never the row", async () => {
      const soon = Date.now() + 24 * 60 * 60 * 1000;
      vi.mocked(engine.listSecrets).mockReturnValue([
        ...LISTED_SECRETS,
        {
          ...(LISTED_SECRETS[0] as SecretInfo),
          handle: "secret://expiring",
          name: "expiring",
          expiresAt: soon,
        },
      ]);
      const text = getResourceText(await readResource(server, "secret://vault/health"));
      const data = JSON.parse(text) as Record<string, unknown>;
      expect(Object.keys(data).sort()).toEqual([
        "by_status",
        "expiring_soon",
        "total_secrets",
        "vault_state",
      ]);
      expect(data.by_status).toEqual({ active: 3 });
      expect(data.expiring_soon).toEqual([{ handle: "secret://expiring", expires_at: soon }]);
      expect(text).not.toContain(SENTINEL);
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

    // M-T2b-13 (test-review-2026-10-09): the tokenless waiver bypasses audit
    // scope filtering — this describe registers the resource under
    // `new ScopeGuard(null)`, and the engine is asked for the last 50 rows with
    // no visibility scope (a scoped guard passes its project / name patterns).
    it("queries the engine for the last 50 rows with no scope under the tokenless guard", async () => {
      await readResource(server, "secret://vault/audit/recent");

      expect(engine.queryAudit).toHaveBeenCalledTimes(1);
      expect(engine.queryAudit).toHaveBeenCalledWith({ limit: 50 }, undefined);
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

    it("answers exactly project and secret_count per entry, never the row", async () => {
      const text = getResourceText(await readResource(server, "secret://vault/projects"));
      expect(JSON.parse(text)).toEqual([
        { project: "(none)", secret_count: 1 },
        { project: "prod", secret_count: 1 },
      ]);
      expect(text).not.toContain(SENTINEL);
    });
  });

  describe("scope filtering on resources", () => {
    it("secrets resource filters by project scope", async () => {
      const scoped = new ScopeGuard(makeScopedToken({ project: "prod" }));
      const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
      registerSecretsResource(srv, engine, scoped);

      const result = await readResource(srv, "secret://vault/secrets");
      const data = JSON.parse(getResourceText(result));
      // Only "prod" project secrets should be visible
      expect(data).toHaveLength(1);
      expect(data[0].project).toBe("prod");
    });

    it("secrets resource filters by secret name scope", async () => {
      const scoped = new ScopeGuard(makeScopedToken({ secrets: ["my-key"] }));
      const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
      registerSecretsResource(srv, engine, scoped);

      const result = await readResource(srv, "secret://vault/secrets");
      const data = JSON.parse(getResourceText(result));
      expect(data).toHaveLength(1);
      expect(data[0].name).toBe("my-key");
    });

    it("a project-scoped token lists its project's secret and reads it at the advertised URI", async () => {
      const scoped = new ScopeGuard(makeScopedToken({ project: "prod", scope: ["list", "read"] }));
      const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
      registerSecretsResource(srv, engine, scoped);
      const { client } = await inMemoryClientFor(srv);

      const uris = (await client.listResources()).resources.map((r) => r.uri);
      expect(uris).toEqual(["secret://vault/secrets", "secret://vault/secrets/prod%2Fdb-pass"]);
      const data = JSON.parse(
        getResourceText(
          await client.readResource({ uri: "secret://vault/secrets/prod%2Fdb-pass" }),
        ),
      ) as { handle: string };
      expect(data.handle).toBe("secret://prod/db-pass");
      expect(engine.getSecretInfo).toHaveBeenCalledExactlyOnceWith(
        "secret://prod/db-pass",
        scoped.caller,
      );
    });

    it.each([
      { label: "a global secret", uri: "secret://vault/secrets/my-key" },
      { label: "another project's secret", uri: "secret://vault/secrets/dev%2Fdb-pass" },
    ])("a project-scoped token is refused $label, reason project", async ({ uri }) => {
      const seen = vi.fn();
      const scoped = new ScopeGuard(
        makeScopedToken({ project: "prod", scope: ["list", "read"] }),
        "mcp",
        undefined,
        undefined,
        seen,
      );
      const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
      registerSecretsResource(srv, engine, scoped);

      await expectVaultError(
        () => invokeHandler(srv, "resources/read", { uri }),
        ErrorCode.ACCESS_DENIED,
      );
      expect(seen).toHaveBeenCalledExactlyOnceWith(`resources/read ${uri}`, "project");
      expect(engine.getSecretInfo).not.toHaveBeenCalled();
    });

    it("a read-scoped token without a grant meets one refusal for an ungranted and a nonexistent secret on both protocol legs", async () => {
      const token = makeScopedToken({ scope: ["read"] });
      const ungranted = mockEngine();
      vi.mocked(ungranted.getSecretInfo).mockImplementation((handle: string) =>
        Promise.reject(VaultError.secretNotFound(handle)),
      );
      const uri = "secret://vault/secrets/prod%2Fdb-key";
      const refusals: string[] = [];
      const codes: unknown[] = [];
      const record = (read: Promise<unknown>): Promise<void> =>
        read.then(
          (answered) => {
            refusals.push(`answered ${JSON.stringify(answered)}`);
            codes.push(undefined);
          },
          (err: unknown) => {
            refusals.push(String(err));
            codes.push((err as { code?: number }).code);
          },
        );
      const serverFor = (vault: VaultEngine): McpServer => {
        const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
        registerSecretsResource(srv, vault, new ScopeGuard(token));
        return srv;
      };
      for (const vault of [ungranted, mockEngine([])]) {
        await record(readResource(serverFor(vault), uri));
        const modernServer = serverFor(vault);
        const modern = await connectModernInMemoryClient(() => modernServer);
        try {
          expect(modern.client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
          await record(modern.readResource(uri));
        } finally {
          await modern.close();
        }
      }
      expect(refusals).toHaveLength(4);
      for (const refusal of refusals) {
        expect(refusal).toContain("Secret not found: secret://prod/db-key");
        expect(refusal).toBe(refusals[0]);
      }
      expect(codes).toEqual([-32603, -32603, -32603, -32603]);
    });

    it("health resource respects scope filtering", async () => {
      const scoped = new ScopeGuard(makeScopedToken({ project: "prod" }));
      const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
      registerHealthResource(srv, engine, scoped);

      const result = await readResource(srv, "secret://vault/health");
      const data = JSON.parse(getResourceText(result));
      expect(data.total_secrets).toBe(1);
    });

    it("projects resource respects scope filtering", async () => {
      const scoped = new ScopeGuard(makeScopedToken({ project: "prod" }));
      const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
      registerProjectsResource(srv, engine, scoped);

      const result = await readResource(srv, "secret://vault/projects");
      const data = JSON.parse(getResourceText(result)) as Array<{
        project: string;
        secret_count: number;
      }>;
      expect(data).toHaveLength(1);
      expect(data[0]).toBeDefined();
      expect(data[0]?.project).toBe("prod");
    });

    // L10: the audit resource enforced the permission dimension alone, so a
    // project- or name-scoped admin token read every secret's audit detail.
    it("audit resource passes the token's project/name scope to the engine", async () => {
      const scoped = new ScopeGuard(makeScopedToken({ project: "prod", secrets: ["db-*"] }));
      const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
      registerAuditResource(srv, engine, scoped);

      await readResource(srv, "secret://vault/audit/recent");

      expect(engine.queryAudit).toHaveBeenCalledWith(expect.anything(), {
        project: "prod",
        secrets: ["db-*"],
      });
    });

    it("audit resource passes no scope for an unrestricted admin token", async () => {
      const unrestricted = new ScopeGuard(makeScopedToken());
      const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
      registerAuditResource(srv, engine, unrestricted);

      await readResource(srv, "secret://vault/audit/recent");

      expect(engine.queryAudit).toHaveBeenCalledWith(expect.anything(), undefined);
    });

    it("audit resource requires admin permission", async () => {
      const seen = vi.fn();
      const listOnly = new ScopeGuard(
        makeScopedToken({ scope: ["list"] }),
        "mcp",
        undefined,
        undefined,
        seen,
      );
      const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
      registerAuditResource(srv, engine, listOnly);

      await expect(
        invokeHandler(srv, "resources/read", { uri: "secret://vault/audit/recent" }),
      ).rejects.toThrow(expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }));
      expect(seen).toHaveBeenCalledWith("resources/read secret://vault/audit/recent", "permission");
    });

    describe("scope refusals", () => {
      interface ResourceRefusal {
        label: string;
        operation: string;
        register: typeof registerSecretsResource;
        method: "resources/read" | "resources/list";
        params: Record<string, unknown>;
        scope: Permission[];
        missing: Permission;
      }

      const REFUSALS: ResourceRefusal[] = [
        {
          label: "secret://vault/secrets",
          operation: "resources/read secret://vault/secrets",
          register: registerSecretsResource,
          method: "resources/read",
          params: { uri: "secret://vault/secrets" },
          scope: ["use"],
          missing: "list",
        },
        {
          label: "the by-name template's list",
          operation: "resources/list secret://vault/secrets/{name}",
          register: registerSecretsResource,
          method: "resources/list",
          params: {},
          scope: ["use"],
          missing: "list",
        },
        {
          label: "secret://vault/secrets/my-key",
          operation: "resources/read secret://vault/secrets/my-key",
          register: registerSecretsResource,
          method: "resources/read",
          params: { uri: "secret://vault/secrets/my-key" },
          scope: ["use", "list"],
          missing: "read",
        },
        {
          label: "secret://vault/health",
          operation: "resources/read secret://vault/health",
          register: registerHealthResource,
          method: "resources/read",
          params: { uri: "secret://vault/health" },
          scope: ["use"],
          missing: "list",
        },
        {
          label: "secret://vault/projects",
          operation: "resources/read secret://vault/projects",
          register: registerProjectsResource,
          method: "resources/read",
          params: { uri: "secret://vault/projects" },
          scope: ["use"],
          missing: "list",
        },
      ];

      it.each(REFUSALS)(
        "$label refuses a token without $missing",
        async ({ operation, register, method, params, scope }) => {
          const seen = vi.fn();
          const guard = new ScopeGuard(
            makeScopedToken({ scope }),
            "mcp",
            undefined,
            undefined,
            seen,
          );
          const srv = track(new McpServer({ name: "test", version: "0.0.0" }));
          register(srv, engine, guard);

          await expectVaultError(() => invokeHandler(srv, method, params), ErrorCode.ACCESS_DENIED);
          expect(seen).toHaveBeenCalledExactlyOnceWith(operation, "permission");
          expect(engine.listSecrets).not.toHaveBeenCalled();
          expect(engine.getSecretInfo).not.toHaveBeenCalled();
        },
      );
    });
  });
});
