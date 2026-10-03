import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import type { Permission, ScopeRefusalReason, VaultApiToken } from "@harpoc/shared";
import { createApp } from "../app.js";
import { silenceAuditLines } from "@harpoc/test-utils";

silenceAuditLines();

const ALL_SCOPES: Permission[] = ["list", "read", "create", "rotate", "revoke", "use", "admin"];

const TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ALL_SCOPES,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
};

const lacking = (permission: Permission): VaultApiToken => ({
  ...TOKEN,
  scope: ALL_SCOPES.filter((s) => s !== permission && s !== "admin"),
});
const OTHER_PROJECT_TOKEN: VaultApiToken = { ...TOKEN, project: "myproj" };
const NAME_PATTERN_TOKEN: VaultApiToken = { ...TOKEN, secrets: ["db-*"] };

const PRIVATE_KEY_PEM =
  "-----BEGIN PRIVATE KEY-----\nMIIFakePrivateKey\n-----END PRIVATE KEY-----\n";
const CERTIFICATE_PEM =
  "-----BEGIN CERTIFICATE-----\nMIIFakeCertificate\n-----END CERTIFICATE-----\n";

const FULL_POLICY = {
  url_allowlist: ["https://api.github.com/*"],
  command_allowlist: ["gh"],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: false,
  fs_isolation: false,
  smtp_recipient_allowlist: [],
  imap_read_only: false,
  strict_tree_exit: false,
};
const CREATE_BODY = { name: "k", type: "api_key" };
const USE_BODY = {
  action: {
    type: "http",
    method: "GET",
    url: "https://api.example.com/x",
    injection: { type: "bearer" },
  },
};
const MCP_SERVER_BODY = {
  server_name: "docs",
  transport: "http",
  url: "https://mcp.example.com/mcp",
};
const CONNECTION_BODY = {
  ssh: { known_hosts: ["example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGV4YW1wbGVrZXk"] },
};
const POLICY_BODY = { principal_type: "agent", principal_id: "a1", permissions: ["read"] };
const OAUTH_BODY = {
  name: "gh-app",
  provider: "github",
  grant_type: "device_code",
  client_id: "cid",
};
const IMPORT_BODY = {
  name: "my-cert",
  private_key_pem: PRIVATE_KEY_PEM,
  certificate_pem: CERTIFICATE_PEM,
};
const CSR_BODY = { name: "my-csr", subject: "example.com" };

function createMocks() {
  return {
    engine: {
      verifyToken: vi.fn(),
      auditScopeRefusal: vi.fn(),
      auditGovernanceRefusal: vi.fn(),
      listSecrets: vi.fn(),
      createSecret: vi.fn(),
      getSecretInfo: vi.fn(),
      getSecretValue: vi.fn(),
      revokeSecret: vi.fn(),
      rotateSecret: vi.fn(),
      useSecret: vi.fn(),
      getInjectionPolicy: vi.fn(),
      setInjectionPolicy: vi.fn(),
      getMcpServerConfig: vi.fn(),
      setMcpServerConfig: vi.fn(),
      deleteMcpServerConfig: vi.fn(),
      getConnectionConfig: vi.fn(),
      setConnectionConfig: vi.fn(),
      deleteConnectionConfig: vi.fn(),
      resolveSecretId: vi.fn(),
      listPolicies: vi.fn(),
      grantPolicy: vi.fn(),
      revokePolicy: vi.fn(),
      queryAudit: vi.fn(),
      verifyAuditChain: vi.fn(),
      getExpiringOAuthTokenStatuses: vi.fn(),
      getExpiringCertificateStatuses: vi.fn(),
      getOAuthTokenStatus: vi.fn(),
      refreshOAuthToken: vi.fn(),
      getCertificateStatus: vi.fn(),
      listAgents: vi.fn(),
      registerAgent: vi.fn(),
      getAgent: vi.fn(),
      updateAgent: vi.fn(),
      deactivateAgent: vi.fn(),
      activateAgent: vi.fn(),
      deleteAgent: vi.fn(),
      listAgentPolicies: vi.fn(),
      setAgentPermissions: vi.fn(),
      listIssuedTokens: vi.fn(),
      revokeToken: vi.fn(),
    },
    oauthManager: {
      startClientCredentials: vi.fn(),
      startDeviceCode: vi.fn(),
      startAuthorizationCodeDeferred: vi.fn(),
    },
    certManager: {
      importCertificate: vi.fn(),
      generateCsr: vi.fn(),
      renewCertificate: vi.fn(),
    },
  };
}

type Mocks = ReturnType<typeof createMocks>;

function build() {
  const mocks = createMocks();
  const app = createApp(mocks.engine as never, {
    oauthManager: mocks.oauthManager as never,
    certManager: mocks.certManager as never,
  });
  return { app, mocks };
}

interface ScopeSite {
  site: string;
  method: "GET" | "POST" | "PUT" | "DELETE";
  route: string;
  path: string;
  query?: string;
  body?: Record<string, unknown>;
  token: VaultApiToken;
  reason: ScopeRefusalReason;
  untouched: (m: Mocks) => Mock[];
}

/**
 * One row per `checkScope(` call site under `routes/` (44). A route with a
 * second, name-carrying check is reachable there only with the permission held,
 * so those five rows refuse on the project or the name pattern instead.
 */
const SITES: ScopeSite[] = [
  {
    site: "agents.ts:41",
    method: "GET",
    route: "/api/v1/agents",
    path: "/api/v1/agents",
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.listAgents],
  },
  {
    site: "agents.ts:56",
    method: "POST",
    route: "/api/v1/agents",
    path: "/api/v1/agents",
    body: { name: "bot" },
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.registerAgent],
  },
  {
    site: "agents.ts:71",
    method: "GET",
    route: "/api/v1/agents/:name",
    path: "/api/v1/agents/bot",
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.getAgent],
  },
  {
    site: "agents.ts:80",
    method: "PUT",
    route: "/api/v1/agents/:name",
    path: "/api/v1/agents/bot",
    body: { description: "d" },
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.updateAgent],
  },
  {
    site: "agents.ts:97",
    method: "POST",
    route: "/api/v1/agents/:name/deactivate",
    path: "/api/v1/agents/bot/deactivate",
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.deactivateAgent],
  },
  {
    site: "agents.ts:107",
    method: "POST",
    route: "/api/v1/agents/:name/activate",
    path: "/api/v1/agents/bot/activate",
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.activateAgent],
  },
  {
    site: "agents.ts:117",
    method: "DELETE",
    route: "/api/v1/agents/:name",
    path: "/api/v1/agents/bot",
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.deleteAgent],
  },
  {
    site: "agents.ts:127",
    method: "GET",
    route: "/api/v1/agents/:name/policies",
    path: "/api/v1/agents/bot/policies",
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.listAgentPolicies],
  },
  {
    site: "agents.ts:139",
    method: "PUT",
    route: "/api/v1/agents/:name/secrets/:handle/permissions",
    path: "/api/v1/agents/bot/secrets/test-key/permissions",
    body: { permissions: ["read"] },
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.resolveSecretId, m.engine.setAgentPermissions],
  },
  {
    site: "agents.ts:144",
    method: "PUT",
    route: "/api/v1/agents/:name/secrets/:handle/permissions",
    path: "/api/v1/agents/bot/secrets/test-key/permissions",
    body: { permissions: ["read"] },
    token: NAME_PATTERN_TOKEN,
    reason: "secret",
    untouched: (m) => [m.engine.resolveSecretId, m.engine.setAgentPermissions],
  },
  {
    site: "audit.ts:12",
    method: "GET",
    route: "/api/v1/audit",
    path: "/api/v1/audit",
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.queryAudit],
  },
  {
    site: "audit.ts:69",
    method: "POST",
    route: "/api/v1/audit/verify",
    path: "/api/v1/audit/verify",
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.verifyAuditChain],
  },
  {
    site: "certificates.ts:20",
    method: "POST",
    route: "/api/v1/certificates/import",
    path: "/api/v1/certificates/import",
    body: IMPORT_BODY,
    token: lacking("create"),
    reason: "permission",
    untouched: (m) => [m.certManager.importCertificate],
  },
  {
    site: "certificates.ts:26",
    method: "POST",
    route: "/api/v1/certificates/import",
    path: "/api/v1/certificates/import",
    body: { ...IMPORT_BODY, project: "other" },
    token: OTHER_PROJECT_TOKEN,
    reason: "project",
    untouched: (m) => [m.certManager.importCertificate],
  },
  {
    site: "certificates.ts:43",
    method: "POST",
    route: "/api/v1/certificates/csr",
    path: "/api/v1/certificates/csr",
    body: CSR_BODY,
    token: lacking("create"),
    reason: "permission",
    untouched: (m) => [m.certManager.generateCsr],
  },
  {
    site: "certificates.ts:49",
    method: "POST",
    route: "/api/v1/certificates/csr",
    path: "/api/v1/certificates/csr",
    body: { ...CSR_BODY, project: "other" },
    token: OTHER_PROJECT_TOKEN,
    reason: "project",
    untouched: (m) => [m.certManager.generateCsr],
  },
  {
    site: "certificates.ts:64",
    method: "POST",
    route: "/api/v1/certificates/:handle/renew",
    path: "/api/v1/certificates/test-key/renew",
    token: lacking("rotate"),
    reason: "permission",
    untouched: (m) => [m.engine.resolveSecretId, m.certManager.renewCertificate],
  },
  {
    site: "certificates.ts:78",
    method: "GET",
    route: "/api/v1/certificates/:handle/status",
    path: "/api/v1/certificates/test-key/status",
    token: lacking("read"),
    reason: "permission",
    untouched: (m) => [m.engine.resolveSecretId, m.engine.getCertificateStatus],
  },
  {
    site: "health.ts:35",
    method: "GET",
    route: "/api/v1/health/expiring",
    path: "/api/v1/health/expiring",
    token: lacking("list"),
    reason: "permission",
    untouched: (m) => [
      m.engine.listSecrets,
      m.engine.getExpiringOAuthTokenStatuses,
      m.engine.getExpiringCertificateStatuses,
    ],
  },
  {
    site: "oauth.ts:14",
    method: "POST",
    route: "/api/v1/oauth/authorize",
    path: "/api/v1/oauth/authorize",
    body: OAUTH_BODY,
    token: lacking("create"),
    reason: "permission",
    untouched: (m) => [
      m.oauthManager.startClientCredentials,
      m.oauthManager.startDeviceCode,
      m.oauthManager.startAuthorizationCodeDeferred,
    ],
  },
  {
    site: "oauth.ts:20",
    method: "POST",
    route: "/api/v1/oauth/authorize",
    path: "/api/v1/oauth/authorize",
    body: OAUTH_BODY,
    token: NAME_PATTERN_TOKEN,
    reason: "secret",
    untouched: (m) => [
      m.oauthManager.startClientCredentials,
      m.oauthManager.startDeviceCode,
      m.oauthManager.startAuthorizationCodeDeferred,
    ],
  },
  {
    site: "oauth.ts:31",
    method: "GET",
    route: "/api/v1/oauth/:handle/status",
    path: "/api/v1/oauth/test-key/status",
    token: lacking("read"),
    reason: "permission",
    untouched: (m) => [m.engine.resolveSecretId, m.engine.getOAuthTokenStatus],
  },
  {
    site: "oauth.ts:42",
    method: "POST",
    route: "/api/v1/oauth/:handle/refresh",
    path: "/api/v1/oauth/test-key/refresh",
    token: lacking("rotate"),
    reason: "permission",
    untouched: (m) => [m.engine.resolveSecretId, m.engine.refreshOAuthToken],
  },
  {
    site: "policies.ts:16",
    method: "GET",
    route: "/api/v1/secrets/:handle/policies",
    path: "/api/v1/secrets/test-key/policies",
    token: lacking("read"),
    reason: "permission",
    untouched: (m) => [m.engine.resolveSecretId, m.engine.listPolicies],
  },
  {
    site: "policies.ts:30",
    method: "POST",
    route: "/api/v1/secrets/:handle/policies",
    path: "/api/v1/secrets/test-key/policies",
    body: POLICY_BODY,
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.resolveSecretId, m.engine.grantPolicy],
  },
  {
    site: "policies.ts:60",
    method: "DELETE",
    route: "/api/v1/secrets/:handle/policies/:policyId",
    path: "/api/v1/secrets/test-key/policies/p1",
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.resolveSecretId, m.engine.revokePolicy],
  },
  {
    site: "secrets.ts:31",
    method: "GET",
    route: "/api/v1/secrets",
    path: "/api/v1/secrets",
    token: lacking("list"),
    reason: "permission",
    untouched: (m) => [m.engine.listSecrets],
  },
  {
    site: "secrets.ts:59",
    method: "POST",
    route: "/api/v1/secrets",
    path: "/api/v1/secrets",
    body: CREATE_BODY,
    token: lacking("create"),
    reason: "permission",
    untouched: (m) => [m.engine.createSecret],
  },
  {
    site: "secrets.ts:69",
    method: "POST",
    route: "/api/v1/secrets",
    path: "/api/v1/secrets",
    body: { ...CREATE_BODY, project: "other" },
    token: OTHER_PROJECT_TOKEN,
    reason: "project",
    untouched: (m) => [m.engine.createSecret],
  },
  {
    site: "secrets.ts:90",
    method: "GET",
    route: "/api/v1/secrets/:handle",
    path: "/api/v1/secrets/test-key",
    token: lacking("read"),
    reason: "permission",
    untouched: (m) => [m.engine.getSecretInfo],
  },
  {
    site: "secrets.ts:105",
    method: "GET",
    route: "/api/v1/secrets/:handle/value",
    path: "/api/v1/secrets/test-key/value",
    token: lacking("read"),
    reason: "permission",
    untouched: (m) => [m.engine.getSecretValue],
  },
  {
    site: "secrets.ts:118",
    method: "DELETE",
    route: "/api/v1/secrets/:handle",
    path: "/api/v1/secrets/test-key",
    query: "?confirm=true",
    token: lacking("revoke"),
    reason: "permission",
    untouched: (m) => [m.engine.revokeSecret],
  },
  {
    site: "secrets.ts:136",
    method: "POST",
    route: "/api/v1/secrets/:handle/rotate",
    path: "/api/v1/secrets/test-key/rotate",
    body: { value: "aGVsbG8=" },
    token: lacking("rotate"),
    reason: "permission",
    untouched: (m) => [m.engine.rotateSecret],
  },
  {
    site: "secrets.ts:160",
    method: "POST",
    route: "/api/v1/secrets/:handle/use",
    path: "/api/v1/secrets/test-key/use",
    body: USE_BODY,
    token: lacking("use"),
    reason: "permission",
    untouched: (m) => [m.engine.useSecret],
  },
  {
    site: "secrets.ts:183",
    method: "GET",
    route: "/api/v1/secrets/:handle/injection-policy",
    path: "/api/v1/secrets/test-key/injection-policy",
    token: lacking("read"),
    reason: "permission",
    untouched: (m) => [m.engine.getInjectionPolicy],
  },
  {
    site: "secrets.ts:196",
    method: "PUT",
    route: "/api/v1/secrets/:handle/injection-policy",
    path: "/api/v1/secrets/test-key/injection-policy",
    body: FULL_POLICY,
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.setInjectionPolicy],
  },
  {
    site: "secrets.ts:214",
    method: "GET",
    route: "/api/v1/secrets/:handle/mcp-server",
    path: "/api/v1/secrets/test-key/mcp-server",
    token: lacking("read"),
    reason: "permission",
    untouched: (m) => [m.engine.getMcpServerConfig],
  },
  {
    site: "secrets.ts:225",
    method: "PUT",
    route: "/api/v1/secrets/:handle/mcp-server",
    path: "/api/v1/secrets/test-key/mcp-server",
    body: MCP_SERVER_BODY,
    token: lacking("rotate"),
    reason: "permission",
    untouched: (m) => [m.engine.setMcpServerConfig],
  },
  {
    site: "secrets.ts:242",
    method: "DELETE",
    route: "/api/v1/secrets/:handle/mcp-server",
    path: "/api/v1/secrets/test-key/mcp-server",
    token: lacking("rotate"),
    reason: "permission",
    untouched: (m) => [m.engine.deleteMcpServerConfig],
  },
  {
    site: "secrets.ts:253",
    method: "GET",
    route: "/api/v1/secrets/:handle/connection-config",
    path: "/api/v1/secrets/test-key/connection-config",
    token: lacking("read"),
    reason: "permission",
    untouched: (m) => [m.engine.getConnectionConfig],
  },
  {
    site: "secrets.ts:264",
    method: "PUT",
    route: "/api/v1/secrets/:handle/connection-config",
    path: "/api/v1/secrets/test-key/connection-config",
    body: CONNECTION_BODY,
    token: lacking("rotate"),
    reason: "permission",
    untouched: (m) => [m.engine.setConnectionConfig],
  },
  {
    site: "secrets.ts:281",
    method: "DELETE",
    route: "/api/v1/secrets/:handle/connection-config",
    path: "/api/v1/secrets/test-key/connection-config",
    token: lacking("rotate"),
    reason: "permission",
    untouched: (m) => [m.engine.deleteConnectionConfig],
  },
  {
    site: "tokens.ts:17",
    method: "GET",
    route: "/api/v1/tokens",
    path: "/api/v1/tokens",
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.listIssuedTokens],
  },
  {
    site: "tokens.ts:39",
    method: "DELETE",
    route: "/api/v1/tokens/:jti",
    path: "/api/v1/tokens/jti-9",
    token: lacking("admin"),
    reason: "permission",
    untouched: (m) => [m.engine.revokeToken],
  },
];

const UNAUTHENTICATED_ROUTES = ["GET /api/v1/health"];
const ROUTES_DIR = new URL(".", import.meta.url);

describe("every checkScope site writes the audited scope denial (D2g)", () => {
  it.each(SITES)(
    "$site: $method $path refuses 403 on $reason with one access.denied row",
    async (row) => {
      const { app, mocks } = build();
      mocks.engine.verifyToken.mockReturnValue(row.token);
      const headers: Record<string, string> = {
        host: "localhost",
        authorization: "Bearer valid-jwt",
      };
      if (row.body !== undefined) headers["content-type"] = "application/json";

      const res = await app.request(`${row.path}${row.query ?? ""}`, {
        method: row.method,
        headers,
        body: row.body === undefined ? undefined : JSON.stringify(row.body),
      });

      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);
      expect(mocks.engine.auditScopeRefusal).toHaveBeenCalledTimes(1);
      expect(mocks.engine.auditScopeRefusal).toHaveBeenCalledWith(
        expect.objectContaining({ principal_id: row.token.sub, interface: "rest" }),
        `${row.method} ${row.path}`,
        row.reason,
      );
      expect(mocks.engine.auditGovernanceRefusal).not.toHaveBeenCalled();
      for (const fn of row.untouched(mocks)) {
        expect(fn).not.toHaveBeenCalled();
      }
    },
  );
});

describe("the scope-site inventory is complete", () => {
  it("names every authenticated route the app registers, and nothing else", () => {
    const { app } = build();
    const registered = app.routes
      .filter((r) => r.method !== "ALL")
      .map((r) => `${r.method} ${r.path}`)
      .filter((route) => !UNAUTHENTICATED_ROUTES.includes(route));
    const inventoried = new Set(SITES.map((row) => `${row.method} ${row.route}`));
    expect([...inventoried].sort()).toEqual([...new Set(registered)].sort());
  });

  it("requests a concrete path of each row's own route", () => {
    for (const row of SITES) {
      expect(row.path).toMatch(new RegExp(`^${row.route.replace(/:[^/]+/g, "[^/]+")}$`));
    }
  });

  it("holds one row per checkScope call site in every route file", () => {
    const files = readdirSync(ROUTES_DIR).filter(
      (f) => f.endsWith(".ts") && !f.endsWith(".test.ts"),
    );
    const callSites = Object.fromEntries(
      files.map((f) => [
        f,
        (readFileSync(new URL(f, ROUTES_DIR), "utf8").match(/\bcheckScope\(c, "/g) ?? []).length,
      ]),
    );
    const rows = Object.fromEntries(
      files.map((f) => [f, SITES.filter((row) => row.site.startsWith(`${f}:`)).length]),
    );
    expect(rows).toEqual(callSites);
    expect(Object.values(rows).reduce((a, b) => a + b, 0)).toBe(SITES.length);
  });
});
