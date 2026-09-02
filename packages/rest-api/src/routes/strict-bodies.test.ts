import { describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { createApp } from "../app.js";

const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["list", "read", "create", "rotate", "revoke", "use", "admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
};

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
};

function createMockEngine() {
  const policy = {
    id: "p1",
    secret_id: "uuid-1",
    principal_type: "agent",
    principal_id: "a1",
    permissions: ["read"],
    created_at: Date.now(),
    expires_at: null,
    created_by: "test-agent",
  };
  const agent = {
    id: "agent-1",
    name: "bot",
    description: null,
    owner: null,
    status: "active",
    created_at: Date.now(),
    updated_at: Date.now(),
  };
  return {
    getState: vi.fn().mockReturnValue("unlocked"),
    verifyToken: vi.fn().mockReturnValue(MOCK_TOKEN),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-1"),
    createSecret: vi.fn().mockResolvedValue({
      handle: "secret://k",
      status: "created",
      message: "Secret created",
    }),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    useSecret: vi.fn().mockResolvedValue({ type: "http", status: 200, headers: {}, body: "" }),
    setInjectionPolicy: vi.fn().mockResolvedValue(undefined),
    setMcpServerConfig: vi.fn().mockResolvedValue(undefined),
    setConnectionConfig: vi.fn().mockResolvedValue(undefined),
    grantPolicy: vi.fn().mockReturnValue(policy),
    registerAgent: vi.fn().mockReturnValue(agent),
    getAgent: vi.fn().mockReturnValue(agent),
    updateAgent: vi.fn().mockReturnValue(agent),
    setAgentPermissions: vi
      .fn()
      .mockResolvedValue({ policy, gated_before: true, gated_after: true }),
  };
}

function createMockCertManager() {
  return {
    importCertificate: vi.fn().mockResolvedValue({ handle: "secret://c", secretId: "uuid-c" }),
    generateCsr: vi.fn().mockResolvedValue({
      handle: "secret://c",
      secretId: "uuid-c",
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nx\n-----END CERTIFICATE REQUEST-----\n",
    }),
    renewCertificate: vi.fn(),
  };
}

function createMockOAuthManager() {
  return {
    startClientCredentials: vi.fn().mockResolvedValue({
      handle: "secret://gh-app",
      status: "authorized",
      message: "Client credentials flow completed for github",
    }),
    startDeviceCode: vi.fn(),
    startAuthorizationCodeDeferred: vi.fn(),
  };
}

// Every JSON-body route, with a body its schema accepts: the control proves
// the sample is valid, the case proves the stray key alone is what 400s.
const BODY_ROUTES: Array<[string, string, string, Record<string, unknown>]> = [
  ["POST", "/api/v1/secrets", "create", { name: "k", type: "api_key" }],
  ["POST", "/api/v1/secrets/k/rotate", "rotate", { value: "aGVsbG8=" }],
  [
    "POST",
    "/api/v1/secrets/k/use",
    "use",
    {
      action: {
        type: "http",
        method: "GET",
        url: "https://api.example.com/x",
        injection: { type: "bearer" },
      },
    },
  ],
  ["PUT", "/api/v1/secrets/k/injection-policy", "injection-policy", FULL_POLICY],
  [
    "PUT",
    "/api/v1/secrets/k/mcp-server",
    "mcp-server",
    {
      server_name: "docs",
      transport: "http",
      url: "https://mcp.example.com/mcp",
    },
  ],
  [
    "PUT",
    "/api/v1/secrets/k/connection-config",
    "connection-config",
    {
      ssh: {
        known_hosts: ["example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGV4YW1wbGVrZXk"],
      },
    },
  ],
  [
    "POST",
    "/api/v1/secrets/k/policies",
    "policies",
    { principal_type: "agent", principal_id: "a1", permissions: ["read"] },
  ],
  ["POST", "/api/v1/agents", "agents", { name: "bot" }],
  ["PUT", "/api/v1/agents/bot", "agents/:name", { description: "d" }],
  ["PUT", "/api/v1/agents/bot/secrets/k/permissions", "permissions", { permissions: ["read"] }],
  [
    "POST",
    "/api/v1/certificates/import",
    "certificates/import",
    {
      name: "c",
      private_key_pem: PRIVATE_KEY_PEM,
      certificate_pem: CERTIFICATE_PEM,
    },
  ],
  ["POST", "/api/v1/certificates/csr", "certificates/csr", { name: "c", subject: "example.com" }],
  [
    "POST",
    "/api/v1/oauth/authorize",
    "oauth/authorize",
    {
      name: "gh",
      provider: "github",
      grant_type: "client_credentials",
      client_id: "id",
      client_secret: "s",
    },
  ],
];

function build() {
  const engine = createMockEngine();
  const app = createApp(engine as never, {
    certManager: createMockCertManager() as never,
    oauthManager: createMockOAuthManager() as never,
  });
  return { app, engine };
}

function send(app: ReturnType<typeof build>["app"], method: string, path: string, body: unknown) {
  return app.request(path, {
    method,
    headers: {
      authorization: "Bearer valid-jwt",
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

describe("every JSON-body route refuses an unknown key (R10/A5)", () => {
  it.each(BODY_ROUTES)(
    "%s %s: a stray key is a 400 naming it",
    async (method, path, _label, body) => {
      const { app } = build();
      const res = await send(app, method, path, { ...body, extra: 1 });
      expect(res.status).toBe(400);
      const json = (await res.json()) as { error: string; message: string };
      expect(json.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
      expect(json.message).toContain("Unrecognized key(s) in object: 'extra'");
    },
  );

  it.each(BODY_ROUTES)(
    "%s %s: the control body without the key succeeds",
    async (method, path, _label, body) => {
      const { app } = build();
      const res = await send(app, method, path, body);
      expect(res.status).toBeLessThan(400);
    },
  );
});
