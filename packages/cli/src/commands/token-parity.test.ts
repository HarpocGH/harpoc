import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { Command } from "commander";
import type { CertificateStatus, Permission, VaultApiToken } from "@harpoc/shared";

const { mockEngine, mockManager, mockCertManager, mockResolveSecretValue, mockPromptConfirm } =
  vi.hoisted(() => {
    const manager = {
      importCertificate: vi.fn(),
      generateCsr: vi.fn(),
      issueWithAcme: vi.fn(),
      renewCertificate: vi.fn(),
    };
    return {
      mockEngine: {
        listSecrets: vi.fn(),
        getSecretInfo: vi.fn(),
        getSecretValue: vi.fn(),
        createSecret: vi.fn(),
        rotateSecret: vi.fn(),
        revokeSecret: vi.fn(),
        getInjectionPolicy: vi.fn(),
        setInjectionPolicy: vi.fn(),
        getMcpServerConfig: vi.fn(),
        setMcpServerConfig: vi.fn(),
        deleteMcpServerConfig: vi.fn(),
        getConnectionConfig: vi.fn(),
        setConnectionConfig: vi.fn(),
        deleteConnectionConfig: vi.fn(),
        listPolicies: vi.fn(),
        grantPolicy: vi.fn(),
        revokePolicy: vi.fn(),
        queryAudit: vi.fn(),
        verifyAuditChain: vi.fn(),
        getAuditChainTail: vi.fn(),
        getOAuthTokenStatus: vi.fn(),
        refreshOAuthToken: vi.fn(),
        getCertificateStatus: vi.fn(),
        registerAgent: vi.fn(),
        getAgent: vi.fn(),
        listAgents: vi.fn(),
        updateAgent: vi.fn(),
        deactivateAgent: vi.fn(),
        activateAgent: vi.fn(),
        deleteAgent: vi.fn(),
        setAgentPermissions: vi.fn(),
        listIssuedTokens: vi.fn(),
        verifyToken: vi.fn(),
        destroy: vi.fn().mockResolvedValue(undefined),
      },
      mockManager: manager,
      mockCertManager: vi.fn(() => manager),
      mockResolveSecretValue: vi.fn(),
      mockPromptConfirm: vi.fn(),
    };
  });

vi.mock("../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("sid-1"),
}));
// Partial: `cert import` also reads MAX_SECRET_FILE_BYTES from this module, and
// a factory that returns only the faked function makes that import a load-time
// failure rather than a scope refusal.
vi.mock("../utils/secret-value.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../utils/secret-value.js")>()),
  resolveSecretValue: mockResolveSecretValue,
}));
vi.mock("../utils/prompt.js", () => ({ promptConfirm: mockPromptConfirm }));

// Four of the five cert commands reach the vault through CertManager, not
// through an engine method the mock above can stand in for: `cert renew` and
// the three creation entry points would otherwise generate key pairs, bind a
// challenge responder and talk to a live ACME CA. The manager is faked at the
// module boundary for the same reason issue-renew.test.ts fakes it — what this
// map pins is the scope gate in front of the work, not the work.
vi.mock("@harpoc/cert-manager", () => ({ CertManager: mockCertManager }));

import { registerSecretListCommand } from "./secret/list.js";
import { registerSecretGetCommand } from "./secret/get.js";
import { registerSecretSetCommand } from "./secret/set.js";
import { registerSecretRotateCommand } from "./secret/rotate.js";
import { registerSecretDeleteCommand } from "./secret/delete.js";
import { registerSecretAllowCommand } from "./secret/allow.js";
import { registerSecretMcpServerCommand } from "./secret/mcp-server.js";
import { registerSecretConnectionCommand } from "./secret/connection.js";
import { registerPolicyGrantCommand } from "./policy/grant.js";
import { registerPolicyRevokeCommand } from "./policy/revoke.js";
import { registerPolicyListCommand } from "./policy/list.js";
import { registerAuditCommand } from "./audit.js";
import { registerOAuthStatusCommand } from "./oauth/status.js";
import { registerOAuthRefreshCommand } from "./oauth/refresh.js";
import { registerCertImportCommand } from "./cert/import.js";
import { registerCertStatusCommand } from "./cert/status.js";
import { registerCertCsrCommand } from "./cert/csr.js";
import { registerCertIssueCommand } from "./cert/issue.js";
import { registerCertRenewCommand } from "./cert/renew.js";
import { registerAgentRegisterCommand } from "./agent/register.js";
import { registerAgentListCommand } from "./agent/list.js";
import { registerAgentShowCommand } from "./agent/show.js";
import { registerAgentUpdateCommand } from "./agent/update.js";
import { registerAgentDeactivateCommand } from "./agent/deactivate.js";
import { registerAgentActivateCommand } from "./agent/activate.js";
import { registerAgentDeleteCommand } from "./agent/delete.js";
import { registerAgentPermissionsCommand } from "./agent/permissions.js";
import { registerAuthListCommand } from "./auth/list.js";

const FIXTURES = new URL("../__fixtures__/certs/", import.meta.url);
const KEY_PATH = fileURLToPath(new URL("rsa-key.pem", FIXTURES));
const CERT_PATH = fileURLToPath(new URL("rsa-cert.pem", FIXTURES));

function token(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "agent-1",
    vault_id: "vault-1",
    scope: ["read"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
    principal_type: "agent",
    ...overrides,
  };
}

const INFO = {
  handle: "secret://k",
  name: "k",
  type: "api_key",
  project: null,
  status: "active",
  version: 1,
  createdAt: 0,
  updatedAt: 0,
  expiresAt: null,
  rotatedAt: null,
};

const CERT_STATUS: CertificateStatus = {
  secret_id: "sid-1",
  subject: "CN=fixture.example.com",
  issuer: "CN=fixture.example.com",
  not_before: 1_787_000_000_000,
  not_after: 2_102_000_000_000,
  auto_renew: false,
  renewal_status: "ok",
};

const AGENT = {
  id: "agent-1",
  name: "bot",
  description: null,
  owner: null,
  status: "active",
  created_at: 0,
  updated_at: 0,
  deactivated_at: null,
  last_active_at: null,
  active_tokens: 0,
  grants: 0,
};

const POLICY = {
  id: "pol-1",
  secret_id: "sid-1",
  principal_type: "agent",
  principal_id: "bot",
  permissions: ["use"],
  created_at: 0,
  expires_at: null,
};

function buildProgram(): Command {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");

  registerAuditCommand(program);

  const secret = program.command("secret");
  registerSecretListCommand(secret);
  registerSecretGetCommand(secret);
  registerSecretSetCommand(secret);
  registerSecretRotateCommand(secret);
  registerSecretDeleteCommand(secret);
  registerSecretAllowCommand(secret);
  registerSecretMcpServerCommand(secret);
  registerSecretConnectionCommand(secret);

  const policy = program.command("policy");
  registerPolicyGrantCommand(policy);
  registerPolicyRevokeCommand(policy);
  registerPolicyListCommand(policy);

  const oauth = program.command("oauth");
  registerOAuthStatusCommand(oauth);
  registerOAuthRefreshCommand(oauth);

  const cert = program.command("cert");
  registerCertImportCommand(cert);
  registerCertStatusCommand(cert);
  registerCertCsrCommand(cert);
  registerCertIssueCommand(cert);
  registerCertRenewCommand(cert);

  const agent = program.command("agent");
  registerAgentRegisterCommand(agent);
  registerAgentListCommand(agent);
  registerAgentShowCommand(agent);
  registerAgentUpdateCommand(agent);
  registerAgentDeactivateCommand(agent);
  registerAgentActivateCommand(agent);
  registerAgentDeleteCommand(agent);
  registerAgentPermissionsCommand(agent);

  // Only `auth list` from the auth group (R4): `auth token` declares no
  // --token flag at all, so the pin below never sees it; `auth revoke` does
  // declare one, but it is the JWT whose expiry the command extracts — not a
  // scoped caller — so it stays out of the map, and registering it here would
  // red the exhaustiveness pin.
  const auth = program.command("auth");
  registerAuthListCommand(auth);

  return program;
}

function tokenCommandPaths(parent: Command, prefix: string[] = []): string[][] {
  const paths: string[][] = [];
  for (const child of parent.commands) {
    const path = [...prefix, child.name()];
    if (child.options.some((option) => option.long === "--token")) paths.push(path);
    paths.push(...tokenCommandPaths(child, path));
  }
  return paths;
}

async function run(args: string[]): Promise<void> {
  const program = buildProgram();
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", ...args]);
}

/**
 * A row's `call` is the mock the command must reach once the token carries the
 * permission — an engine method for the commands that address the engine
 * directly, a CertManager method for the cert commands whose work the manager
 * owns (neither `renewCertificate` nor the three creation entry points exist on
 * the engine, so there is no engine-side probe that would mean the same thing).
 * The names are disjoint across the two mocks.
 */
const PROBES = { ...mockEngine, ...mockManager };

interface Row {
  argv: string[];
  permission: Permission;
  call: keyof typeof PROBES;
}

// No "secret use" row: use predates this tranche and is pinned in secret/use.test.ts.
const ROWS: Row[] = [
  { argv: ["secret", "list"], permission: "list", call: "listSecrets" },
  { argv: ["secret", "get", "secret://k"], permission: "read", call: "getSecretInfo" },
  { argv: ["secret", "get", "secret://k", "--value"], permission: "read", call: "getSecretValue" },
  { argv: ["secret", "set", "k"], permission: "create", call: "createSecret" },
  { argv: ["secret", "rotate", "secret://k"], permission: "rotate", call: "rotateSecret" },
  {
    argv: ["secret", "delete", "secret://k", "--confirm"],
    permission: "revoke",
    call: "revokeSecret",
  },
  {
    argv: ["secret", "allow", "secret://k", "--show"],
    permission: "read",
    call: "getInjectionPolicy",
  },
  {
    argv: ["secret", "allow", "secret://k", "--url", "https://api.example.com/*"],
    permission: "rotate",
    call: "setInjectionPolicy",
  },
  {
    argv: ["secret", "mcp-server", "secret://k", "--show"],
    permission: "read",
    call: "getMcpServerConfig",
  },
  {
    argv: [
      "secret",
      "mcp-server",
      "secret://k",
      "--name",
      "srv",
      "--transport",
      "http",
      "--url",
      "https://mcp.example.com/mcp",
    ],
    permission: "rotate",
    call: "setMcpServerConfig",
  },
  {
    argv: ["secret", "mcp-server", "secret://k", "--delete"],
    permission: "rotate",
    call: "deleteMcpServerConfig",
  },
  {
    argv: ["secret", "connection", "secret://k", "--show"],
    permission: "read",
    call: "getConnectionConfig",
  },
  {
    argv: ["secret", "connection", "secret://k", "--db-tls", "require"],
    permission: "rotate",
    call: "setConnectionConfig",
  },
  {
    argv: ["secret", "connection", "secret://k", "--delete"],
    permission: "rotate",
    call: "deleteConnectionConfig",
  },
  { argv: ["policy", "list", "secret://k"], permission: "read", call: "listPolicies" },
  {
    argv: [
      "policy",
      "grant",
      "secret://k",
      "--principal-type",
      "agent",
      "--principal-id",
      "bot",
      "--permissions",
      "use",
    ],
    permission: "admin",
    call: "grantPolicy",
  },
  {
    argv: ["policy", "revoke", "pol-1", "--secret", "secret://k"],
    permission: "admin",
    call: "revokePolicy",
  },
  { argv: ["audit"], permission: "admin", call: "queryAudit" },
  { argv: ["audit", "verify"], permission: "admin", call: "verifyAuditChain" },
  { argv: ["audit", "anchor"], permission: "admin", call: "getAuditChainTail" },
  { argv: ["oauth", "status", "secret://k"], permission: "read", call: "getOAuthTokenStatus" },
  { argv: ["oauth", "refresh", "secret://k"], permission: "rotate", call: "refreshOAuthToken" },
  { argv: ["cert", "status", "secret://k"], permission: "read", call: "getCertificateStatus" },
  { argv: ["cert", "renew", "secret://k"], permission: "rotate", call: "renewCertificate" },
  // The three creation-scoped cert commands take the same shape `secret set`
  // does — one row apiece, `create` as the permission — because `create` is not
  // grantable per secret: token scope alone governs it, so the row is the whole
  // contract.
  {
    argv: ["cert", "import", "k", "--key", KEY_PATH, "--cert", CERT_PATH],
    permission: "create",
    call: "importCertificate",
  },
  {
    argv: ["cert", "csr", "k", "--subject", "fixture.example.com"],
    permission: "create",
    call: "generateCsr",
  },
  {
    argv: ["cert", "issue", "k", "--domains", "example.com", "--email", "ops@example.com"],
    permission: "create",
    call: "issueWithAcme",
  },
  // Agent governance (v1.4): no per-secret referent, so `admin` at the
  // interface is the whole gate — the same permission the REST routes check.
  // The matrix cell names a secret on top of that, and its row is the `admin`
  // one for the same reason `policy grant`'s is.
  { argv: ["agent", "register", "bot"], permission: "admin", call: "registerAgent" },
  { argv: ["agent", "list"], permission: "admin", call: "listAgents" },
  { argv: ["agent", "show", "bot"], permission: "admin", call: "getAgent" },
  {
    argv: ["agent", "update", "bot", "--owner", "ops"],
    permission: "admin",
    call: "updateAgent",
  },
  { argv: ["agent", "deactivate", "bot"], permission: "admin", call: "deactivateAgent" },
  { argv: ["agent", "activate", "bot"], permission: "admin", call: "activateAgent" },
  {
    argv: ["agent", "delete", "bot", "--confirm"],
    permission: "admin",
    call: "deleteAgent",
  },
  {
    argv: ["agent", "permissions", "bot", "secret://k", "--permissions", "use"],
    permission: "admin",
    call: "setAgentPermissions",
  },
  { argv: ["auth", "list"], permission: "admin", call: "listIssuedTokens" },
];

describe("token permission map (Task 9 pin)", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let stdoutWriteSpy: MockInstance;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;

    mockEngine.listSecrets.mockReturnValue([]);
    mockEngine.getSecretInfo.mockResolvedValue(INFO);
    mockEngine.getSecretValue.mockResolvedValue(new TextEncoder().encode("v"));
    mockEngine.createSecret.mockResolvedValue({ handle: "secret://k" });
    mockEngine.rotateSecret.mockResolvedValue(undefined);
    mockEngine.revokeSecret.mockResolvedValue(undefined);
    mockEngine.getInjectionPolicy.mockResolvedValue({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
      fs_isolation: false,
    });
    mockEngine.setInjectionPolicy.mockResolvedValue(undefined);
    mockEngine.getMcpServerConfig.mockResolvedValue({
      server_name: "srv",
      transport: "http",
      url: "https://mcp.example.com/mcp",
    });
    mockEngine.setMcpServerConfig.mockResolvedValue(undefined);
    mockEngine.deleteMcpServerConfig.mockResolvedValue(true);
    mockEngine.getConnectionConfig.mockResolvedValue({ database: { tls_mode: "require" } });
    mockEngine.setConnectionConfig.mockResolvedValue(undefined);
    mockEngine.deleteConnectionConfig.mockResolvedValue(true);
    mockEngine.listPolicies.mockReturnValue([POLICY]);
    mockEngine.grantPolicy.mockReturnValue(POLICY);
    mockEngine.revokePolicy.mockReturnValue(undefined);
    mockEngine.queryAudit.mockReturnValue([]);
    mockEngine.verifyAuditChain.mockReturnValue({
      valid: true,
      firstBrokenId: null,
      checked: 0,
      tail: null,
    });
    mockEngine.getAuditChainTail.mockReturnValue({
      format: "harpoc-audit-anchor/1",
      last_id: 1,
      row_hmac: "aa",
      timestamp: 0,
    });
    mockEngine.getOAuthTokenStatus.mockReturnValue({
      secret_id: "sid-1",
      provider: "github",
      has_access_token: true,
      access_token_expires_at: null,
      has_refresh_token: true,
      last_refreshed_at: null,
      refresh_status: "ok",
      token_endpoint_auth_method: null,
    });
    mockEngine.refreshOAuthToken.mockResolvedValue(2_000_000_000_000);
    mockEngine.getCertificateStatus.mockReturnValue(CERT_STATUS);
    mockEngine.registerAgent.mockReturnValue(AGENT);
    mockEngine.getAgent.mockReturnValue(AGENT);
    mockEngine.listAgents.mockReturnValue([AGENT]);
    mockEngine.updateAgent.mockReturnValue(AGENT);
    mockEngine.deactivateAgent.mockReturnValue({ revoked_tokens: 0 });
    mockEngine.activateAgent.mockReturnValue(AGENT);
    mockEngine.deleteAgent.mockReturnValue({ revoked_tokens: 0, removed_grants: 0 });
    mockEngine.setAgentPermissions.mockReturnValue({
      policy: POLICY,
      gated_before: true,
      gated_after: true,
    });
    mockEngine.listIssuedTokens.mockReturnValue([]);
    mockEngine.verifyToken.mockReturnValue(token());

    mockManager.importCertificate.mockResolvedValue({ handle: "secret://k", secretId: "sid-1" });
    mockManager.generateCsr.mockResolvedValue({
      handle: "secret://k",
      secretId: "sid-1",
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n",
    });
    mockManager.issueWithAcme.mockResolvedValue({
      handle: "secret://k",
      secretId: "sid-1",
      status: CERT_STATUS,
    });
    mockManager.renewCertificate.mockResolvedValue(CERT_STATUS);

    mockResolveSecretValue.mockResolvedValue(new TextEncoder().encode("v"));
    mockPromptConfirm.mockResolvedValue(true);

    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    stdoutWriteSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    // Same rationale as get.token.test.ts / list.token.test.ts et al.: a
    // blanket vi.restoreAllMocks() also tears down the vi.mock'd
    // loadUnlockedEngine (a bare vi.fn(), not a spy on a real function), so
    // restore only the spies actually created here.
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
    stdoutWriteSpy.mockRestore();
    if (savedEnvToken === undefined) delete process.env.HARPOC_TOKEN;
    else process.env.HARPOC_TOKEN = savedEnvToken;
  });

  describe.each(ROWS)("token permission map: $argv", ({ argv, permission, call }) => {
    it(`refuses a token without '${permission}' before the engine call`, async () => {
      mockEngine.verifyToken.mockReturnValue(token({ scope: [] }));
      await expect(run([...argv, "--token", "jwt-value"])).rejects.toThrow("process.exit");
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining(`Token lacks permission: ${permission}`),
      );
      expect(PROBES[call]).not.toHaveBeenCalled();
    });

    it(`executes with '${permission}' scope`, async () => {
      mockEngine.verifyToken.mockReturnValue(token({ scope: [permission] }));
      await run([...argv, "--token", "jwt-value"]);
      expect(PROBES[call]).toHaveBeenCalled();
    });
  });

  // Exhaustiveness, bounded by what buildProgram registers: a token-bearing
  // command added to the tree above without a row fails here instead of ageing
  // silently into an unpinned scope. It cannot see a command that is never
  // registered here at all — keeping buildProgram in step with index.ts stays a
  // reading exercise.
  it("pins every --token-bearing command the program registers", () => {
    const unpinned = tokenCommandPaths(buildProgram()).filter(
      (path) => !ROWS.some((row) => path.every((segment, i) => row.argv[i] === segment)),
    );
    expect(unpinned).toEqual([]);
  });
});
