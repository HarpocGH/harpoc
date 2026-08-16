import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import type { Permission, VaultApiToken } from "@harpoc/shared";

const { mockEngine, mockResolveSecretValue, mockPromptConfirm } = vi.hoisted(() => ({
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
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
  mockResolveSecretValue: vi.fn(),
  mockPromptConfirm: vi.fn(),
}));

vi.mock("../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("sid-1"),
}));
vi.mock("../utils/secret-value.js", () => ({ resolveSecretValue: mockResolveSecretValue }));
vi.mock("../utils/prompt.js", () => ({ promptConfirm: mockPromptConfirm }));

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

function token(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "agent-1",
    vault_id: "vault-1",
    scope: ["read"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
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

  return program;
}

async function run(args: string[]): Promise<void> {
  const program = buildProgram();
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", ...args]);
}

interface Row {
  argv: string[];
  permission: Permission;
  call: keyof typeof mockEngine;
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
];

describe("token permission map (Task 9 pin)", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let stdoutWriteSpy: ReturnType<typeof vi.spyOn>;
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
      legacy: 0,
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
    mockEngine.verifyToken.mockReturnValue(token());

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
      expect(mockEngine[call]).not.toHaveBeenCalled();
    });

    it(`executes with '${permission}' scope`, async () => {
      mockEngine.verifyToken.mockReturnValue(token({ scope: [permission] }));
      await run([...argv, "--token", "jwt-value"]);
      expect(mockEngine[call]).toHaveBeenCalled();
    });
  });
});
