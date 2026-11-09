import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import { Command } from "commander";
import { ErrorCode, VaultError } from "@harpoc/shared";

const {
  mockEngine,
  mockManager,
  mockCertManager,
  mockClient,
  MockRestClient,
  mockResolveSecretValue,
  mockPromptConfirm,
  mockPromptPassword,
} = vi.hoisted(() => {
  const manager = {
    importCertificate: vi.fn(),
    generateCsr: vi.fn(),
    renewCertificate: vi.fn(),
  };
  const client = {
    listSecrets: vi.fn(),
    getSecretInfo: vi.fn(),
    getSecretValue: vi.fn(),
    createSecret: vi.fn(),
    rotateSecret: vi.fn(),
    revokeSecret: vi.fn(),
    useSecret: vi.fn(),
    getInjectionPolicy: vi.fn(),
    setInjectionPolicy: vi.fn(),
    getMcpServerConfig: vi.fn(),
    setMcpServerConfig: vi.fn(),
    getConnectionConfig: vi.fn(),
    setConnectionConfig: vi.fn(),
    deleteConnectionConfig: vi.fn(),
    grantPolicy: vi.fn(),
    revokePolicy: vi.fn(),
    listPolicies: vi.fn(),
    queryAudit: vi.fn(),
    registerAgent: vi.fn(),
    listAgents: vi.fn(),
    getAgent: vi.fn(),
    updateAgent: vi.fn(),
    deactivateAgent: vi.fn(),
    activateAgent: vi.fn(),
    deleteAgent: vi.fn(),
    setAgentPermissions: vi.fn(),
    listTokens: vi.fn(),
    revokeToken: vi.fn(),
    getOAuthStatus: vi.fn(),
    refreshOAuthToken: vi.fn(),
    importCertificate: vi.fn(),
    generateCsr: vi.fn(),
    attachCertificate: vi.fn(),
    renewCertificate: vi.fn(),
    getCertificateStatus: vi.fn(),
    lockVault: vi.fn(),
  };
  return {
    mockEngine: {
      listSecrets: vi.fn(),
      getSecretInfo: vi.fn(),
      getSecretValue: vi.fn(),
      createSecret: vi.fn(),
      rotateSecret: vi.fn(),
      revokeSecret: vi.fn(),
      useSecret: vi.fn(),
      getInjectionPolicy: vi.fn(),
      setInjectionPolicy: vi.fn(),
      getMcpServerConfig: vi.fn(),
      setMcpServerConfig: vi.fn(),
      getConnectionConfig: vi.fn(),
      setConnectionConfig: vi.fn(),
      deleteConnectionConfig: vi.fn(),
      listPolicies: vi.fn(),
      grantPolicy: vi.fn(),
      revokePolicy: vi.fn(),
      queryAudit: vi.fn(),
      getOAuthTokenStatus: vi.fn(),
      refreshOAuthToken: vi.fn(),
      updateCertificate: vi.fn(),
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
      revokeToken: vi.fn(),
      lock: vi.fn(),
      verifyToken: vi.fn(),
      destroy: vi.fn().mockResolvedValue(undefined),
    },
    mockManager: manager,
    mockCertManager: vi.fn(function () {
      return manager;
    }),
    mockClient: client,
    MockRestClient: vi.fn(function () {
      return client;
    }),
    mockResolveSecretValue: vi.fn(),
    mockPromptConfirm: vi.fn(),
    mockPromptPassword: vi.fn(),
  };
});

vi.mock("./utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("sid-1"),
  refuseEmptyVaultDir: vi.fn(),
}));
vi.mock("./utils/secret-value.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./utils/secret-value.js")>()),
  resolveSecretValue: mockResolveSecretValue,
}));
vi.mock("./utils/prompt.js", () => ({
  promptConfirm: mockPromptConfirm,
  promptPassword: mockPromptPassword,
}));
vi.mock("@harpoc/cert-manager", () => ({ CertManager: mockCertManager }));
// RestClient is built with `new` by the REST-mode hook: a function implementation.
vi.mock("@harpoc/sdk", () => ({ RestClient: MockRestClient }));
// The real token-file reader, spied: the REST-mode hook and `server start` both read through it.
vi.mock("@harpoc/mcp-server", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@harpoc/mcp-server")>();
  return {
    ...actual,
    readLaunchTokenFile: vi.fn(actual.readLaunchTokenFile),
    createStdioServerFactory: vi.fn(),
  };
});
// Reached only if a root option captured `server start --token-file` again: no real stdio server.
vi.mock("@modelcontextprotocol/server/stdio", () => ({ serveStdio: vi.fn() }));

import { readLaunchTokenFile } from "@harpoc/mcp-server";
import { loadUnlockedEngine } from "./utils/vault-loader.js";
import { buildProgram } from "./program.js";
import { spyCli, type CliSpies } from "./__fixtures__/cli-harness.js";

const FIXTURES = new URL("./__fixtures__/certs/", import.meta.url);
const KEY_PATH = fileURLToPath(new URL("rsa-key.pem", FIXTURES));
const CERT_PATH = fileURLToPath(new URL("rsa-cert.pem", FIXTURES));
const CERT_PEM = readFileSync(CERT_PATH, "utf8");

const BASE = "http://127.0.0.1:3000";
const TOKEN = "rest-mode.jwt";
const CONSTRUCTED = { baseUrl: `${BASE}/`, token: TOKEN };
/** Never created: `ssh-agent status --consumer` probes the one socket path and lists nothing. */
const NO_RUNTIME_DIR = join(tmpdir(), "harpoc-rest-mode-no-runtime-dir");

let dir: string;
let tokenFile: string;
let valueFile: string;
let rest: string[];

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-rest-mode-"));
  tokenFile = join(dir, "token.jwt");
  valueFile = join(dir, "value.txt");
  writeFileSync(tokenFile, `${TOKEN}\n`);
  writeFileSync(valueFile, "v");
  rest = ["--url", BASE, "--token-file", tokenFile];
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

const INFO = {
  handle: "secret://k",
  name: "k",
  type: "api_key",
  project: null,
  status: "active",
  version: 1,
  createdAt: 1_700_000_000_000,
  updatedAt: 1_700_000_000_000,
  expiresAt: null,
  rotatedAt: null,
};
const CREATED = { handle: "secret://k", secret_id: "sid-1" };
const STORED_POLICY = {
  url_allowlist: [],
  command_allowlist: [],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: false,
  fs_isolation: false,
  smtp_recipient_allowlist: [],
  imap_read_only: false,
  strict_tree_exit: false,
  proxy: false,
  ssh_agent_socket: false,
};
const MCP_CONFIG = { server_name: "srv", transport: "http", url: "https://mcp.example.com/mcp" };
/** The config `--name srv --transport http --url …` parses to: the schema adds the default revision. */
const MCP_PARSED = { ...MCP_CONFIG, protocol: "2025-11-25" };
const CONNECTION = { database: { tls_mode: "disable" } };
const POLICY = {
  id: "pol-1-0000-0000",
  secret_id: "sid-1-0000-0000-0000",
  principal_type: "agent",
  principal_id: "bot",
  permissions: ["use"],
  created_at: 1_700_000_000_000,
  expires_at: null,
};
const AGENT = {
  id: "agent-1",
  name: "bot",
  description: null,
  owner: null,
  status: "active",
  created_at: 1_700_000_000_000,
  updated_at: 1_700_000_000_000,
  deactivated_at: null,
  last_active_at: null,
  active_tokens: 2,
  grants: 1,
};
const EVENT = {
  id: 7,
  timestamp: 1_700_000_000_000,
  event_type: "secret.read",
  secret_id: "sid-1",
  principal_type: "agent",
  principal_id: "bot",
  ip_address: null,
  session_id: "0123456789abcdef",
  success: true,
  detail: null,
};
const ISSUED = {
  jti: "jti-1",
  subject: "bot",
  principal_type: "agent",
  agent: "bot",
  scope: ["use", "list"],
  project: null,
  secrets: null,
  label: "ci",
  issued_at: 1_700_000_000_000,
  expires_at: 1_700_086_400_000,
  revoked_at: null,
  status: "active",
};
const OAUTH_STATUS = {
  secret_id: "sid-1",
  provider: "github",
  has_access_token: true,
  access_token_expires_at: 1_700_003_600_000,
  has_refresh_token: false,
  last_refreshed_at: null,
  refresh_status: "no_refresh_token",
  token_endpoint_auth_method: "client_secret_post",
};
const CERT_STATUS = {
  secret_id: "sid-1",
  subject: "CN=fixture.example.com",
  issuer: "CN=fixture.example.com",
  not_before: 1_787_000_000_000,
  not_after: 2_102_000_000_000,
  auto_renew: false,
  renewal_status: "ok",
};
const CSR_PEM = "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n";
const HTTP_ACTION = {
  type: "http",
  method: "GET",
  url: "https://api.example.com/v1",
  injection: { type: "bearer" },
};

let spies: CliSpies;
let stdoutWrite: MockInstance;
let sentValues: string[];

beforeEach(() => {
  vi.clearAllMocks();
  sentValues = [];

  mockEngine.listSecrets.mockReturnValue([INFO]);
  mockEngine.getSecretInfo.mockResolvedValue(INFO);
  mockEngine.getSecretValue.mockResolvedValue(new TextEncoder().encode("s3cret"));
  mockEngine.createSecret.mockResolvedValue(CREATED);
  mockEngine.useSecret.mockImplementation(async () => ({ type: "http", status: 200, body: "ok" }));
  mockEngine.getInjectionPolicy.mockResolvedValue(STORED_POLICY);
  mockEngine.getMcpServerConfig.mockResolvedValue(MCP_CONFIG);
  mockEngine.getConnectionConfig.mockResolvedValue(CONNECTION);
  mockEngine.deleteConnectionConfig.mockResolvedValue(true);
  mockEngine.listPolicies.mockReturnValue([POLICY]);
  mockEngine.grantPolicy.mockReturnValue(POLICY);
  mockEngine.queryAudit.mockReturnValue([EVENT]);
  mockEngine.getOAuthTokenStatus.mockReturnValue(OAUTH_STATUS);
  mockEngine.refreshOAuthToken.mockResolvedValue(1_700_007_200_000);
  mockEngine.getCertificateStatus.mockReturnValue(CERT_STATUS);
  mockEngine.registerAgent.mockReturnValue(AGENT);
  mockEngine.getAgent.mockReturnValue(AGENT);
  mockEngine.listAgents.mockReturnValue([AGENT]);
  mockEngine.updateAgent.mockReturnValue(AGENT);
  mockEngine.deactivateAgent.mockReturnValue({ revoked_tokens: 2 });
  mockEngine.activateAgent.mockReturnValue(AGENT);
  mockEngine.deleteAgent.mockReturnValue({ revoked_tokens: 2, removed_grants: 1 });
  mockEngine.setAgentPermissions.mockReturnValue({
    policy: POLICY,
    gated_before: true,
    gated_after: false,
  });
  mockEngine.listIssuedTokens.mockReturnValue([ISSUED]);
  mockManager.importCertificate.mockResolvedValue({ handle: "secret://c", secretId: "sid-2" });
  mockManager.generateCsr.mockResolvedValue({
    handle: "secret://c",
    secretId: "sid-2",
    csrPem: CSR_PEM,
  });
  mockManager.renewCertificate.mockResolvedValue(CERT_STATUS);

  mockClient.listSecrets.mockResolvedValue([INFO]);
  mockClient.getSecretInfo.mockResolvedValue(INFO);
  mockClient.getSecretValue.mockResolvedValue(new TextEncoder().encode("s3cret"));
  mockClient.createSecret.mockImplementation(async (input: { value: Uint8Array }) => {
    sentValues.push(Buffer.from(input.value).toString("utf8"));
    return CREATED;
  });
  mockClient.rotateSecret.mockImplementation(async (_handle: string, value: Uint8Array) => {
    sentValues.push(Buffer.from(value).toString("utf8"));
  });
  mockClient.useSecret.mockImplementation(async () => ({ type: "http", status: 200, body: "ok" }));
  mockClient.getInjectionPolicy.mockResolvedValue(STORED_POLICY);
  mockClient.getMcpServerConfig.mockResolvedValue(MCP_CONFIG);
  mockClient.getConnectionConfig.mockResolvedValue(CONNECTION);
  mockClient.deleteConnectionConfig.mockResolvedValue(true);
  mockClient.listPolicies.mockResolvedValue([POLICY]);
  mockClient.grantPolicy.mockResolvedValue(POLICY);
  mockClient.queryAudit.mockResolvedValue([EVENT]);
  mockClient.getOAuthStatus.mockResolvedValue(OAUTH_STATUS);
  mockClient.refreshOAuthToken.mockResolvedValue(1_700_007_200_000);
  mockClient.getCertificateStatus.mockResolvedValue(CERT_STATUS);
  mockClient.attachCertificate.mockResolvedValue(CERT_STATUS);
  mockClient.renewCertificate.mockResolvedValue(CERT_STATUS);
  mockClient.registerAgent.mockResolvedValue(AGENT);
  mockClient.getAgent.mockResolvedValue(AGENT);
  mockClient.listAgents.mockResolvedValue([AGENT]);
  mockClient.updateAgent.mockResolvedValue(AGENT);
  mockClient.deactivateAgent.mockResolvedValue({ revoked_tokens: 2 });
  mockClient.activateAgent.mockResolvedValue(AGENT);
  mockClient.deleteAgent.mockResolvedValue({ revoked_tokens: 2, removed_grants: 1 });
  mockClient.setAgentPermissions.mockResolvedValue({
    policy: POLICY,
    gated_before: true,
    gated_after: false,
  });
  mockClient.listTokens.mockResolvedValue([ISSUED]);
  mockClient.importCertificate.mockResolvedValue({ handle: "secret://c", secretId: "sid-2" });
  mockClient.generateCsr.mockResolvedValue({ handle: "secret://c", csrPem: CSR_PEM });

  mockResolveSecretValue.mockImplementation(async () => Buffer.from("v"));
  mockPromptConfirm.mockResolvedValue(true);

  spies = spyCli();
  stdoutWrite = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
});

afterEach(() => {
  spies.restore();
  stdoutWrite.mockRestore();
});

async function run(args: string[]): Promise<void> {
  const program = buildProgram();
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", ...args]);
}

interface Output {
  stdout: string;
  stderr: string;
  written: string;
}

async function capture(args: string[]): Promise<Output> {
  spies.logSpy.mockClear();
  spies.errorSpy.mockClear();
  stdoutWrite.mockClear();
  await run(args);
  return {
    stdout: spies.stdout(),
    stderr: spies.stderr(),
    written: stdoutWrite.mock.calls.map((call) => String(call[0])).join(""),
  };
}

/** Every RestClient member the run reached, with its argument lists. */
function clientCalls(): Record<string, unknown[][]> {
  return Object.fromEntries(
    Object.entries(mockClient)
      .filter(([, member]) => member.mock.calls.length > 0)
      .map(([name, member]) => [name, member.mock.calls]),
  );
}

interface RestRow {
  argv: string[];
  calls: Record<string, unknown[][]>;
  constructed?: Record<string, unknown>;
}

// Every command the REST mode serves: the RestClient member(s) with the whole argument list,
// no vault loaded, and the same output the in-process path prints for the same data.
const REST_ROWS: RestRow[] = [
  { argv: ["lock"], calls: { lockVault: [[]] } },
  { argv: ["secret", "get", "secret://k"], calls: { getSecretInfo: [["secret://k"]] } },
  {
    argv: ["secret", "get", "secret://k", "--value"],
    calls: { getSecretValue: [["secret://k"]] },
  },
  {
    argv: ["secret", "list", "--project", "p", "--type", "api_key"],
    calls: { listSecrets: [["p"]] },
  },
  {
    argv: ["secret", "set", "k", "--from-file", "<value>"],
    calls: {
      createSecret: [
        [{ name: "k", type: "api_key", project: undefined, value: expect.any(Uint8Array) }],
      ],
    },
  },
  {
    argv: ["secret", "rotate", "secret://k", "--from-file", "<value>"],
    calls: { rotateSecret: [["secret://k", expect.any(Uint8Array)]] },
  },
  {
    argv: ["secret", "delete", "secret://k", "--confirm"],
    calls: { revokeSecret: [["secret://k"]] },
  },
  {
    argv: [
      "secret",
      "use",
      "secret://k",
      "--action",
      "http",
      "--url",
      "https://api.example.com/v1",
    ],
    calls: { useSecret: [["secret://k", HTTP_ACTION]] },
    constructed: { ...CONSTRUCTED, timeoutMs: 1_860_000 },
  },
  {
    argv: ["secret", "allow", "secret://k", "--show"],
    calls: { getInjectionPolicy: [["secret://k"]] },
  },
  {
    argv: ["secret", "allow", "secret://k", "--url", "https://api.example.com/*"],
    calls: {
      getInjectionPolicy: [["secret://k"]],
      setInjectionPolicy: [
        [
          "secret://k",
          { ...STORED_POLICY, url_allowlist: ["https://api.example.com/*"] },
          { acknowledge_interpreters: false },
        ],
      ],
    },
  },
  {
    argv: ["secret", "allow", "secret://k", "--proxy"],
    calls: {
      getInjectionPolicy: [["secret://k"]],
      setInjectionPolicy: [
        ["secret://k", { ...STORED_POLICY, proxy: true }, { acknowledge_interpreters: false }],
      ],
    },
  },
  {
    argv: ["secret", "allow", "secret://k", "--ssh-agent-socket"],
    calls: {
      getInjectionPolicy: [["secret://k"]],
      getConnectionConfig: [["secret://k"]],
      setInjectionPolicy: [
        [
          "secret://k",
          { ...STORED_POLICY, ssh_agent_socket: true },
          { acknowledge_interpreters: false },
        ],
      ],
    },
  },
  {
    argv: ["secret", "mcp-server", "secret://k", "--show"],
    calls: { getMcpServerConfig: [["secret://k"]] },
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
    calls: { setMcpServerConfig: [["secret://k", MCP_PARSED]] },
  },
  {
    argv: ["secret", "connection", "secret://k", "--show"],
    calls: { getConnectionConfig: [["secret://k"]] },
  },
  {
    argv: ["secret", "connection", "secret://k", "--db-tls", "require"],
    calls: {
      getConnectionConfig: [["secret://k"]],
      setConnectionConfig: [["secret://k", { database: { tls_mode: "require" } }]],
    },
  },
  {
    argv: ["secret", "connection", "secret://k", "--delete"],
    calls: { deleteConnectionConfig: [["secret://k"]] },
  },
  {
    argv: ["audit", "--event", "secret.read", "--limit", "5"],
    calls: {
      queryAudit: [[{ secretId: undefined, eventType: "secret.read", since: undefined, limit: 5 }]],
    },
  },
  {
    argv: ["auth", "list", "--agent", "bot"],
    calls: { listTokens: [[{ agent: "bot", status: "active" }]] },
  },
  { argv: ["auth", "revoke", "jti-1"], calls: { revokeToken: [["jti-1"]] } },
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
      "use,read",
    ],
    calls: {
      grantPolicy: [
        [
          "secret://k",
          {
            principal_type: "agent",
            principal_id: "bot",
            permissions: ["use", "read"],
            expires_at: undefined,
          },
        ],
      ],
    },
  },
  {
    argv: ["policy", "revoke", "pol-1", "--secret", "secret://k"],
    calls: { revokePolicy: [["secret://k", "pol-1"]] },
  },
  { argv: ["policy", "list", "secret://k"], calls: { listPolicies: [["secret://k"]] } },
  {
    argv: ["agent", "register", "bot", "--description", "d"],
    calls: { registerAgent: [[{ name: "bot", description: "d", owner: undefined }]] },
  },
  { argv: ["agent", "list", "--all"], calls: { listAgents: [["all"]] } },
  { argv: ["agent", "show", "bot"], calls: { getAgent: [["bot"]] } },
  {
    argv: ["agent", "update", "bot", "--owner", "ops"],
    calls: {
      getAgent: [["bot"]],
      updateAgent: [["bot", { description: undefined, owner: "ops" }]],
    },
  },
  { argv: ["agent", "deactivate", "bot"], calls: { deactivateAgent: [["bot"]] } },
  { argv: ["agent", "activate", "bot"], calls: { activateAgent: [["bot"]] } },
  {
    argv: ["agent", "delete", "bot", "--confirm"],
    calls: { getAgent: [["bot"]], deleteAgent: [["bot"]] },
  },
  {
    argv: ["agent", "permissions", "bot", "secret://k", "--permissions", "use"],
    calls: {
      setAgentPermissions: [["bot", "secret://k", { permissions: ["use"], expires_at: undefined }]],
    },
  },
  { argv: ["oauth", "status", "secret://k"], calls: { getOAuthStatus: [["secret://k"]] } },
  { argv: ["oauth", "refresh", "secret://k"], calls: { refreshOAuthToken: [["secret://k"]] } },
  { argv: ["oauth", "providers"], calls: {} },
  { argv: ["proxy", "env", "agent", "secret://k"], calls: {} },
  {
    argv: ["ssh-agent", "status", "--consumer", "agent", "--runtime-dir", NO_RUNTIME_DIR],
    calls: {},
  },
  {
    argv: ["cert", "import", "c", "--key", KEY_PATH, "--cert", CERT_PATH],
    calls: {
      importCertificate: [
        [
          "c",
          {
            private_key_pem: "v",
            certificate_pem: CERT_PEM,
            chain_pem: undefined,
            project: undefined,
            renew_before_days: 30,
          },
        ],
      ],
    },
  },
  {
    argv: ["cert", "status", "secret://k"],
    calls: { getCertificateStatus: [["secret://k"]] },
  },
  {
    argv: ["cert", "csr", "c", "--subject", "svc.example.com"],
    calls: {
      generateCsr: [
        [
          "c",
          {
            subject: "svc.example.com",
            sans: undefined,
            algorithm: "ec",
            bits: undefined,
            curve: undefined,
            project: undefined,
          },
        ],
      ],
    },
  },
  { argv: ["cert", "renew", "secret://k"], calls: { renewCertificate: [["secret://k"]] } },
  {
    argv: ["cert", "attach", "secret://k", "--cert", CERT_PATH],
    calls: {
      attachCertificate: [["secret://k", { certificate_pem: CERT_PEM, chain_pem: undefined }]],
    },
  },
];

const withValueFile = (argv: string[]): string[] =>
  argv.map((arg) => (arg === "<value>" ? valueFile : arg));

describe("the REST mode of every REST-capable command (--url / --token-file)", () => {
  describe.each(REST_ROWS)("harpoc --url … $argv", ({ argv, calls, constructed }) => {
    it("reaches the RestClient member with the whole argument list, prints what the in-process path prints, loads no vault", async () => {
      const local = await capture(withValueFile(argv));
      vi.mocked(loadUnlockedEngine).mockClear();
      MockRestClient.mockClear();

      const remote = await capture([...rest, ...withValueFile(argv)]);

      expect(MockRestClient.mock.calls).toEqual([[constructed ?? CONSTRUCTED]]);
      expect(clientCalls()).toEqual(calls);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(spies.exitSpy).not.toHaveBeenCalled();
      expect(remote).toEqual(local);
    });
  });

  it("secret allow --proxy over REST prints the empty-allowlist note before the OK line (B2)", async () => {
    await capture([...rest, "secret", "allow", "secret://k", "--proxy"]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        "Note: secret://k is open to the egress proxy but allowlists no URL — the proxy brokers it to no origin until --url <pattern> adds one.",
      ],
      ["OK: Injection policy updated (secret://k)"],
    ]);
  });

  it("secret allow --ssh-agent-socket over REST reads the pin through the route and prints both notes before the OK line (B3)", async () => {
    await capture([...rest, "secret", "allow", "secret://k", "--ssh-agent-socket"]);
    expect(mockClient.getConnectionConfig.mock.calls).toEqual([["secret://k"]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        "Note: secret://k is open to the ssh-agent socket but allowlists no host — the socket signs with it for no host until --host <pattern> adds one.",
      ],
      [
        "Note: secret://k is open to the ssh-agent socket but pins no host key — the socket signs with it for no host until secret connection secret://k --known-host <line> pins one.",
      ],
      ["OK: Injection policy updated (secret://k)"],
    ]);
  });

  it("sends the value read from --from-file and wipes it after the call (secret set, secret rotate)", async () => {
    await run([...rest, "secret", "set", "k", "--from-file", valueFile]);
    await run([...rest, "secret", "rotate", "secret://k", "--from-file", valueFile]);
    expect(sentValues).toEqual(["v", "v"]);
    const created = mockClient.createSecret.mock.calls[0]?.[0] as { value: Uint8Array };
    const rotated = mockClient.rotateSecret.mock.calls[0]?.[1] as Uint8Array;
    expect([...created.value, ...rotated]).toEqual([0, 0]);
  });

  it("takes the two options in either order before the command (--token-file first)", async () => {
    await run(["--token-file", tokenFile, "--url", BASE, "secret", "list"]);
    expect(MockRestClient.mock.calls).toEqual([[CONSTRUCTED]]);
    expect(clientCalls()).toEqual({ listSecrets: [[undefined]] });
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("keeps a path prefix of --url and the = forms", async () => {
    await run([`--url=${BASE}/harpoc/`, `--token-file=${tokenFile}`, "secret", "list"]);
    expect(MockRestClient.mock.calls).toEqual([[{ baseUrl: `${BASE}/harpoc/`, token: TOKEN }]]);
  });

  it("renders a refusal of the server like the in-process path (the --json envelope)", async () => {
    mockClient.getSecretInfo.mockRejectedValueOnce(
      new VaultError(ErrorCode.ACCESS_DENIED, "Access denied: Token lacks permission: read"),
    );
    await expect(run([...rest, "secret", "get", "secret://k", "--json"])).rejects.toThrow(
      "process.exit",
    );
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        JSON.stringify({
          error: "ACCESS_DENIED",
          message: "Access denied: Token lacks permission: read",
        }),
      ],
    ]);
  });

  it("an unreachable server is CONNECTION_REFUSED naming the origin, not fetch's bare message", async () => {
    mockClient.listSecrets.mockRejectedValueOnce(new TypeError("fetch failed"));
    await expect(run([...rest, "secret", "list"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Error: [CONNECTION_REFUSED] Cannot reach the harpoc server at ${BASE}`],
    ]);
  });

  it("refuses agent update's set flag beside its clear twin INVALID_INPUT through the --json envelope, the server never contacted", async () => {
    await expect(
      run([
        ...rest,
        "agent",
        "update",
        "bot",
        "--description",
        "d",
        "--clear-description",
        "--json",
      ]),
    ).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        JSON.stringify({
          error: "INVALID_INPUT",
          message: "--description and --clear-description are mutually exclusive",
        }),
      ],
    ]);
    expect(clientCalls()).toEqual({});
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });
});

describe("the REST-mode refusals (the root preAction hook), before any prompt, vault or request", () => {
  const refusals: { label: string; args: () => string[]; line: string }[] = [
    {
      label: "--url without --token-file",
      args: () => ["--url", BASE, "secret", "list"],
      line: "Error: [INVALID_INPUT] --url requires --token-file <path> (the bearer token)",
    },
    {
      label: "--token-file without --url",
      args: () => ["--token-file", tokenFile, "secret", "list"],
      line: "Error: [INVALID_INPUT] --token-file before the command is the bearer of --url and requires it (server start's own --token-file goes after the command)",
    },
    {
      label: "--url with --vault-dir",
      args: () => [...rest, "--vault-dir", "/v", "secret", "list"],
      line: "Error: [INVALID_INPUT] --url and --vault-dir exclude each other: --url sends the command to a server, --vault-dir opens a local vault",
    },
    {
      label: "a per-command --token under --url",
      args: () => [...rest, "secret", "list", "--token", "jwt-value"],
      line: "Error: [INVALID_INPUT] --token is the bearer under --url; pass it through --token-file",
    },
    {
      label: "an empty --token-file",
      args: () => ["--url", BASE, "--token-file", "", "secret", "list"],
      line: "Error: [INVALID_INPUT] --token-file: empty path",
    },
    {
      label: "a flag taken as the --token-file path",
      args: () => ["--url", BASE, "--token-file", "--json", "secret", "list"],
      line: "Error: [INVALID_INPUT] --token-file: a flag, not a path (give a path that starts with a dash as ./-name)",
    },
    {
      label: "a handle without secret://",
      args: () => [...rest, "secret", "get", "k"],
      line: "Error: [INVALID_HANDLE] Invalid handle: k",
    },
  ];

  it.each(refusals)("refuses $label", async ({ args, line }) => {
    await expect(run(args())).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([[line]]);
    expect(MockRestClient).not.toHaveBeenCalled();
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("refuses an ambient HARPOC_TOKEN under --url (the bearer comes from --token-file only)", async () => {
    process.env.HARPOC_TOKEN = "ambient.jwt";
    await expect(run([...rest, "secret", "list"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        "Error: [INVALID_INPUT] HARPOC_TOKEN is set: under --url the bearer is read from --token-file only (unset HARPOC_TOKEN)",
      ],
    ]);
    expect(MockRestClient).not.toHaveBeenCalled();
  });

  it("refuses a plain-HTTP --url off loopback through the --json envelope, the value unnamed", async () => {
    await expect(
      run([
        "--url",
        "http://vault.example.com:3000",
        "--token-file",
        tokenFile,
        "secret",
        "list",
        "--json",
      ]),
    ).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        JSON.stringify({
          error: "INVALID_INPUT",
          message: "--url must use HTTPS (plain HTTP is allowed for loopback only)",
        }),
      ],
    ]);
    expect(spies.logSpy).not.toHaveBeenCalled();
  });

  it("refuses an unreadable --token-file with the reader's message, before the vault", async () => {
    const missing = join(dir, "missing.jwt");
    await expect(run(["--url", BASE, "--token-file", missing, "secret", "list"])).rejects.toThrow(
      "process.exit",
    );
    expect(readLaunchTokenFile).toHaveBeenCalledWith(missing);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        expect.stringMatching(
          /^Error: \[INVALID_INPUT\] Cannot read --token-file .*missing\.jwt: /,
        ),
      ],
    ]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("a --url without its value is Commander's missing-argument error", async () => {
    await expect(run(["--url"])).rejects.toMatchObject({
      code: "commander.optionMissingArgument",
      message: "error: option '--url <base>' argument missing",
    });
  });
});

describe("REST_MODE_UNSUPPORTED: the commands without a REST mode", () => {
  const unsupported: { args: string[]; message: string; json: boolean }[] = [
    { args: ["init"], message: "init has no REST mode; run it on the vault host", json: false },
    { args: ["unlock"], message: "unlock has no REST mode; run it on the vault host", json: false },
    {
      args: ["server", "start", "--rest"],
      message: "server start has no REST mode; run it on the vault host",
      json: false,
    },
    {
      args: ["audit", "anchor", "--json"],
      message: "audit anchor has no REST mode; run it on the vault host",
      json: true,
    },
    {
      args: ["audit", "verify", "--json"],
      message: "audit verify has no REST mode; run it on the vault host",
      json: true,
    },
    {
      args: ["auth", "token", "--agent", "bot", "--json"],
      message: "auth token has no REST mode; run it on the vault host",
      json: true,
    },
    {
      args: ["oauth", "connect", "gh", "--provider", "github", "--client-id", "x", "--json"],
      message: "oauth connect has no REST mode; run it on the vault host",
      json: true,
    },
    {
      args: [
        "cert",
        "issue",
        "c",
        "--domains",
        "a.example.com",
        "--email",
        "a@example.com",
        "--json",
      ],
      message: "cert issue has no REST mode; run it on the vault host",
      json: true,
    },
    {
      args: ["secret", "mcp-server", "secret://k", "--delete"],
      message: "secret mcp-server --delete has no REST mode; run it on the vault host",
      json: false,
    },
    {
      args: ["policy", "list", "--json"],
      message: "policy list without a handle has no REST mode; run it on the vault host",
      json: true,
    },
    {
      args: ["cert", "renew", "secret://k", "--http-port", "8080"],
      message: "cert renew --http-port has no REST mode; run it on the vault host",
      json: false,
    },
    {
      args: ["unlock-key", "enroll", "--out", "harpoc-unlock.key"],
      message: "unlock-key enroll has no REST mode; run it on the vault host",
      json: false,
    },
    {
      args: ["unlock-key", "revoke"],
      message: "unlock-key revoke has no REST mode; run it on the vault host",
      json: false,
    },
    {
      args: ["unlock-key", "status", "--json"],
      message: "unlock-key status has no REST mode; run it on the vault host",
      json: true,
    },
    {
      args: ["proxy", "ca", "init", "--name-constraints", "api.github.com", "--json"],
      message: "proxy ca init has no REST mode; run it on the vault host",
      json: true,
    },
    {
      args: ["proxy", "ca", "export"],
      message: "proxy ca export has no REST mode; run it on the vault host",
      json: false,
    },
  ];

  it.each(unsupported)("refuses $args", async ({ args, message, json }) => {
    await expect(run([...rest, ...args])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        json
          ? JSON.stringify({ error: "REST_MODE_UNSUPPORTED", message })
          : `Error: [REST_MODE_UNSUPPORTED] ${message}`,
      ],
    ]);
    expect(clientCalls()).toEqual({});
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockPromptPassword).not.toHaveBeenCalled();
  });

  it("policy revoke under --url requires --secret (the route addresses the policy through it)", async () => {
    await expect(run([...rest, "policy", "revoke", "pol-1"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        "Error: [INVALID_INPUT] --secret <handle> is required under --url: the REST route addresses the policy through its secret.",
      ],
    ]);
    expect(clientCalls()).toEqual({});
  });
});

describe("the commands' own --url and --token-file after the command stay theirs", () => {
  const missingLaunchToken = (): string => join(dir, "no-launch-token");

  it("server start --mcp --token-file <file> reads the launch-token file itself (model A)", async () => {
    await expect(
      run(["server", "start", "--mcp", "--token-file", missingLaunchToken()]),
    ).rejects.toThrow("process.exit");
    expect(vi.mocked(readLaunchTokenFile).mock.calls).toEqual([[missingLaunchToken()]]);
    expect(spies.errorSpy.mock.calls[0]).toEqual([
      expect.stringMatching(/^Error: Cannot read --token-file .*no-launch-token: /),
    ]);
    expect(MockRestClient).not.toHaveBeenCalled();
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("secret use … --url <target> is the action's URL, run in-process", async () => {
    await run([
      "secret",
      "use",
      "secret://k",
      "--action",
      "http",
      "--url",
      "https://api.example.com/v1",
    ]);
    expect(mockEngine.useSecret.mock.calls).toEqual([["secret://k", HTTP_ACTION, undefined]]);
    expect(MockRestClient).not.toHaveBeenCalled();
  });

  it("secret allow … --url <pattern> is the allowlist entry, run in-process", async () => {
    await run(["secret", "allow", "secret://k", "--url", "https://api.example.com/*"]);
    expect(mockEngine.setInjectionPolicy.mock.calls).toEqual([
      [
        "secret://k",
        { ...STORED_POLICY, url_allowlist: ["https://api.example.com/*"] },
        { acknowledge_interpreters: false },
        undefined,
      ],
    ]);
    expect(MockRestClient).not.toHaveBeenCalled();
  });

  it("secret mcp-server … --url <endpoint> is the downstream endpoint, run in-process", async () => {
    await run([
      "secret",
      "mcp-server",
      "secret://k",
      "--name",
      "srv",
      "--transport",
      "http",
      "--url",
      "https://mcp.example.com/mcp",
    ]);
    expect(mockEngine.setMcpServerConfig.mock.calls).toEqual([
      ["secret://k", MCP_PARSED, undefined],
    ]);
    expect(MockRestClient).not.toHaveBeenCalled();
  });

  it("a --url after a command that has none is Commander's unknown option", async () => {
    const written: string[] = [];
    const errWrite = vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      written.push(String(chunk));
      return true;
    });
    try {
      await expect(run(["secret", "list", "--url", BASE])).rejects.toThrow("process.exit");
    } finally {
      errWrite.mockRestore();
    }
    expect(written).toEqual(["error: unknown option '--url'\n"]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });
});

describe("the REST mode's place in the command tree", () => {
  // Pure groups carry no action. Everything else is classified here: a command added later reds
  // this row until it is listed as REST-capable (with a REST_ROWS row) or unsupported.
  const GROUPS = [
    "agent",
    "auth",
    "cert",
    "oauth",
    "policy",
    "proxy",
    "proxy ca",
    "secret",
    "server",
    "ssh-agent",
    "unlock-key",
  ];
  const REST_CAPABLE = [
    "agent activate",
    "agent deactivate",
    "agent delete",
    "agent list",
    "agent permissions",
    "agent register",
    "agent show",
    "agent update",
    "audit",
    "auth list",
    "auth revoke",
    "cert attach",
    "cert csr",
    "cert import",
    "cert renew",
    "cert status",
    "lock",
    "oauth providers",
    "oauth refresh",
    "oauth status",
    "policy grant",
    "policy list",
    "policy revoke",
    "proxy env",
    "secret allow",
    "secret connection",
    "secret delete",
    "secret get",
    "secret list",
    "secret mcp-server",
    "secret rotate",
    "secret set",
    "secret use",
    "ssh-agent status",
  ];
  const UNSUPPORTED = [
    "audit anchor",
    "audit verify",
    "auth token",
    "cert issue",
    "init",
    "oauth connect",
    "proxy ca export",
    "proxy ca init",
    "server start",
    "unlock",
    "unlock-key enroll",
    "unlock-key revoke",
    "unlock-key status",
  ];

  function paths(parent: Command, prefix: string[] = []): string[] {
    return parent.commands.flatMap((child) => {
      const path = [...prefix, child.name()];
      return [path.join(" "), ...paths(child, path)];
    });
  }

  it("classifies every command the program registers", () => {
    expect(paths(buildProgram()).sort()).toEqual(
      [...GROUPS, ...REST_CAPABLE, ...UNSUPPORTED].sort(),
    );
  });

  it("every REST-capable command has a REST_ROWS row", () => {
    const rowOf = (path: string): RestRow | undefined =>
      REST_ROWS.find((row) => row.argv.slice(0, path.split(" ").length).join(" ") === path);
    expect(REST_CAPABLE.filter((path) => rowOf(path) === undefined)).toEqual([]);
  });

  it("names both options in the root help", async () => {
    await expect(run(["--help"])).rejects.toMatchObject({ code: "commander.helpDisplayed" });
    const help = stdoutWrite.mock.calls.map((call) => String(call[0])).join("");
    expect(help).toContain("REST mode (both before the command):");
    expect(help).toContain("--url <base>");
    expect(help).toContain("--token-file <path>");
  });
});
