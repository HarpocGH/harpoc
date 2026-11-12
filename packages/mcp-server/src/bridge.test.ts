import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { startServer } from "@harpoc/rest-api";
import { RestClient } from "@harpoc/sdk";
import type { VaultClient } from "@harpoc/sdk";
import type { DecryptedAuditEvent, SecretInfo, VaultEngine } from "@harpoc/core";
import { AuditEventType, ErrorCode, HARPOC_VERSION, VaultError, VaultState } from "@harpoc/shared";
import type { ExpiringOAuthTokenInfo, UseSecretAction, VaultApiToken } from "@harpoc/shared";
import { createBridgeServer, restClientFromTokenFile } from "./bridge.js";
import { createMcpServer, createStdioServerFactory } from "./server.js";
import type { InMemoryMcpClient, InMemoryToolResult } from "@harpoc/test-utils";
import {
  connectInMemoryClient,
  connectModernInMemoryClient,
  expectVaultError,
  silenceAuditLines,
} from "@harpoc/test-utils";

silenceAuditLines();

const DAY_MS = 24 * 60 * 60 * 1000;
const BASE_URL = "http://127.0.0.1:1";

const SECRETS: SecretInfo[] = [
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
    expiresAt: Date.now() + 2 * DAY_MS,
    rotatedAt: 2000,
  },
];

const OAUTH: ExpiringOAuthTokenInfo[] = [
  {
    handle: "secret://gh",
    name: "gh",
    project: null,
    provider: "github",
    access_token_expires_at: 1_000,
    has_refresh_token: true,
    refresh_status: "expiring_soon",
  },
];

const AUDIT: DecryptedAuditEvent[] = [
  {
    id: 1,
    timestamp: 1000,
    event_type: AuditEventType.SECRET_READ,
    secret_id: "uuid-1",
    principal_type: "agent",
    principal_id: "bridge-agent",
    ip_address: null,
    session_id: null,
    success: true,
    detail: { handle: "secret://my-key" },
  },
];

function token(sub: string, scope: VaultApiToken["scope"]): VaultApiToken {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub,
    vault_id: "v",
    scope,
    iat: now,
    exp: now + 3600,
    jti: `jti-${sub}`,
    principal_type: "agent",
  };
}

function text(result: InMemoryToolResult): string {
  return (result.content[0] as { text: string }).text;
}

/** The engine `createMcpServer` reads for the advertised surface and the read-only results. */
function parityEngine(): VaultEngine {
  return {
    verifyToken: vi.fn().mockReturnValue(token("parity", ["admin"])),
    auditServerStart: vi.fn(),
    auditScopeRefusal: vi.fn(),
    isTokenRevoked: vi.fn().mockReturnValue(false),
    getState: vi.fn().mockReturnValue(VaultState.UNLOCKED),
    listSecrets: vi.fn().mockReturnValue(SECRETS),
    getSecretInfo: vi.fn().mockResolvedValue(SECRETS[0]),
    getExpiringOAuthTokenStatuses: vi.fn().mockReturnValue(OAUTH),
    getExpiringCertificateStatuses: vi.fn().mockReturnValue([]),
    queryAudit: vi.fn().mockReturnValue(AUDIT),
  } as unknown as VaultEngine;
}

/** The `VaultClient` members the bridge reads, answering what `parityEngine` holds. */
function parityClient(): VaultClient {
  return {
    listSecrets: vi.fn().mockResolvedValue(SECRETS),
    getSecretInfo: vi.fn().mockResolvedValue(SECRETS[0]),
    getHealth: vi.fn().mockResolvedValue({ state: VaultState.UNLOCKED, version: HARPOC_VERSION }),
    getExpiringReport: vi.fn().mockResolvedValue({
      expiring: [SECRETS[1]],
      oauth_refresh_needed: OAUTH,
      certificates_nearing_renewal: [],
    }),
    queryAudit: vi.fn().mockResolvedValue(AUDIT),
  } as unknown as VaultClient;
}

describe("the bridge advertises the in-process server's surface (B1 parity pin)", () => {
  let inProcess: InMemoryMcpClient;
  let bridge: InMemoryMcpClient;

  beforeAll(async () => {
    inProcess = await connectInMemoryClient(
      createMcpServer({ engine: parityEngine(), launchToken: "parity.launch.token" }),
    );
    const client = parityClient();
    bridge = await connectInMemoryClient(
      createBridgeServer({ client: () => client, baseUrl: BASE_URL }),
    );
  });

  afterAll(async () => {
    await inProcess.close();
    await bridge.close();
  });

  it("announces the same serverInfo and capabilities", () => {
    expect(bridge.client.getServerVersion()).toEqual(inProcess.client.getServerVersion());
    expect(bridge.client.getServerCapabilities()).toEqual(inProcess.client.getServerCapabilities());
  });

  it("tools/list is the in-process listing, byte for byte", async () => {
    const listed = await bridge.listTools();
    expect(listed).toEqual(await inProcess.listTools());
    expect(listed.map((tool) => tool.name)).toEqual([
      "list_secrets",
      "get_secret_info",
      "use_secret",
      "create_secret",
      "rotate_secret",
      "revoke_secret",
      "check_secret_health",
      "start_oauth_flow",
      "renew_certificate",
    ]);
  });

  it("resources/list and resources/templates/list are the in-process listings", async () => {
    expect(await bridge.client.listResources()).toEqual(await inProcess.client.listResources());
    expect(await bridge.client.listResourceTemplates()).toEqual(
      await inProcess.client.listResourceTemplates(),
    );
  });

  it("a 2026-07-28 client lists the in-process stdio factory's tools from the bridge's", async () => {
    const client = parityClient();
    const modernBridge = await connectModernInMemoryClient(() =>
      createBridgeServer({ client: () => client, baseUrl: BASE_URL }),
    );
    const modernInProcess = await connectModernInMemoryClient(
      createStdioServerFactory({ engine: parityEngine(), launchToken: "parity.launch.token" }),
    );
    try {
      expect(await modernBridge.listTools()).toEqual(await modernInProcess.listTools());
    } finally {
      await modernBridge.close();
      await modernInProcess.close();
    }
  });

  it.each([
    ["list_secrets", {}],
    ["list_secrets", { status: "active", type: "api_key" }],
    ["get_secret_info", { handle: "secret://my-key" }],
    ["check_secret_health", {}],
    ["check_secret_health", { handle: "secret://gh" }],
  ])("%s %j answers what the in-process tool answers over the same data", async (name, args) => {
    expect(await bridge.callTool(name, args)).toEqual(await inProcess.callTool(name, args));
  });

  it.each([
    "secret://vault/secrets",
    "secret://vault/secrets/prod%2Fdb-pass",
    "secret://vault/health",
    "secret://vault/audit/recent",
    "secret://vault/projects",
  ])("resource %s reads what the in-process resource reads", async (uri) => {
    expect(await bridge.readResource(uri)).toEqual(await inProcess.readResource(uri));
  });
});

describe("the bridge collects no value and drives no browser leg (B1)", () => {
  let client: VaultClient;
  let bridge: InMemoryMcpClient;

  beforeEach(async () => {
    client = {
      createSecret: vi.fn().mockResolvedValue({
        handle: "secret://new-key",
        status: "pending",
        message: "Secret created without value",
      }),
      startOAuthFlow: vi.fn().mockResolvedValue({
        handle: "secret://gh",
        status: "pending_authorization",
        auth_url: "https://github.com/login/device",
        user_code: "ABCD-1234",
        message: "Enter the code",
      }),
    } as unknown as VaultClient;
    bridge = await connectInMemoryClient(
      createBridgeServer({ client: () => client, baseUrl: BASE_URL }),
    );
  });

  afterEach(async () => {
    await bridge.close();
  });

  it("create_secret creates the secret without a value and answers the deferred path", async () => {
    const result = await bridge.callTool("create_secret", {
      name: "new-key",
      type: "api_key",
      project: "prod",
    });
    expect(result.isError).toBeUndefined();
    expect(JSON.parse(text(result))).toEqual({
      handle: "secret://new-key",
      status: "pending",
      message: "Secret created. Set the value with: harpoc secret set new-key --project prod",
    });
    expect(client.createSecret).toHaveBeenCalledWith({
      name: "new-key",
      type: "api_key",
      project: "prod",
    });
  });

  it.each([
    {
      label: "an unscoped api_key create",
      args: { name: "new-key", type: "api_key" },
      command: "harpoc secret set new-key",
    },
    {
      label: "a certificate-typed create",
      args: { name: "new-key", type: "certificate" },
      command: "harpoc secret set new-key --type certificate",
    },
    {
      label: "a project-scoped certificate-typed create",
      args: { name: "new-key", type: "certificate", project: "prod" },
      command: "harpoc secret set new-key --type certificate --project prod",
    },
  ])(
    "$label: the pending hint is the command that sets the value (F2)",
    async ({ args, command }) => {
      const result = await bridge.callTool("create_secret", args);
      expect(result.isError).toBeUndefined();
      expect(JSON.parse(text(result))).toEqual({
        handle: "secret://new-key",
        status: "pending",
        message: `Secret created. Set the value with: ${command}`,
      });
      expect(client.createSecret).toHaveBeenCalledWith(args);
    },
  );

  it.each([
    {
      label: "-x, an unscoped api_key create",
      args: { name: "-x", type: "api_key" },
      command: 'harpoc secret set "--" -x',
    },
    {
      label: "--help, an unscoped api_key create",
      args: { name: "--help", type: "api_key" },
      command: 'harpoc secret set "--" --help',
    },
    {
      label: "-p, a project-scoped create",
      args: { name: "-p", type: "api_key", project: "proj" },
      command: 'harpoc secret set --project proj "--" -p',
    },
    {
      label: "--from-file, a certificate-typed create",
      args: { name: "--from-file", type: "certificate" },
      command: 'harpoc secret set --type certificate "--" --from-file',
    },
    {
      label: "-p, a project-scoped certificate-typed create",
      args: { name: "-p", type: "certificate", project: "proj" },
      command: 'harpoc secret set --type certificate --project proj "--" -p',
    },
  ])(
    '$label: a name that begins with - is printed after a quoted "--", the options first (C-5, M2-R1)',
    async ({ args, command }) => {
      const result = await bridge.callTool("create_secret", args);
      expect(result.isError).toBeUndefined();
      expect(JSON.parse(text(result))).toEqual({
        handle: "secret://new-key",
        status: "pending",
        message: `Secret created. Set the value with: ${command}`,
      });
      expect(client.createSecret).toHaveBeenCalledWith(args);
    },
  );

  it("rotate_secret refuses, naming the vault user's command, and sends nothing", async () => {
    const result = await bridge.callTool("rotate_secret", { handle: "secret://prod/db-pass" });
    expect(result.isError).toBe(true);
    expect(text(result)).toBe(
      "rotate_secret is not available through the REST bridge: the new value would pass through the agent's process. Rotate it as the vault user: harpoc secret rotate secret://prod/db-pass",
    );
  });

  it.each([
    ["authorization_code", "harpoc oauth connect gh --provider github --client-id cid"],
    [
      "client_credentials",
      "harpoc oauth connect gh --client-credentials --provider github --client-id cid",
    ],
  ])("start_oauth_flow %s refuses, naming %s, and sends nothing", async (grant, command) => {
    const result = await bridge.callTool("start_oauth_flow", {
      name: "gh",
      provider: "github",
      grant_type: grant,
      client_id: "cid",
    });
    expect(result.isError).toBe(true);
    expect(text(result)).toBe(
      `start_oauth_flow's ${grant} grant is not available through the REST bridge. Complete it as the vault user: ${command}`,
    );
    expect(client.startOAuthFlow).not.toHaveBeenCalled();
  });

  describe("start_oauth_flow's hints (C-5)", () => {
    const GRANTS = [
      { grant: "authorization_code", flags: "--provider github" },
      { grant: "client_credentials", flags: "--client-credentials --provider github" },
    ];

    async function refusalOf(grant: string, secretName: string, clientId: string): Promise<string> {
      const result = await bridge.callTool("start_oauth_flow", {
        name: secretName,
        provider: "github",
        grant_type: grant,
        client_id: clientId,
      });
      expect(result.isError).toBe(true);
      expect(client.startOAuthFlow).not.toHaveBeenCalled();
      return text(result);
    }

    const lead = (grant: string): string =>
      `start_oauth_flow's ${grant} grant is not available through the REST bridge. Complete it as the vault user: harpoc oauth connect`;

    it.each(
      GRANTS.flatMap((g) => ["a b", "x;y", "$(z)", "-x"].map((clientId) => ({ ...g, clientId }))),
    )(
      "$grant: a client_id of $clientId is not a plain word and is printed as <client-id>",
      async ({ grant, flags, clientId }) => {
        expect(await refusalOf(grant, "gh", clientId)).toBe(
          `${lead(grant)} gh ${flags} --client-id <client-id>`,
        );
      },
    );

    it.each(
      GRANTS.flatMap((g) =>
        ["client-123", "1234-abc.apps.googleusercontent.com", "_m2m:tenant@idp/app+v=1-x"].map(
          (clientId) => ({ ...g, clientId }),
        ),
      ),
    )(
      "$grant: a plain-word client_id of $clientId is printed as today",
      async ({ grant, flags, clientId }) => {
        expect(await refusalOf(grant, "gh", clientId)).toBe(
          `${lead(grant)} gh ${flags} --client-id ${clientId}`,
        );
      },
    );

    it.each(
      GRANTS.flatMap((g) => [
        { ...g, secretName: "-x", clientId: "cid", printed: "cid" },
        { ...g, secretName: "--help", clientId: "a b", printed: "<client-id>" },
      ]),
    )(
      '$grant: a name of $secretName that begins with - is printed after a quoted "--", the options first (M2-R1)',
      async ({ grant, flags, secretName, clientId, printed }) => {
        expect(await refusalOf(grant, secretName, clientId)).toBe(
          `${lead(grant)} ${flags} --client-id ${printed} "--" ${secretName}`,
        );
      },
    );
  });

  it("start_oauth_flow device_code forwards the shared field set to the REST flow", async () => {
    const result = await bridge.callTool("start_oauth_flow", {
      name: "gh",
      provider: "github",
      grant_type: "device_code",
      client_id: "cid",
    });
    expect(result.isError).toBeUndefined();
    expect(JSON.parse(text(result))).toEqual({
      handle: "secret://gh",
      status: "pending_authorization",
      auth_url: "https://github.com/login/device",
      user_code: "ABCD-1234",
      message: "Enter the code",
    });
    expect(client.startOAuthFlow).toHaveBeenCalledWith({
      name: "gh",
      provider: "github",
      grant_type: "device_code",
      client_id: "cid",
    });
  });
});

describe("the bridge refuses at its own boundary what the shared tool schemas refuse (M1-R1)", () => {
  let fetchSpy: Mock;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => ({
        data: { handle: "secret://new-key", status: "pending", message: "Secret created" },
      }),
    });
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("create_secret with a 256-character name answers the input-validation error and makes no REST request", async () => {
    const bridge = await connectInMemoryClient(
      createBridgeServer({
        client: () => new RestClient({ baseUrl: BASE_URL, token: "bridge.jwt" }),
        baseUrl: BASE_URL,
      }),
    );
    try {
      const result = await bridge.callTool("create_secret", {
        name: "a".repeat(256),
        type: "api_key",
      });
      expect(fetchSpy.mock.calls.length).toBe(0);
      expect(result.isError).toBe(true);
      expect(text(result)).toContain("Input validation error");
      expect(text(result)).toMatch(/name: Too big/);
    } finally {
      await bridge.close();
    }
  });
});

describe("the bridge's client failures (B1)", () => {
  it("an unreachable REST server is a descriptive error, never fetch's own message", async () => {
    const client = {
      listSecrets: vi.fn().mockRejectedValue(new TypeError("fetch failed")),
    } as unknown as VaultClient;
    const bridge = await connectInMemoryClient(
      createBridgeServer({ client: () => client, baseUrl: BASE_URL }),
    );
    try {
      const result = await bridge.callTool("list_secrets", {});
      expect(result.isError).toBe(true);
      expect(text(result)).toBe(`Harpoc REST server unreachable: ${BASE_URL}`);
    } finally {
      await bridge.close();
    }
  });

  describe("restClientFromTokenFile", () => {
    let dir: string;
    let fetchSpy: Mock;

    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "harpoc-bridge-token-"));
      fetchSpy = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ data: { state: VaultState.UNLOCKED, version: HARPOC_VERSION } }),
      });
      vi.stubGlobal("fetch", fetchSpy);
    });

    afterEach(() => {
      vi.unstubAllGlobals();
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    it("reads the file for every call, so a rotated token is the one sent", async () => {
      const path = join(dir, "token.jwt");
      const clientFor = restClientFromTokenFile(BASE_URL, path);
      writeFileSync(path, "first.jwt\n", "utf8");
      await clientFor().getHealth();
      writeFileSync(path, "second.jwt\n", "utf8");
      await clientFor().getHealth();
      const sent = fetchSpy.mock.calls.map(
        (call) =>
          ((call as [string, RequestInit])[1].headers as Record<string, string>).authorization,
      );
      expect(sent).toEqual(["Bearer first.jwt", "Bearer second.jwt"]);
    });

    it("refuses a call whose file can no longer be read FILE_IO_ERROR, by path", async () => {
      const path = join(dir, "token.jwt");
      writeFileSync(path, "\n", "utf8");
      const err = await expectVaultError(
        () => restClientFromTokenFile(BASE_URL, path)(),
        ErrorCode.FILE_IO_ERROR,
      );
      expect(err.message).toBe(`--token-file ${path} is empty.`);
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });
});

describe("the bridge against a REST app on a loopback port (B1 round trip)", () => {
  const AGENT = token("bridge-agent", ["use", "list"]);
  const LIST_ONLY = token("bridge-agent", ["list"]);
  const ACTION: UseSecretAction = {
    type: "http",
    method: "GET",
    url: "https://api.example.com/v1/me",
    timeout_ms: 5000,
    injection: { type: "bearer" },
    follow_redirects: "none",
  };
  const RESPONSE = {
    type: "http",
    status: 200,
    headers: { "content-type": "application/json" },
    body: '{"ok":true}',
  };
  const CALLER = {
    principal_type: "agent",
    principal_id: "bridge-agent",
    interface: "rest",
    remote_address: "127.0.0.1",
  };

  const engine = {
    getState: vi.fn().mockReturnValue(VaultState.UNLOCKED),
    auditServerStart: vi.fn(),
    auditScopeRefusal: vi.fn(),
    verifyToken: vi.fn((jwt: string) => {
      if (jwt === "agent.jwt") return AGENT;
      if (jwt === "list-only.jwt") return LIST_ONLY;
      throw new VaultError(ErrorCode.INVALID_TOKEN, "Invalid token signature");
    }),
    listSecrets: vi.fn().mockReturnValue(SECRETS),
    getExpiringOAuthTokenStatuses: vi.fn().mockReturnValue(OAUTH),
    getExpiringCertificateStatuses: vi.fn().mockReturnValue([]),
    useSecret: vi.fn().mockResolvedValue(RESPONSE),
  };
  let server: Awaited<ReturnType<typeof startServer>>;
  let baseUrl: string;

  beforeAll(async () => {
    const banner = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      server = await startServer({ engine: engine as unknown as VaultEngine, port: 0 });
    } finally {
      banner.mockRestore();
    }
    baseUrl = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  beforeEach(() => {
    engine.useSecret.mockClear();
    engine.auditScopeRefusal.mockClear();
  });

  async function bridgeWith(jwt: string): Promise<InMemoryMcpClient> {
    return connectInMemoryClient(
      createBridgeServer({ client: () => new RestClient({ baseUrl, token: jwt }), baseUrl }),
    );
  }

  it("use_secret reaches the engine through POST /use and answers the route's result", async () => {
    const bridge = await bridgeWith("agent.jwt");
    try {
      const result = await bridge.callTool("use_secret", {
        handle: "secret://test-key",
        action: ACTION,
      });
      expect(result.isError).toBeUndefined();
      expect(JSON.parse(text(result))).toEqual(RESPONSE);
      expect(engine.useSecret).toHaveBeenCalledWith("secret://test-key", ACTION, CALLER);
    } finally {
      await bridge.close();
    }
  });

  it("check_secret_health reads GET /secrets, /health/expiring and /health", async () => {
    const bridge = await bridgeWith("agent.jwt");
    try {
      const result = await bridge.callTool("check_secret_health", {});
      expect(JSON.parse(text(result))).toEqual({
        vault_state: VaultState.UNLOCKED,
        total_secrets: 2,
        by_status: { active: 2 },
        expiring_soon: [{ handle: "secret://prod/db-pass", expires_at: SECRETS[1]?.expiresAt }],
        oauth_refresh_needed: OAUTH,
        certificates_nearing_renewal: [],
      });
    } finally {
      await bridge.close();
    }
  });

  it("a token the REST server refuses (401) is the tool's error, without the token", async () => {
    const bridge = await bridgeWith("forged.jwt");
    try {
      const result = await bridge.callTool("use_secret", {
        handle: "secret://test-key",
        action: ACTION,
      });
      expect(result.isError).toBe(true);
      expect(text(result)).toBe("Invalid token signature");
      expect(text(result)).not.toContain("forged.jwt");
      expect(engine.useSecret).not.toHaveBeenCalled();
    } finally {
      await bridge.close();
    }
  });

  it("a token without use (403) is the tool's error and REST's access.denied row, without the token", async () => {
    const bridge = await bridgeWith("list-only.jwt");
    try {
      const result = await bridge.callTool("use_secret", {
        handle: "secret://test-key",
        action: ACTION,
      });
      expect(result.isError).toBe(true);
      expect(text(result)).toBe("Access denied: Token lacks permission: use");
      expect(text(result)).not.toContain("list-only.jwt");
      expect(engine.auditScopeRefusal).toHaveBeenCalledWith(
        CALLER,
        "POST /api/v1/secrets/test-key/use",
        "permission",
      );
      expect(engine.useSecret).not.toHaveBeenCalled();
    } finally {
      await bridge.close();
    }
  });
});
