import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { VaultEngine } from "@harpoc/core";
import { createMcpServer } from "@harpoc/mcp-server";
import { createApp } from "@harpoc/rest-api";
import { DirectClient, RestClient } from "@harpoc/sdk";
import type { VaultClient } from "@harpoc/sdk";
import {
  AuditEventType,
  ErrorCode,
  HARPOC_VERSION,
  SecretStatus,
  SecretType,
  VaultState,
} from "@harpoc/shared";
import type { McpServer } from "@modelcontextprotocol/server";
import {
  createTestVault,
  destroyTestVault,
  grantOn,
  registerAgents,
} from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { callTool, parseToolResult } from "./helpers/mcp-helpers.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";
import { expectVaultError, silenceAuditLines } from "@harpoc/test-utils";

silenceAuditLines();

const PASSWORD = "integration-test-pw";
const SECRET_NAME = "my-api-key";
const SECRET_VALUE = "sk-test-abcdef1234567890ab";
const SECRET_VALUE_V2 = "sk-test-rotated-9876543210";

type ParityRead = (client: VaultClient, handle: string) => Promise<unknown>;
type ParityOracle = (engine: VaultEngine, handle: string) => unknown;

/** A read's result as the wire carries it: JSON, `undefined` kept as itself. */
function asJson(value: unknown): unknown {
  return value === undefined ? undefined : (JSON.parse(JSON.stringify(value)) as unknown);
}

const PARITY_READS: [string, ParityRead, ParityOracle][] = [
  ["listSecrets", (c) => c.listSecrets(), (e) => e.listSecrets()],
  ["getSecretInfo", (c, h) => c.getSecretInfo(h), (e, h) => e.getSecretInfo(h)],
  ["getInjectionPolicy", (c, h) => c.getInjectionPolicy(h), (e, h) => e.getInjectionPolicy(h)],
  ["getMcpServerConfig", (c, h) => c.getMcpServerConfig(h), (e, h) => e.getMcpServerConfig(h)],
  ["getConnectionConfig", (c, h) => c.getConnectionConfig(h), (e, h) => e.getConnectionConfig(h)],
  [
    "listPolicies",
    (c, h) => c.listPolicies(h),
    async (e, h) => e.listPolicies(await e.resolveSecretId(h)),
  ],
  [
    "queryAudit",
    (c) => c.queryAudit({ eventType: AuditEventType.SECRET_CREATE }),
    (e) => e.queryAudit({ eventType: AuditEventType.SECRET_CREATE }),
  ],
  ["listAgents", (c) => c.listAgents("all"), (e) => e.listAgents("all")],
  ["getAgent", (c) => c.getAgent("test-agent"), (e) => e.getAgent("test-agent")],
  [
    "listAgentPolicies",
    (c) => c.listAgentPolicies("test-agent"),
    (e) => e.listAgentPolicies("test-agent"),
  ],
  [
    "listTokens",
    (c) => c.listTokens({ status: "all" }),
    (e) => e.listIssuedTokens({ status: "all" }),
  ],
  ["getHealth", (c) => c.getHealth(), (e) => ({ state: e.getState(), version: HARPOC_VERSION })],
];

const PARITY_REFUSALS: [string, ErrorCode, ParityRead][] = [
  ["getOAuthStatus", ErrorCode.OAUTH_NOT_CONFIGURED, (c, h) => c.getOAuthStatus(h)],
  ["getCertificateStatus", ErrorCode.CERT_NOT_CONFIGURED, (c, h) => c.getCertificateStatus(h)],
];

/**
 * One write row's own world, built on the trusted path and named for the mode
 * and the member: a secret the REST token's principal administers, and an agent
 * holding one `read` grant on it and one live token — so no row reads or
 * mutates what another row touched, and the table runs in any order.
 */
interface WriteFixture {
  name: string;
  handle: string;
  secretId: string;
  value: string;
  agent: string;
  policyId: string;
  jti: string;
}

async function writeFixture(engine: VaultEngine, tag: string): Promise<WriteFixture> {
  const name = `wps-${tag}`;
  const handle = `secret://${name}`;
  const value = `wv-${tag}-9q4z`;
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from(value)),
  });
  await grantOn(engine, handle, "test-agent", ["admin"]);
  const agent = `wpa-${tag}`;
  const policy = await grantOn(engine, handle, agent, ["read"]);
  engine.createToken(agent, ["read"]);
  const [issued] = engine.listIssuedTokens({ agent, status: "all" });
  if (!issued) throw new Error(`no token issued for ${agent}`);
  const secretId = await engine.resolveSecretId(handle);
  return { name, handle, secretId, value, agent, policyId: policy.id, jti: issued.jti };
}

interface ParityWrite {
  member: string;
  /** The audit rows the write appends, in order, every one attributed to the mode's caller. */
  events: string[];
  prepare?: (engine: VaultEngine, f: WriteFixture) => void;
  write: (client: VaultClient, f: WriteFixture) => Promise<unknown>;
  /** The engine's state after the write — the client's answer read against it. */
  oracle: (engine: VaultEngine, f: WriteFixture, got: unknown) => Promise<void> | void;
}

const text = (bytes: Uint8Array): string => Buffer.from(bytes).toString("utf8");

const PARITY_WRITES: ParityWrite[] = [
  {
    member: "getSecretValue",
    events: [AuditEventType.SECRET_READ],
    write: (c, f) => c.getSecretValue(f.handle),
    oracle: (_e, f, got) => {
      expect(text(got as Uint8Array)).toBe(f.value);
    },
  },
  {
    member: "createSecret",
    events: [AuditEventType.SECRET_CREATE],
    write: (c, f) =>
      c.createSecret({
        name: `${f.name}-new`,
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from(`${f.value}-new`)),
      }),
    oracle: async (e, f, got) => {
      const handle = `secret://${f.name}-new`;
      expect(got).toEqual({ handle, status: "created", message: `Secret ${handle} created` });
      expect((await e.getSecretInfo(handle)).status).toBe(SecretStatus.ACTIVE);
      expect(text(await e.getSecretValue(handle))).toBe(`${f.value}-new`);
    },
  },
  {
    member: "rotateSecret",
    events: [AuditEventType.SECRET_ROTATE],
    write: (c, f) => c.rotateSecret(f.handle, new Uint8Array(Buffer.from(`${f.value}-v2`))),
    oracle: async (e, f, got) => {
      expect(got).toBeUndefined();
      expect((await e.getSecretInfo(f.handle)).version).toBe(2);
      expect(text(await e.getSecretValue(f.handle))).toBe(`${f.value}-v2`);
    },
  },
  {
    member: "revokeSecret",
    events: [AuditEventType.SECRET_REVOKE],
    write: (c, f) => c.revokeSecret(f.handle),
    oracle: async (e, f) => {
      expect((await e.getSecretInfo(f.handle)).status).toBe(SecretStatus.REVOKED);
    },
  },
  {
    member: "grantPolicy",
    events: [AuditEventType.POLICY_GRANT],
    write: (c, f) =>
      c.grantPolicy(f.handle, {
        principal_type: "agent",
        principal_id: f.agent,
        permissions: ["use"],
      }),
    oracle: (e, f, got) => {
      const granted = e.listPolicies(f.secretId).find((p) => p.id === (got as { id: string }).id);
      expect(granted).toMatchObject({ principal_id: f.agent, permissions: ["use"] });
      expect(asJson(got)).toEqual(asJson(granted));
    },
  },
  {
    member: "revokePolicy",
    events: [AuditEventType.POLICY_REVOKE],
    write: (c, f) => c.revokePolicy(f.handle, f.policyId),
    oracle: (e, f) => {
      expect(e.listPolicies(f.secretId).map((p) => p.id)).not.toContain(f.policyId);
    },
  },
  {
    member: "registerAgent",
    events: [AuditEventType.AGENT_REGISTER],
    write: (c, f) => c.registerAgent({ name: `${f.agent}-new`, description: "registered" }),
    oracle: (e, f, got) => {
      expect(got).toMatchObject({ name: `${f.agent}-new`, description: "registered" });
      expect(asJson(got)).toEqual(asJson(e.getAgent(`${f.agent}-new`)));
    },
  },
  {
    member: "updateAgent",
    events: [AuditEventType.AGENT_UPDATE],
    write: (c, f) => c.updateAgent(f.agent, { description: "updated", owner: "ops" }),
    oracle: (e, f, got) => {
      expect(got).toMatchObject({ description: "updated", owner: "ops" });
      expect(asJson(got)).toEqual(asJson(e.getAgent(f.agent)));
    },
  },
  {
    member: "deactivateAgent",
    events: [AuditEventType.TOKEN_REVOKE, AuditEventType.AGENT_DEACTIVATE],
    write: (c, f) => c.deactivateAgent(f.agent),
    oracle: (e, f, got) => {
      expect(got).toEqual({ revoked_tokens: 1 });
      expect(e.getAgent(f.agent).status).toBe("inactive");
    },
  },
  {
    member: "activateAgent",
    events: [AuditEventType.AGENT_ACTIVATE],
    prepare: (e, f) => {
      e.deactivateAgent(f.agent);
    },
    write: (c, f) => c.activateAgent(f.agent),
    oracle: (e, f, got) => {
      expect(got).toMatchObject({ name: f.agent, status: "active" });
      expect(asJson(got)).toEqual(asJson(e.getAgent(f.agent)));
    },
  },
  {
    member: "deleteAgent",
    events: [
      AuditEventType.TOKEN_REVOKE,
      AuditEventType.POLICY_REVOKE,
      AuditEventType.AGENT_DELETE,
    ],
    write: (c, f) => c.deleteAgent(f.agent),
    oracle: async (e, f, got) => {
      expect(got).toEqual({ revoked_tokens: 1, removed_grants: 1 });
      await expectVaultError(() => Promise.resolve(e.getAgent(f.agent)), ErrorCode.AGENT_NOT_FOUND);
    },
  },
  {
    member: "setAgentPermissions",
    events: [AuditEventType.POLICY_REVOKE, AuditEventType.POLICY_GRANT],
    write: (c, f) => c.setAgentPermissions(f.agent, f.handle, { permissions: ["read", "use"] }),
    oracle: (e, f, got) => {
      const cells = e.listPolicies(f.secretId).filter((p) => p.principal_id === f.agent);
      expect(cells).toHaveLength(1);
      expect([...(cells[0]?.permissions ?? [])].sort()).toEqual(["read", "use"]);
      expect(asJson((got as { policy: unknown }).policy)).toEqual(asJson(cells[0]));
    },
  },
  {
    member: "revokeToken",
    events: [AuditEventType.TOKEN_REVOKE],
    write: (c, f) => c.revokeToken(f.jti),
    oracle: (e, f, got) => {
      expect(got).toBeUndefined();
      const [issued] = e.listIssuedTokens({ agent: f.agent, status: "all" });
      expect(issued).toMatchObject({ jti: f.jti, status: "revoked" });
    },
  },
];

describe("Full Lifecycle", () => {
  let vault: TestVault;
  let mcpServer: McpServer;
  let echoServer: Server;
  let echoUrl: string;
  let restServer: TestServer;
  let token: string;
  let handle: string;

  beforeAll(async () => {
    // 1. Create echo HTTP server (echoes back request headers as JSON)
    echoServer = createServer((req, res) => {
      const body = JSON.stringify({
        method: req.method,
        url: req.url,
        headers: req.headers,
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
    });
    await new Promise<void>((resolve) => {
      echoServer.listen(0, "127.0.0.1", resolve);
    });
    const echoAddr = echoServer.address() as AddressInfo;
    echoUrl = `http://127.0.0.1:${echoAddr.port}`;

    // 2. Create VaultEngine, init vault, create secret
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "test-agent");

    const result = await vault.engine.createSecret({
      name: SECRET_NAME,
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from(SECRET_VALUE)),
    });
    handle = result.handle;
    await grantOn(vault.engine, handle, "test-agent", ["list", "read", "use", "rotate", "admin"]);
    await vault.engine.setInjectionPolicy(handle, { url_allowlist: [`${echoUrl}/*`] });

    // 3. Create JWT token for REST API auth
    token = vault.engine.createToken("test-agent", ["admin"]);

    // 4. Create MCP server
    mcpServer = createMcpServer({ engine: vault.engine, allowTokenless: true });

    // 5. Start real HTTP server for REST API (SDK RestClient)
    restServer = startTestServer(vault.engine);
  });

  afterAll(async () => {
    await mcpServer?.close();
    await restServer?.close();
    await new Promise<void>((resolve, reject) => {
      echoServer?.close((err) => (err ? reject(err) : resolve()));
    });
    await destroyTestVault(vault);
  });

  // ---- Test 1: initVault + createSecret -----------------------------------
  it("creates a secret with handle and active status", async () => {
    expect(handle).toBe(`secret://${SECRET_NAME}`);
    expect((await vault.engine.getSecretInfo(handle)).status).toBe(SecretStatus.ACTIVE);
  });

  // ---- Test 2: MCP list_secrets -------------------------------------------
  it("MCP list_secrets returns the secret without value", async () => {
    const result = await callTool(mcpServer, "list_secrets", {});
    const secrets = parseToolResult(result, "list_secrets") as Array<{
      handle: string;
      name: string;
    }>;
    expect(secrets).toHaveLength(1);
    const listed = secrets[0];
    if (!listed) throw new Error("expected a listed secret");
    expect(listed.handle).toBe(handle);
    expect(listed.name).toBe(SECRET_NAME);
    // Ensure no value field
    expect(Object.keys(listed)).not.toContain("value");
  });

  // ---- Test 3: MCP get_secret_info ----------------------------------------
  it("MCP get_secret_info returns correct metadata", async () => {
    const result = await callTool(mcpServer, "get_secret_info", { handle });
    const info = parseToolResult(result, "get_secret_info") as Record<string, unknown>;
    expect(info.name).toBe(SECRET_NAME);
    expect(info.type).toBe(SecretType.API_KEY);
    expect(info.status).toBe("active");
    expect(info.version).toBe(1);
  });

  // ---- Test 4: MCP use_secret + echo server -------------------------------
  it("MCP use_secret injects bearer token and sanitizes response", async () => {
    const result = await callTool(mcpServer, "use_secret", {
      handle,
      action: {
        type: "http",
        method: "GET",
        url: echoUrl,
        injection: { type: "bearer" },
      },
    });
    expect(result.isError).toBeFalsy();
    const response = parseToolResult(result, "use_secret") as { status: number; body: string };
    expect(response.status).toBe(200);

    // The echo server returned the Authorization header in the body.
    // InjectionGuard should have redacted the Bearer token in the body.
    expect(response.body).not.toContain(SECRET_VALUE);
  });

  // ---- Test 5: REST GET /api/v1/secrets -----------------------------------
  it("REST list secrets returns the secret", async () => {
    const app = createApp(vault.engine);
    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: `Bearer ${token}`, host: "localhost" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: Array<{ handle: string }> };
    expect(body.data).toHaveLength(1);
    expect(body.data[0]?.handle).toBe(handle);
  });

  // ---- Test 6: REST GET /api/v1/secrets/:handle ---------------------------
  it("REST get secret info returns matching metadata", async () => {
    const app = createApp(vault.engine);
    const encodedName = encodeURIComponent(SECRET_NAME);
    const res = await app.request(`/api/v1/secrets/${encodedName}`, {
      headers: { authorization: `Bearer ${token}`, host: "localhost" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { name: string; type: string; version: number } };
    expect(body.data.name).toBe(SECRET_NAME);
    expect(body.data.type).toBe(SecretType.API_KEY);
    expect(body.data.version).toBe(1);
  });

  // ---- Test 7: SDK DirectClient.getSecretInfo() ---------------------------
  it("SDK DirectClient getSecretInfo matches MCP and REST", async () => {
    const client = new DirectClient(vault.engine);
    const info = await client.getSecretInfo(handle);
    expect(info.name).toBe(SECRET_NAME);
    expect(info.type).toBe(SecretType.API_KEY);
    expect(info.version).toBe(1);
  });

  // ---- Test 8: SDK RestClient.listSecrets() over real HTTP ----------------
  it("SDK RestClient listSecrets over real HTTP returns secrets", async () => {
    const client = new RestClient({ baseUrl: restServer.baseUrl, token });
    const secrets = await client.listSecrets();
    expect(secrets.length).toBeGreaterThanOrEqual(1);
    expect(secrets.some((s) => s.handle === handle)).toBe(true);
  });

  // ---- Test 9: SDK RestClient.getSecretInfo() over real HTTP --------------
  it("SDK RestClient getSecretInfo over real HTTP matches", async () => {
    const client = new RestClient({ baseUrl: restServer.baseUrl, token });
    const info = await client.getSecretInfo(handle);
    expect(info.name).toBe(SECRET_NAME);
    expect(info.type).toBe(SecretType.API_KEY);
    expect(info.version).toBe(1);
  });

  // ---- Read-only parity: DirectClient and RestClient over the same input ---
  describe.each([
    ["DirectClient", (): VaultClient => new DirectClient(vault.engine)],
    ["RestClient", (): VaultClient => new RestClient({ baseUrl: restServer.baseUrl, token })],
  ])("%s read-only parity", (_label, makeClient) => {
    beforeAll(async () => {
      await vault.engine.setConnectionConfig(handle, { database: { tls_mode: "require" } });
      await vault.engine.setMcpServerConfig(handle, {
        server_name: "github-mcp",
        transport: "stdio",
        protocol: "2025-11-25",
        command: "node",
        args: ["server.js"],
        env_var: "GITHUB_TOKEN",
      });
    });

    it.each(PARITY_READS)("%s answers what the engine answers", async (_member, read, oracle) => {
      const got = asJson(await read(makeClient(), handle));
      expect(got).toEqual(asJson(await oracle(vault.engine, handle)));
    });

    it.each(PARITY_REFUSALS)(
      "%s refuses the api_key secret with %s",
      async (_member, code, read) => {
        await expectVaultError(() => read(makeClient(), handle), code);
      },
    );
  });

  // ---- Write parity (M-P1-7): the thirteen members on the real engine -----
  describe.each([
    ["DirectClient", "d", (): VaultClient => new DirectClient(vault.engine)],
    ["RestClient", "r", (): VaultClient => new RestClient({ baseUrl: restServer.baseUrl, token })],
  ])("%s write parity", (_label, mode, makeClient) => {
    it.each(PARITY_WRITES.map((row) => [row.member, row] as const))(
      "%s leaves the engine holding what it answered, attributed to the mode's caller",
      async (member, row) => {
        const f = await writeFixture(vault.engine, `${mode}-${member.toLowerCase()}`);
        row.prepare?.(vault.engine, f);
        const before = Math.max(...vault.engine.queryAudit().map((r) => r.id));

        const got = await row.write(makeClient(), f);

        const appended = vault.engine
          .queryAudit()
          .filter((r) => r.id > before)
          .sort((a, b) => a.id - b.id);
        expect(appended.map((r) => r.event_type)).toEqual(row.events);
        for (const r of appended) {
          // DirectClient is the trusted local path (no principal, no interface);
          // RestClient's rows carry the token's principal and the rest interface.
          expect(r.success).toBe(true);
          expect(r.principal_id).toBe(mode === "r" ? "test-agent" : null);
          expect(r.detail?.interface).toBe(mode === "r" ? "rest" : undefined);
        }
        await row.oracle(vault.engine, f, got);
      },
    );
  });

  // ---- REST write routes (M-P1-8): the wire body and the engine state -----
  describe("REST write routes over the real engine", () => {
    async function route(
      method: string,
      path: string,
      body?: unknown,
    ): Promise<{ status: number; json: unknown }> {
      const res = await fetch(`${restServer.baseUrl}/api/v1${path}`, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const raw = await res.text();
      try {
        return { status: res.status, json: JSON.parse(raw) as unknown };
      } catch {
        return { status: res.status, json: raw };
      }
    }

    it("DELETE /secrets/:handle?confirm=true revokes the secret", async () => {
      const f = await writeFixture(vault.engine, "route-delete");
      const res = await route("DELETE", `/secrets/${f.name}?confirm=true`);
      expect(res).toEqual({ status: 200, json: { data: { revoked: true } } });
      expect((await vault.engine.getSecretInfo(f.handle)).status).toBe(SecretStatus.REVOKED);
    });

    it("POST /secrets/:handle/rotate stores the decoded value as version 2", async () => {
      const f = await writeFixture(vault.engine, "route-rotate");
      const res = await route("POST", `/secrets/${f.name}/rotate`, {
        value: Buffer.from(`${f.value}-v2`).toString("base64"),
      });
      expect(res).toEqual({ status: 200, json: { data: { rotated: true } } });
      expect((await vault.engine.getSecretInfo(f.handle)).version).toBe(2);
      expect(text(await vault.engine.getSecretValue(f.handle))).toBe(`${f.value}-v2`);
    });

    it("PUT /agents/:name replaces the description and owner", async () => {
      const f = await writeFixture(vault.engine, "route-agent");
      const res = await route("PUT", `/agents/${f.agent}`, {
        description: "replaced",
        owner: "route-owner",
      });
      expect(res.status).toBe(200);
      expect(res.json).toEqual({ data: asJson(vault.engine.getAgent(f.agent)) });
      expect(vault.engine.getAgent(f.agent)).toMatchObject({
        description: "replaced",
        owner: "route-owner",
      });
    });

    it("DELETE /tokens/:jti revokes the issued token", async () => {
      const f = await writeFixture(vault.engine, "route-token");
      const res = await route("DELETE", `/tokens/${f.jti}`);
      expect(res).toEqual({ status: 200, json: { data: { revoked: true } } });
      expect(vault.engine.listIssuedTokens({ agent: f.agent, status: "all" })).toEqual([
        expect.objectContaining({ jti: f.jti, status: "revoked" }),
      ]);
    });

    it("POST /audit/verify answers the engine's chain report without the tail", async () => {
      const report = vault.engine.verifyAuditChain();
      const res = await route("POST", "/audit/verify");
      expect(report.valid).toBe(true);
      expect(res).toEqual({
        status: 200,
        json: { data: { valid: true, checked: report.checked, first_broken_id: null } },
      });
    });
  });

  // ---- Test 10: rotateSecret ----------------------------------------------
  it("rotateSecret bumps version to 2", async () => {
    await vault.engine.rotateSecret(handle, new Uint8Array(Buffer.from(SECRET_VALUE_V2)));
    const info = await vault.engine.getSecretInfo(handle);
    expect(info.version).toBe(2);
  });

  // ---- Test 11: MCP get_secret_info after rotation -------------------------
  it("MCP get_secret_info shows version=2 after rotation", async () => {
    const result = await callTool(mcpServer, "get_secret_info", { handle });
    const info = parseToolResult(result, "get_secret_info (after rotation)") as { version: number };
    expect(info.version).toBe(2);
  });

  // ---- Test 12: queryAudit ------------------------------------------------
  it("audit trail contains expected events in order", async () => {
    const events = vault.engine.queryAudit();
    const types = events.map((e) => e.event_type);
    // queryAudit returns newest-first — reverse to get chronological order
    const chronological = [...types].reverse();
    // The lifecycle secret's own rows: the write-parity fixtures add their own creates and rotates.
    const secretId = await vault.engine.resolveSecretId(handle);
    const lifecycle = [...events]
      .reverse()
      .filter((e) => e.secret_id === secretId)
      .map((e) => e.event_type);

    expect(chronological).toContain(AuditEventType.VAULT_UNLOCK);
    expect(lifecycle).toContain(AuditEventType.SECRET_CREATE);
    expect(lifecycle).toContain(AuditEventType.SECRET_ROTATE);

    // vault.unlock should be the earliest event
    expect(chronological[0]).toBe(AuditEventType.VAULT_UNLOCK);

    // secret.rotate should come after secret.create in chronological order
    const createIdx = lifecycle.indexOf(AuditEventType.SECRET_CREATE);
    const rotateIdx = lifecycle.indexOf(AuditEventType.SECRET_ROTATE);
    expect(rotateIdx).toBeGreaterThan(createIdx);
  });

  // ---- Test 13: lock → sealed, MCP errors, REST 503 ----------------------
  it("lock seals the vault — MCP returns error, REST returns 503", async () => {
    await vault.engine.lock();
    expect(vault.engine.getState()).toBe(VaultState.SEALED);

    // MCP tool should error
    const mcpResult = await callTool(mcpServer, "list_secrets", {});
    expect(mcpResult.isError).toBe(true);
    expect(mcpResult.content[0]?.text ?? "").toContain("Vault is locked");

    // REST should return 503
    const app = createApp(vault.engine);
    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: `Bearer ${token}`, host: "localhost" },
    });
    expect(res.status).toBe(503);
  });

  // ---- Test 14: re-unlock → audit trail persists --------------------------
  it("re-unlock preserves the audit trail", async () => {
    // Create a new engine pointing at the same DB
    const engine2 = new VaultEngine({
      dbPath: vault.dbPath,
      sessionPath: vault.sessionPath,
    });
    try {
      await engine2.unlock(PASSWORD);

      const events = engine2.queryAudit();
      const types = events.map((e) => e.event_type);
      const secretId = await engine2.resolveSecretId(handle);
      const lifecycle = events.filter((e) => e.secret_id === secretId).map((e) => e.event_type);
      // Should contain events from before lock + the new unlock
      expect(types.filter((t) => t === AuditEventType.VAULT_UNLOCK).length).toBeGreaterThanOrEqual(
        2,
      );
      expect(lifecycle).toContain(AuditEventType.SECRET_CREATE);
      expect(lifecycle).toContain(AuditEventType.SECRET_ROTATE);
    } finally {
      await engine2.destroy();
    }
  });
});
