import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpServer } from "@harpoc/mcp-server";
import { providerConfigFromFlowInput } from "@harpoc/oauth-proxy";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";
import { callTool, parseToolResult } from "./helpers/mcp-helpers.js";
import { startMockOAuthProvider } from "./helpers/mock-oauth-provider.js";
import type { MockOAuthProvider } from "./helpers/mock-oauth-provider.js";

/**
 * OAuth lifecycle across the wired surfaces (Phase 10): REST authorize →
 * status → refresh → use_secret → audit, plus the MCP deferred
 * authorization-code path. Every provider leg runs against a real loopback
 * token endpoint, so what reaches the provider and what comes back over
 * Harpoc's own wire are separately observable.
 */

const PASSWORD = "oauth-lifecycle-pw";
const PRINCIPAL = "oauth-agent";
const CC_NAME = "cc-app";
const CC_CLIENT_ID = "cc-client";
const CC_CLIENT_SECRET = "cc-secret-1";
const CC_ACCESS_TOKEN = "at-cc-1";
const AC_NAME = "ac-app";
const AC_CLIENT_ID = "ac-client";
const AC_CLIENT_SECRET = "ac-secret-1";

let mock: MockOAuthProvider;
let sink: Server;
let sinkUrl: string;
let sinkAuthorization: string[];
let vault: TestVault;
let rest: TestServer;
let token: string;
let ccSecretId: string;
let acSecretId: string;
let seededExpiresAt: number;
let refreshedExpiresAt: number;

function authHeaders(): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

function jsonHeaders(): Record<string, string> {
  return { ...authHeaders(), "content-type": "application/json" };
}

beforeAll(async () => {
  mock = await startMockOAuthProvider();
  mock.setNextTokens({ access_token: CC_ACCESS_TOKEN, expires_in: 3600 });

  sinkAuthorization = [];
  sink = createServer((req, res) => {
    const authorization = (req.headers["authorization"] ?? "") as string;
    sinkAuthorization.push(authorization);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ echoed_authorization: authorization }));
  });
  await new Promise<void>((resolve) => sink.listen(0, "127.0.0.1", resolve));
  sinkUrl = `http://127.0.0.1:${(sink.address() as AddressInfo).port}`;

  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
  registerAgents(vault.engine, PRINCIPAL);
  rest = startTestServer(vault.engine);
  token = vault.engine.createToken(PRINCIPAL, ["create", "read", "rotate", "use"]);
});

afterAll(async () => {
  await rest.close();
  await destroyTestVault(vault).catch(() => {});
  await new Promise<void>((resolve, reject) =>
    sink.close((err) => (err ? reject(err) : resolve())),
  );
  await mock.close();
});

describe("OAuth lifecycle across REST, engine and MCP", () => {
  it("1. REST authorize runs client_credentials: the secret reaches the provider, never the response", async () => {
    const res = await fetch(`${rest.baseUrl}/api/v1/oauth/authorize`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({
        name: CC_NAME,
        provider: "custom",
        grant_type: "client_credentials",
        client_id: CC_CLIENT_ID,
        client_secret: CC_CLIENT_SECRET,
        token_endpoint: mock.tokenEndpoint,
      }),
    });

    expect(res.status).toBe(201);
    const raw = await res.text();
    const body = JSON.parse(raw) as { data: { handle: string; status: string; message: string } };
    expect(body.data.status).toBe("authorized");
    expect(body.data.handle).toBe(`secret://${CC_NAME}`);

    // The client secret was POSTed to the provider (client_secret_post is the
    // default auth method) and the access token was stored — neither crosses
    // back over Harpoc's wire.
    expect(mock.requests).toHaveLength(1);
    expect(mock.requests[0]).toMatchObject({
      grant_type: "client_credentials",
      client_id: CC_CLIENT_ID,
      client_secret: CC_CLIENT_SECRET,
    });
    ccSecretId = await vault.engine.resolveSecretId(`secret://${CC_NAME}`);

    // Positive control for the access-token needle: the vault really holds
    // at-cc-1, read back over the trusted local path. Without it the opacity
    // assertion below would pass just as well against a provider that never
    // honoured `setNextTokens` and handed out its default token instead.
    expect(await vault.engine.getOAuthAccessToken(ccSecretId)).toBe(CC_ACCESS_TOKEN);

    expect(raw).not.toContain(CC_CLIENT_SECRET);
    expect(raw).not.toContain(CC_ACCESS_TOKEN);
  });

  it("2. REST status reports the stored access token without a refresh token", async () => {
    const res = await fetch(`${rest.baseUrl}/api/v1/oauth/${CC_NAME}/status`, {
      headers: authHeaders(),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      data: {
        secret_id: string;
        provider: string;
        has_access_token: boolean;
        has_refresh_token: boolean;
      };
    };
    expect(body.data.secret_id).toBe(ccSecretId);
    expect(body.data.provider).toBe("custom");
    expect(body.data.has_access_token).toBe(true);
    expect(body.data.has_refresh_token).toBe(false);
  });

  it("3a. REST refresh on a client_credentials secret is refused before any provider call", async () => {
    // Tokens armed before the refusal on purpose: the provider is ready to
    // hand out at-2, so an unrecorded request would mean the engine POSTed.
    mock.setNextTokens({ access_token: "at-2", expires_in: 3600 });
    const before = mock.requests.length;

    const res = await fetch(`${rest.baseUrl}/api/v1/oauth/${CC_NAME}/refresh`, {
      method: "POST",
      headers: authHeaders(),
    });

    // Pinned: a client-credentials grant stores no refresh token, so the engine
    // refuses with OAUTH_REFRESH_FAILED (502 via the shared ERROR_STATUS table).
    expect(res.status).toBe(502);
    const raw = await res.text();
    expect(JSON.parse(raw)).toMatchObject({ error: ErrorCode.OAUTH_REFRESH_FAILED });
    expect(mock.requests.length).toBe(before);
  });

  it("3b. REST refresh on an authorization-code-shaped secret rotates the access token", async () => {
    const { config } = providerConfigFromFlowInput({
      name: AC_NAME,
      provider: "custom",
      grant_type: "authorization_code",
      client_id: AC_CLIENT_ID,
      client_secret: AC_CLIENT_SECRET,
      token_endpoint: mock.tokenEndpoint,
      auth_endpoint: mock.tokenEndpoint.replace(/\/token$/, "/authorize"),
    });
    const created = await vault.engine.createOAuthSecret(AC_NAME, config);
    acSecretId = created.secretId;
    seededExpiresAt = Date.now() + 30_000;
    await vault.engine.completeOAuthFlow(acSecretId, "at-1", "rt-1", seededExpiresAt);

    const res = await fetch(`${rest.baseUrl}/api/v1/oauth/${AC_NAME}/refresh`, {
      method: "POST",
      headers: authHeaders(),
    });

    expect(res.status).toBe(200);
    const raw = await res.text();
    const body = JSON.parse(raw) as { data: { refreshed: boolean; expires_at: number } };
    expect(body.data.refreshed).toBe(true);
    expect(body.data.expires_at).toBeGreaterThan(seededExpiresAt);
    refreshedExpiresAt = body.data.expires_at;

    // Exactly one more provider call than step 1's: the refresh_token is POSTed
    // once, so a double-exchange regression shows up here.
    expect(mock.requests).toHaveLength(2);
    const last = mock.requests[mock.requests.length - 1];
    expect(last).toMatchObject({
      grant_type: "refresh_token",
      refresh_token: "rt-1",
      client_id: AC_CLIENT_ID,
      client_secret: AC_CLIENT_SECRET,
    });
    expect(raw).not.toContain("rt-1");
    expect(raw).not.toContain("at-2");

    const status = vault.engine.getOAuthTokenStatus(acSecretId);
    expect(status.access_token_expires_at).toBe(refreshedExpiresAt);
    expect(status.has_refresh_token).toBe(true);
  });

  it("4. REST use_secret injects the refreshed token into the request, not the response", async () => {
    await vault.engine.setInjectionPolicy(`secret://${AC_NAME}`, {
      url_allowlist: [`${sinkUrl}/*`],
      command_allowlist: [],
      env_allowlist: [],
    });
    const providerCalls = mock.requests.length;

    const res = await fetch(`${rest.baseUrl}/api/v1/secrets/${AC_NAME}/use`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({
        action: {
          type: "http",
          method: "GET",
          url: `${sinkUrl}/echo`,
          injection: { type: "bearer" },
        },
      }),
    });

    expect(res.status).toBe(200);
    const raw = await res.text();
    expect(sinkAuthorization).toEqual(["Bearer at-2"]);
    expect(raw).not.toContain("at-2");
    expect(raw).not.toContain("at-1");
    // The stored token was still valid, so injection triggered no auto-refresh.
    expect(mock.requests.length).toBe(providerCalls);
  });

  it("5. the audit trail attributes create, refresh and use to the token's principal over rest", () => {
    const authorizeRows = vault.engine.queryAudit({
      eventType: AuditEventType.OAUTH_AUTHORIZE,
      secretId: ccSecretId,
    });
    expect(authorizeRows).toHaveLength(1);
    const createRow = authorizeRows[0];
    expect(createRow?.success).toBe(true);
    expect(createRow?.principal_id).toBe(PRINCIPAL);
    expect(createRow?.principal_type).toBe("agent");
    expect(createRow?.detail?.interface).toBe("rest");
    expect(createRow?.detail?.handle).toBe(`secret://${CC_NAME}`);
    expect(createRow?.detail?.grant_type).toBe("client_credentials");

    // Creation audits as oauth.authorize alone — the OAuth path never writes a
    // secret.create row, so that event type is the sole marker of a plain
    // secret creation.
    expect(vault.engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE })).toHaveLength(0);

    const refusedRows = vault.engine.queryAudit({
      eventType: AuditEventType.OAUTH_REFRESH,
      secretId: ccSecretId,
    });
    expect(refusedRows).toHaveLength(1);
    expect(refusedRows[0]?.success).toBe(false);
    expect(refusedRows[0]?.detail?.error).toBe(ErrorCode.OAUTH_REFRESH_FAILED);
    expect(refusedRows[0]?.principal_id).toBe(PRINCIPAL);
    expect(refusedRows[0]?.detail?.interface).toBe("rest");

    const refreshRows = vault.engine.queryAudit({
      eventType: AuditEventType.OAUTH_REFRESH,
      secretId: acSecretId,
    });
    expect(refreshRows).toHaveLength(1);
    expect(refreshRows[0]?.success).toBe(true);
    expect(refreshRows[0]?.principal_id).toBe(PRINCIPAL);
    expect(refreshRows[0]?.detail?.interface).toBe("rest");
    expect(refreshRows[0]?.detail?.new_expires_at).toBe(refreshedExpiresAt);

    const useRows = vault.engine.queryAudit({
      eventType: AuditEventType.SECRET_USE,
      secretId: acSecretId,
    });
    expect(useRows).toHaveLength(1);
    expect(useRows[0]?.success).toBe(true);
    expect(useRows[0]?.principal_id).toBe(PRINCIPAL);
    expect(useRows[0]?.detail?.interface).toBe("rest");
    expect(useRows[0]?.detail?.context).toBe("http");

    // The seeded authorization-code secret was created on the trusted local
    // path (no caller), which stays principal-NULL and interface-less (D4).
    const acAuthorize = vault.engine.queryAudit({
      eventType: AuditEventType.OAUTH_AUTHORIZE,
      secretId: acSecretId,
    });
    expect(acAuthorize).toHaveLength(1);
    expect(acAuthorize[0]?.principal_id).toBeNull();

    expect(vault.engine.verifyAuditChain().valid).toBe(true);
  });

  it("6. MCP start_oauth_flow defers the browser leg to the CLI and leaves the config PENDING", async () => {
    const mcpServer: McpServer = createMcpServer({
      engine: vault.engine,
      allowTokenless: true,
    });

    const result = await callTool(mcpServer, "start_oauth_flow", {
      name: "gh2",
      provider: "github",
      grant_type: "authorization_code",
      client_id: "cid",
    });

    expect(result.isError ?? false).toBe(false);
    const payload = parseToolResult(result, "start_oauth_flow") as {
      handle: string;
      status: string;
      message: string;
    };
    expect(payload.handle).toBe("secret://gh2");
    expect(payload.status).toBe("pending_authorization");
    expect(payload.message).toContain("harpoc oauth connect");

    const gh2Id = await vault.engine.resolveSecretId("secret://gh2");
    const status = vault.engine.getOAuthTokenStatus(gh2Id);
    expect(status.provider).toBe("github");
    expect(status.has_access_token).toBe(false);
    expect(status.has_refresh_token).toBe(false);
  });
});
