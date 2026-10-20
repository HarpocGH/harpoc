import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { OAuthManager, providerConfigFromFlowInput } from "@harpoc/oauth-proxy";
import {
  createTestVault,
  destroyTestVault,
  grantOn,
  registerAgents,
} from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";
import { startMockOAuthProvider } from "./helpers/mock-oauth-provider.js";
import type { MockOAuthProvider } from "./helpers/mock-oauth-provider.js";
import { AuditEventType, ErrorCode, SecretStatus } from "@harpoc/shared";
import { silenceAuditLines } from "@harpoc/test-utils";

silenceAuditLines();

/**
 * REST background authorization-code flow (Phase 10, D2): `POST /oauth/authorize`
 * returns the auth URL immediately and the browser leg finishes behind the
 * request. The manager is injected so the flow the app started is the flow this
 * file can observe and cancel; the callback server and the token endpoint are
 * both real loopback servers, so the redirect and the code exchange are
 * observable from outside the vault. Case 5 revokes a secret while its browser
 * leg is pending and then drives the redirect: the late completion must not
 * revive it (code-review-2026-10-15 S4). Case 6 re-POSTs a PENDING name with a
 * token holding no `rotate` on it: the REST interface answers what an ACTIVE
 * collision answers and the first flow stands (S2).
 */

const PASSWORD = "oauth-background-pw";
const PRINCIPAL = "background-agent";
const OK_NAME = "bg-ok";
const PENDING_NAME = "bg-pending";
const REVOKED_NAME = "bg-revoked";
const GATED_NAME = "bg-gated";
const ACTIVE_NAME = "bg-active";
const CLIENT_ID = "bg-client";
const CLIENT_SECRET = "bg-secret-1";
const ACCESS_TOKEN = "at-bg-1";
const REFRESH_TOKEN = "rt-bg-1";
const AUTH_ENDPOINT = "https://auth.example/authorize";
const AUTH_CODE = "code-1";

let mock: MockOAuthProvider;
let vault: TestVault;
let manager: OAuthManager;
let rest: TestServer;
let token: string;
let backgroundErrors: { secretId: string; err: unknown }[];
let okAuthUrl: string;
let okState: string;
let okRedirectUri: string;
let okCodeChallenge: string;

function authHeaders(): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

function postAuthorize(name: string): Promise<Response> {
  return fetch(`${rest.baseUrl}/api/v1/oauth/authorize`, {
    method: "POST",
    headers: { ...authHeaders(), "content-type": "application/json" },
    body: JSON.stringify({
      name,
      provider: "custom",
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      auth_endpoint: AUTH_ENDPOINT,
      token_endpoint: mock.tokenEndpoint,
    }),
  });
}

interface StatusBody {
  data: {
    has_access_token: boolean;
    has_refresh_token: boolean;
    refresh_status: string;
    access_token_expires_at: number | null;
  };
}

async function getStatus(name: string): Promise<{ raw: string; body: StatusBody }> {
  const res = await fetch(`${rest.baseUrl}/api/v1/oauth/${name}/status`, {
    headers: authHeaders(),
  });
  expect(res.status).toBe(200);
  const raw = await res.text();
  return { raw, body: JSON.parse(raw) as StatusBody };
}

beforeAll(async () => {
  mock = await startMockOAuthProvider();
  mock.setNextTokens({
    access_token: ACCESS_TOKEN,
    refresh_token: REFRESH_TOKEN,
    expires_in: 3600,
  });

  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
  registerAgents(vault.engine, PRINCIPAL);

  backgroundErrors = [];
  manager = new OAuthManager(vault.engine, {
    callbackPort: 0,
    // REST never runs the browser leg; this file plays the browser itself.
    openBrowser: async () => {},
    onBackgroundFlowError: (secretId, err) => backgroundErrors.push({ secretId, err }),
  });
  rest = startTestServer(vault.engine, { oauthManager: manager });
  token = vault.engine.createToken(PRINCIPAL, ["create", "read"]);
});

afterAll(async () => {
  manager.cancelPendingFlows();
  await rest.close();
  await destroyTestVault(vault);
  await mock.close();
});

describe("REST background authorization-code flow", () => {
  it("1. authorize answers 201 pending_authorization with an auth URL and no flow internals", async () => {
    const res = await postAuthorize(OK_NAME);
    await grantOn(vault.engine, `secret://${OK_NAME}`, PRINCIPAL, ["read", "rotate"]);

    expect(res.status).toBe(201);
    const raw = await res.text();
    const body = JSON.parse(raw) as {
      data: { handle: string; status: string; auth_url: string; message: string };
    };
    expect(body.data.handle).toBe(`secret://${OK_NAME}`);
    expect(body.data.status).toBe("pending_authorization");
    expect(body.data.message).toContain("auth_url");
    okAuthUrl = body.data.auth_url;

    // The internal secretId and the background `completion` promise stay off the
    // wire (D2) — the response is exactly these four fields.
    expect(Object.keys(body.data).sort()).toEqual(["auth_url", "handle", "message", "status"]);
    expect(raw).not.toContain(CLIENT_SECRET);

    // The start resolved before any redirect, so nothing has been exchanged yet.
    expect(mock.requests).toHaveLength(0);
    const { body: status } = await getStatus(OK_NAME);
    expect(status.data.has_access_token).toBe(false);
  });

  it("2. the auth URL carries the live loopback redirect URI and an S256 challenge", () => {
    const authUrl = new URL(okAuthUrl);
    expect(authUrl.origin + authUrl.pathname).toBe(AUTH_ENDPOINT);
    expect(authUrl.searchParams.get("response_type")).toBe("code");
    expect(authUrl.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");

    okState = authUrl.searchParams.get("state") as string;
    okRedirectUri = authUrl.searchParams.get("redirect_uri") as string;
    okCodeChallenge = authUrl.searchParams.get("code_challenge") as string;
    expect(okState).toMatch(/^[0-9a-f]{64}$/);
    expect(okCodeChallenge).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // callbackPort 0 means the redirect URI has to carry the actually bound
    // loopback port, otherwise the browser leg could never reach the vault.
    const redirect = new URL(okRedirectUri);
    expect(redirect.protocol).toBe("http:");
    expect(redirect.hostname).toBe("localhost");
    expect(redirect.pathname).toBe("/oauth/callback");
    expect(Number(redirect.port)).toBeGreaterThan(0);
  });

  it("3. the simulated browser redirect drives the exchange and stores the token", async () => {
    const redirect = await fetch(`${okRedirectUri}?code=${AUTH_CODE}&state=${okState}`);
    expect(redirect.status).toBe(200);

    let statusRaw = "";
    await vi.waitFor(
      async () => {
        const { raw, body } = await getStatus(OK_NAME);
        statusRaw = raw;
        expect(body.data.has_access_token).toBe(true);
      },
      { timeout: 5_000, interval: 200 },
    );

    const { body: status } = await getStatus(OK_NAME);
    expect(status.data.has_refresh_token).toBe(true);
    expect(status.data.refresh_status).toBe("ok");
    expect(status.data.access_token_expires_at).toBeGreaterThan(Date.now());
    expect(statusRaw).not.toContain(ACCESS_TOKEN);
    expect(statusRaw).not.toContain(REFRESH_TOKEN);

    // Exactly one exchange reached the provider, carrying the redirect's code and
    // the verifier whose S256 hash is the challenge the auth URL advertised —
    // the PKCE pair the vault kept in memory, never on the wire.
    expect(mock.requests).toHaveLength(1);
    const exchange = mock.requests[0] as Record<string, string>;
    expect(exchange).toMatchObject({
      grant_type: "authorization_code",
      code: AUTH_CODE,
      redirect_uri: okRedirectUri,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });
    const codeVerifier = exchange.code_verifier as string;
    expect(codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(createHash("sha256").update(codeVerifier).digest("base64url")).toBe(okCodeChallenge);
    expect(okAuthUrl).not.toContain(codeVerifier);
  });

  it("4. an unfetched callback leaves the secret pending, and a re-POST resumes the same handle", async () => {
    const firstRes = await postAuthorize(PENDING_NAME);
    await grantOn(vault.engine, `secret://${PENDING_NAME}`, PRINCIPAL, ["read", "rotate"]);
    expect(firstRes.status).toBe(201);
    const first = (await firstRes.json()) as {
      data: { handle: string; auth_url: string };
    };
    const firstPort = new URL(
      new URL(first.data.auth_url).searchParams.get("redirect_uri") as string,
    ).port;

    // No redirect is ever fetched for this leg: the secret stays PENDING.
    const { body: pending } = await getStatus(PENDING_NAME);
    expect(pending.data.has_access_token).toBe(false);
    expect(pending.data.refresh_status).toBe("no_refresh_token");
    expect(mock.requests).toHaveLength(1);
    const pendingId = await vault.engine.resolveSecretId(`secret://${PENDING_NAME}`);

    // A second identical POST resumes the PENDING secret — same handle, not a
    // duplicate — and supersedes the first flow.
    const secondRes = await postAuthorize(PENDING_NAME);
    expect(secondRes.status).toBe(201);
    const second = (await secondRes.json()) as {
      data: { handle: string; status: string; auth_url: string };
    };
    expect(second.data.handle).toBe(first.data.handle);
    expect(second.data.status).toBe("pending_authorization");
    // Same secret row, not a replacement: a delete-and-recreate would answer
    // with the same handle but a different id, which is what distinguishes a
    // resume from a silent teardown of the caller's secret.
    expect(await vault.engine.resolveSecretId(`secret://${PENDING_NAME}`)).toBe(pendingId);
    const secondPort = new URL(
      new URL(second.data.auth_url).searchParams.get("redirect_uri") as string,
    ).port;
    expect(secondPort).not.toBe(firstPort);

    // The superseded flow's callback server is gone, so its redirect can no
    // longer be exchanged behind the caller's back...
    await vi.waitFor(async () => {
      await expect(fetch(`http://127.0.0.1:${firstPort}/not-the-callback`)).rejects.toThrow();
    });
    // ...and the abort is a cancellation, not a background failure.
    expect(backgroundErrors).toEqual([]);

    // The survivor is the injected manager's flow: the app runs the manager this
    // file handed it, so the pending browser leg is cancellable from here.
    const probe = await fetch(`http://127.0.0.1:${secondPort}/not-the-callback`);
    expect(probe.status).toBe(404);
    expect(manager.cancelFlow(pendingId)).toBe(true);

    const { body: after } = await getStatus(PENDING_NAME);
    expect(after.data.has_access_token).toBe(false);
    expect(mock.requests).toHaveLength(1);
    expect(backgroundErrors).toEqual([]);
  });

  it("5. a callback after the secret was revoked does not revive it: the completion refuses SECRET_REVOKED and the secret stays revoked (S4)", async () => {
    const res = await postAuthorize(REVOKED_NAME);
    expect(res.status).toBe(201);
    const started = (await res.json()) as { data: { handle: string; auth_url: string } };
    const handle = started.data.handle;
    const authUrl = new URL(started.data.auth_url);
    const redirectUri = authUrl.searchParams.get("redirect_uri") as string;
    const state = authUrl.searchParams.get("state") as string;
    const port = new URL(redirectUri).port;
    const secretId = await vault.engine.resolveSecretId(handle);

    await vault.engine.revokeSecret(handle);
    expect((await vault.engine.getSecretInfo(handle)).status).toBe(SecretStatus.REVOKED);
    const exchangesBefore = mock.requests.length;

    const redirect = await fetch(`${redirectUri}?code=${AUTH_CODE}&state=${state}`);
    expect(redirect.status).toBe(200);
    await vi.waitFor(async () => {
      await expect(fetch(`http://127.0.0.1:${port}/not-the-callback`)).rejects.toThrow();
    });

    expect((await vault.engine.getSecretInfo(handle)).status).toBe(SecretStatus.REVOKED);
    expect(vault.engine.getOAuthTokenStatus(secretId).has_access_token).toBe(false);
    expect(mock.requests.length).toBe(exchangesBefore + 1);
    await vi.waitFor(() => {
      expect(backgroundErrors.filter((e) => e.secretId === secretId)).toHaveLength(1);
    });
    expect(backgroundErrors.find((e) => e.secretId === secretId)?.err).toMatchObject({
      code: ErrorCode.SECRET_REVOKED,
    });

    const callbackRows = vault.engine.queryAudit({
      secretId,
      eventType: AuditEventType.OAUTH_CALLBACK,
    });
    expect(callbackRows).toHaveLength(1);
    expect(callbackRows[0]).toMatchObject({ success: false });
    expect(callbackRows[0]?.detail).toMatchObject({ error: ErrorCode.SECRET_REVOKED });
  });

  it("6. a re-POST by a token without rotate on the PENDING secret is refused 409 DUPLICATE_SECRET like an ACTIVE collision, and the first flow stands", async () => {
    const firstRes = await postAuthorize(GATED_NAME);
    expect(firstRes.status).toBe(201);
    const first = (await firstRes.json()) as { data: { handle: string; auth_url: string } };
    const handle = first.data.handle;
    const firstPort = new URL(
      new URL(first.data.auth_url).searchParams.get("redirect_uri") as string,
    ).port;
    const gatedId = await vault.engine.resolveSecretId(handle);
    const exchangesBefore = mock.requests.length;
    const backgroundErrorsBefore = backgroundErrors.length;
    const failedAuthorizeRows = (): number =>
      vault.engine
        .queryAudit({ eventType: AuditEventType.OAUTH_AUTHORIZE })
        .filter((r) => !r.success).length;
    const failedBefore = failedAuthorizeRows();

    const gatedRes = await postAuthorize(GATED_NAME);
    expect(gatedRes.status).toBe(409);
    const gatedRaw = await gatedRes.text();
    expect(JSON.parse(gatedRaw)).toEqual({
      error: ErrorCode.DUPLICATE_SECRET,
      message: `Secret already exists: ${GATED_NAME}`,
    });
    expect(failedAuthorizeRows()).toBe(failedBefore + 1);

    const { config } = providerConfigFromFlowInput({
      name: ACTIVE_NAME,
      provider: "custom",
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      auth_endpoint: AUTH_ENDPOINT,
      token_endpoint: mock.tokenEndpoint,
    });
    const active = await vault.engine.createOAuthSecret(ACTIVE_NAME, config);
    await vault.engine.completeOAuthFlow(active.secretId, ACCESS_TOKEN);
    expect((await vault.engine.getSecretInfo(`secret://${ACTIVE_NAME}`)).status).toBe(
      SecretStatus.ACTIVE,
    );
    const activeRes = await postAuthorize(ACTIVE_NAME);
    expect(activeRes.status).toBe(409);
    const activeRaw = await activeRes.text();
    expect(JSON.parse(activeRaw)).toEqual({
      error: ErrorCode.DUPLICATE_SECRET,
      message: `Secret already exists: ${ACTIVE_NAME}`,
    });
    expect(gatedRaw).toBe(activeRaw.replace(ACTIVE_NAME, GATED_NAME));
    expect(gatedRes.headers.get("content-type")).toBe(activeRes.headers.get("content-type"));

    expect(await vault.engine.resolveSecretId(handle)).toBe(gatedId);
    expect((await vault.engine.getSecretInfo(handle)).status).toBe(SecretStatus.PENDING);
    expect(vault.engine.getOAuthTokenStatus(gatedId).has_access_token).toBe(false);
    const probe = await fetch(`http://127.0.0.1:${firstPort}/not-the-callback`);
    expect(probe.status).toBe(404);
    expect(mock.requests).toHaveLength(exchangesBefore);
    expect(backgroundErrors).toHaveLength(backgroundErrorsBefore);

    const denied = vault.engine
      .queryAudit({ secretId: gatedId, eventType: AuditEventType.OAUTH_AUTHORIZE })
      .filter((r) => !r.success);
    expect(denied).toHaveLength(1);
    expect(denied[0]).toMatchObject({ principal_id: PRINCIPAL });
    expect(denied[0]?.detail).toMatchObject({
      required_permission: "rotate",
      error: ErrorCode.ACCESS_DENIED,
      interface: "rest",
    });

    expect(manager.cancelFlow(gatedId)).toBe(true);
    expect(backgroundErrors).toHaveLength(backgroundErrorsBefore);
  });
});
