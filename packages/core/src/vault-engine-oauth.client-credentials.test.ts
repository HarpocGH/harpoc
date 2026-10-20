import { describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { useOAuthEngine } from "./__fixtures__/oauth-engine.js";

/**
 * Q7 (review 2026-10-15, TC-11): a `client_credentials` secret has no refresh
 * token; its renewal is the client-credentials exchange itself, re-run by the
 * engine's refresh path with the stored client — so the scheduler's
 * `refreshOAuthToken(secretId)` and the use path's auto-refresh renew it.
 */

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const ctx = useOAuthEngine();

function ccConfig(overrides?: Partial<OAuthProviderConfig>): OAuthProviderConfig {
  return {
    provider: "custom",
    grant_type: "client_credentials",
    token_endpoint: ctx.tokenEndpoint,
    client_id: "cc-client",
    client_secret: "S3CRET-TOKEN-client",
    scopes: ["read", "write"],
    ...overrides,
  };
}

async function activeCc(overrides?: Partial<OAuthProviderConfig>): Promise<string> {
  const { secretId } = await ctx.engine.createOAuthSecret("svc", ccConfig(overrides));
  await ctx.engine.completeOAuthFlow(secretId, "S3CRET-TOKEN-first", undefined, Date.now() - 1000);
  return secretId;
}

describe("refreshOAuthToken — a client_credentials secret re-exchanges its client credentials (Q7)", () => {
  it("the scheduler's call (no caller) POSTs grant_type=client_credentials with the stored client and scopes, and stores the new access token", async () => {
    const secretId = await activeCc();

    const expiresAt = await ctx.engine.refreshOAuthToken(secretId);

    expect(expiresAt).toBeGreaterThan(Date.now());
    expect(ctx.requests).toHaveLength(1);
    expect(Object.fromEntries(ctx.requests[0]?.body ?? [])).toEqual({
      grant_type: "client_credentials",
      scope: "read write",
      client_id: "cc-client",
      client_secret: "S3CRET-TOKEN-client",
    });
    expect(await ctx.engine["getOAuthAccessToken"](secretId)).toBe("S3CRET-TOKEN-renewed");
    const status = ctx.engine.getOAuthTokenStatus(secretId);
    expect(status.has_refresh_token).toBe(false);
    expect(status.access_token_expires_at).toBe(expiresAt);
  });

  it("writes the successful oauth.refresh row", async () => {
    const secretId = await activeCc();

    const expiresAt = await ctx.engine.refreshOAuthToken(secretId);

    const rows = ctx.engine.queryAudit({ eventType: AuditEventType.OAUTH_REFRESH });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(true);
    expect(rows[0]?.secret_id).toBe(secretId);
    expect(rows[0]?.detail).toEqual({ new_expires_at: expiresAt });
  });

  it("a client_secret_basic row sends the Basic header and keeps the credentials out of the body", async () => {
    const secretId = await activeCc({ token_endpoint_auth_method: "client_secret_basic" });

    await ctx.engine.refreshOAuthToken(secretId);

    const request = ctx.requests[0];
    expect(request?.authorization).toBe(
      `Basic ${Buffer.from("cc-client:S3CRET-TOKEN-client", "utf8").toString("base64")}`,
    );
    expect(Object.fromEntries(request?.body ?? [])).toEqual({
      grant_type: "client_credentials",
      scope: "read write",
    });
  });

  it("the re-exchange asks for a JSON answer with Accept: application/json, as the first exchange does", async () => {
    const secretId = await activeCc();

    await ctx.engine.refreshOAuthToken(secretId);

    expect(ctx.requests).toHaveLength(1);
    expect(ctx.requests[0]?.accept).toBe("application/json");
  });

  it("scopes join with the provider's separator — a comma for the slack preset", async () => {
    const secretId = await activeCc({ provider: "slack", scopes: ["chat:write", "channels:read"] });

    await ctx.engine.refreshOAuthToken(secretId);

    expect(ctx.requests[0]?.body.get("scope")).toBe("chat:write,channels:read");
  });

  it("a row without scopes sends no scope parameter", async () => {
    const secretId = await activeCc({ scopes: undefined });

    await ctx.engine.refreshOAuthToken(secretId);

    expect(ctx.requests[0]?.body.has("scope")).toBe(false);
  });

  it("a client_credentials row without a stored client secret is refused OAUTH_REFRESH_FAILED before any request", async () => {
    const secretId = await activeCc({ client_secret: undefined });

    const err = await expectVaultError(
      () => ctx.engine.refreshOAuthToken(secretId),
      ErrorCode.OAUTH_REFRESH_FAILED,
    );

    expect(err.message).toBe(
      "OAuth token refresh failed: No client secret stored for the client credentials grant",
    );
    expect(ctx.requests).toHaveLength(0);
  });

  it("control: an authorization_code row without a refresh token still answers no refresh token available", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret(
      "code",
      ccConfig({ grant_type: "authorization_code", auth_endpoint: "https://idp.example/auth" }),
    );
    await ctx.engine.completeOAuthFlow(secretId, "S3CRET-TOKEN-first");

    const err = await expectVaultError(
      () => ctx.engine.refreshOAuthToken(secretId),
      ErrorCode.OAUTH_REFRESH_FAILED,
    );

    expect(err.message).toBe("OAuth token refresh failed: No refresh token available");
    expect(ctx.requests).toHaveLength(0);
  });
});

describe("getOAuthAccessToken — the use path renews an expired client_credentials token (Q7)", () => {
  it("a use on an expired client_credentials token re-exchanges once and serves the new token", async () => {
    const secretId = await activeCc();

    expect(await ctx.engine["getOAuthAccessToken"](secretId)).toBe("S3CRET-TOKEN-renewed");

    expect(ctx.requests).toHaveLength(1);
    expect(ctx.requests[0]?.body.get("grant_type")).toBe("client_credentials");
  });

  it("two concurrent uses coalesce onto one re-exchange", async () => {
    const secretId = await activeCc();
    let release: () => void = () => {};
    ctx.gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const first = ctx.engine["getOAuthAccessToken"](secretId);
    const second = ctx.engine["getOAuthAccessToken"](secretId);
    release();

    expect(await Promise.all([first, second])).toEqual([
      "S3CRET-TOKEN-renewed",
      "S3CRET-TOKEN-renewed",
    ]);
    expect(ctx.requests).toHaveLength(1);
  });

  it("a failed re-exchange on an expired token surfaces OAUTH_REFRESH_FAILED", async () => {
    const secretId = await activeCc();
    ctx.response = { status: 401, body: { error: "invalid_client" } };

    await expectVaultError(
      () => ctx.engine["getOAuthAccessToken"](secretId),
      ErrorCode.OAUTH_REFRESH_FAILED,
    );
    expect(ctx.requests).toHaveLength(1);
  });
});
