import { describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { readRow, runSql, useOAuthEngine } from "./__fixtures__/oauth-engine.js";

/**
 * S7 (review 2026-10-15): a refresh reads the secret's status first, through
 * the use path's ladder — a REVOKED or EXPIRED secret's refresh token is never
 * POSTed, and the refusal is a failed `oauth.refresh` row.
 */

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const ctx = useOAuthEngine();

function config(): OAuthProviderConfig {
  return {
    provider: "github",
    grant_type: "authorization_code",
    token_endpoint: ctx.tokenEndpoint,
    auth_endpoint: "https://github.com/login/oauth/authorize",
    client_id: "operator-cid",
    client_secret: "S3CRET-TOKEN-operator",
  };
}

async function activeSecret(): Promise<string> {
  const { secretId } = await ctx.engine.createOAuthSecret("gh", config());
  await ctx.engine.completeOAuthFlow(
    secretId,
    "S3CRET-TOKEN-access",
    "S3CRET-TOKEN-refresh",
    Date.now() - 1000,
  );
  return secretId;
}

function tokenColumns(secretId: string): unknown {
  return readRow(
    ctx.dbPath,
    "SELECT access_token_encrypted, refresh_token_encrypted FROM oauth_tokens WHERE secret_id = ?",
    secretId,
  );
}

describe("refreshOAuthToken — a revoked or expired secret is not refreshed (S7)", () => {
  it("a revoked secret's refresh is refused SECRET_REVOKED with no token-endpoint request and its tokens unchanged", async () => {
    const secretId = await activeSecret();
    await ctx.engine.revokeSecret("secret://gh");
    const before = tokenColumns(secretId);

    const err = await expectVaultError(
      () => ctx.engine.refreshOAuthToken(secretId),
      ErrorCode.SECRET_REVOKED,
    );

    expect(err.message).toBe("Secret revoked: secret://gh");
    expect(ctx.requests).toHaveLength(0);
    expect(tokenColumns(secretId)).toEqual(before);
  });

  it("the refusal is one failed oauth.refresh row and no successful one", async () => {
    const secretId = await activeSecret();
    await ctx.engine.revokeSecret("secret://gh");

    await expectVaultError(() => ctx.engine.refreshOAuthToken(secretId), ErrorCode.SECRET_REVOKED);

    const rows = ctx.engine.queryAudit({ eventType: AuditEventType.OAUTH_REFRESH });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.secret_id).toBe(secretId);
    expect(rows[0]?.detail).toEqual({ action: "refresh", error: ErrorCode.SECRET_REVOKED });
  });

  it("an expired-by-time secret's refresh is refused SECRET_EXPIRED, writes the lazy transition's secret.expire row and sends nothing", async () => {
    const secretId = await activeSecret();
    runSql(
      ctx.dbPath,
      "UPDATE secrets SET expires_at = ? WHERE id = ?",
      Date.now() - 1000,
      secretId,
    );

    const err = await expectVaultError(
      () => ctx.engine.refreshOAuthToken(secretId),
      ErrorCode.SECRET_EXPIRED,
    );

    expect(err.message).toBe("Secret expired: secret://gh");
    expect(ctx.requests).toHaveLength(0);
    expect(readRow(ctx.dbPath, "SELECT status FROM secrets WHERE id = ?", secretId)).toEqual({
      status: "expired",
    });
    const expire = ctx.engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE });
    expect(expire).toHaveLength(1);
    expect(expire[0]?.detail).toMatchObject({ handle: "secret://gh" });
    expect(
      ctx.engine.queryAudit({ eventType: AuditEventType.OAUTH_REFRESH })[0]?.detail,
    ).toMatchObject({ error: ErrorCode.SECRET_EXPIRED });
  });

  it("control: a PENDING secret's refresh keeps its answer — OAUTH_REFRESH_FAILED, no refresh token available", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", config());

    const err = await expectVaultError(
      () => ctx.engine.refreshOAuthToken(secretId),
      ErrorCode.OAUTH_REFRESH_FAILED,
    );

    expect(err.message).toBe("OAuth token refresh failed: No refresh token available");
    expect(ctx.requests).toHaveLength(0);
  });

  it("control: an ACTIVE secret still refreshes with its refresh token", async () => {
    const secretId = await activeSecret();

    await expect(ctx.engine.refreshOAuthToken(secretId)).resolves.toBeGreaterThan(Date.now());

    expect(ctx.requests).toHaveLength(1);
    expect(ctx.requests[0]?.body.get("grant_type")).toBe("refresh_token");
    expect(ctx.requests[0]?.body.get("refresh_token")).toBe("S3CRET-TOKEN-refresh");
  });
});

describe("refreshOAuthToken — a revoke during the token-endpoint round trip stores nothing (S7, R11)", () => {
  async function revokeWhileInFlight(secretId: string): Promise<void> {
    let release: () => void = () => {};
    ctx.gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const arrived = new Promise<void>((resolve) => {
      ctx.onRequest = resolve;
    });
    const before = tokenColumns(secretId);

    const refresh = expectVaultError(
      () => ctx.engine.refreshOAuthToken(secretId),
      ErrorCode.SECRET_REVOKED,
    );
    await Promise.race([arrived, refresh]);
    await ctx.engine.revokeSecret("secret://gh");
    release();
    const err = await refresh;

    expect(err.message).toBe("Secret revoked: secret://gh");
    expect(ctx.requests).toHaveLength(1);
    expect(tokenColumns(secretId)).toEqual(before);
    const rows = ctx.engine.queryAudit({ eventType: AuditEventType.OAUTH_REFRESH });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail).toEqual({ action: "refresh", error: ErrorCode.SECRET_REVOKED });
  }

  it("a refresh-token refresh whose secret is revoked mid-flight is refused SECRET_REVOKED and stores no rotation", async () => {
    await revokeWhileInFlight(await activeSecret());
  });

  it("a client-credentials re-exchange whose secret is revoked mid-flight is refused SECRET_REVOKED and stores no token", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", {
      provider: "custom",
      grant_type: "client_credentials",
      token_endpoint: ctx.tokenEndpoint,
      client_id: "cc-client",
      client_secret: "S3CRET-TOKEN-client",
    });
    await ctx.engine.completeOAuthFlow(
      secretId,
      "S3CRET-TOKEN-first",
      undefined,
      Date.now() - 1000,
    );

    await revokeWhileInFlight(secretId);
  });
});

describe("refreshOAuthToken — the refresh-token POST asks for a JSON answer", () => {
  it("a refresh-token refresh sends Accept: application/json, as the first exchange does", async () => {
    const secretId = await activeSecret();

    await ctx.engine.refreshOAuthToken(secretId);

    expect(ctx.requests).toHaveLength(1);
    expect(ctx.requests[0]?.body.get("grant_type")).toBe("refresh_token");
    expect(ctx.requests[0]?.accept).toBe("application/json");
  });
});
