import { describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { readRow, runSql, useOAuthEngine } from "./__fixtures__/oauth-engine.js";

/**
 * S4 (review 2026-10-15, TC-8): `completeOAuthFlow` completes a PENDING secret
 * only. A late completion must not revive a revoked secret, overwrite an
 * ACTIVE one or move an EXPIRED one back to ACTIVE, and every refusal is a
 * failed `oauth.callback` row.
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

function stored(secretId: string): unknown {
  return readRow(
    ctx.dbPath,
    `SELECT s.status, o.access_token_encrypted IS NOT NULL AS has_access,
            o.refresh_token_encrypted IS NOT NULL AS has_refresh
       FROM secrets s JOIN oauth_tokens o ON o.secret_id = s.id WHERE s.id = ?`,
    secretId,
  );
}

function callbackRows(secretId: string): ReturnType<typeof ctx.engine.queryAudit> {
  return ctx.engine
    .queryAudit({ eventType: AuditEventType.OAUTH_CALLBACK })
    .filter((r) => r.secret_id === secretId);
}

describe("completeOAuthFlow — only a PENDING secret completes (S4)", () => {
  it("a revoked secret's completion is refused SECRET_REVOKED; it stays revoked with no token stored", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", config());
    await ctx.engine.revokeSecret("secret://gh");

    const err = await expectVaultError(
      () => ctx.engine.completeOAuthFlow(secretId, "S3CRET-TOKEN-late", "S3CRET-TOKEN-rt"),
      ErrorCode.SECRET_REVOKED,
    );

    expect(err.message).toBe("Secret revoked");
    expect(stored(secretId)).toEqual({ status: "revoked", has_access: 0, has_refresh: 0 });
  });

  it("the refused completion writes one failed oauth.callback row naming the error and the status", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", config());
    await ctx.engine.revokeSecret("secret://gh");

    await expectVaultError(
      () => ctx.engine.completeOAuthFlow(secretId, "S3CRET-TOKEN-late"),
      ErrorCode.SECRET_REVOKED,
    );

    const rows = callbackRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.principal_id).toBeNull();
    expect(rows[0]?.detail).toEqual({ status: "revoked", error: ErrorCode.SECRET_REVOKED });
  });

  it("a late completion after the name was re-created is SECRET_REVOKED with one failed row — no raw constraint error — and the new secret stays pending", async () => {
    const first = await ctx.engine.createOAuthSecret("gh", config());
    await ctx.engine.revokeSecret("secret://gh");
    const second = await ctx.engine.createOAuthSecret("gh", config());

    await expectVaultError(
      () => ctx.engine.completeOAuthFlow(first.secretId, "S3CRET-TOKEN-late"),
      ErrorCode.SECRET_REVOKED,
    );

    expect(callbackRows(first.secretId)).toHaveLength(1);
    expect(stored(first.secretId)).toMatchObject({ status: "revoked", has_access: 0 });
    expect(stored(second.secretId)).toEqual({ status: "pending", has_access: 0, has_refresh: 0 });
  });

  it("a second completion of an ACTIVE secret is OAUTH_FLOW_FAILED and keeps the first tokens", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", config());
    await ctx.engine.completeOAuthFlow(secretId, "S3CRET-TOKEN-first", "S3CRET-TOKEN-rt1");

    const err = await expectVaultError(
      () => ctx.engine.completeOAuthFlow(secretId, "S3CRET-TOKEN-second"),
      ErrorCode.OAUTH_FLOW_FAILED,
    );

    expect(err.message).toBe("OAuth flow failed: the secret is no longer pending");
    expect(await ctx.engine["getOAuthAccessToken"](secretId)).toBe("S3CRET-TOKEN-first");
    const rows = callbackRows(secretId);
    expect(rows.map((r) => r.success)).toEqual([false, true]);
    expect(rows[0]?.detail).toEqual({ status: "active", error: ErrorCode.OAUTH_FLOW_FAILED });
  });

  it("an EXPIRED secret's completion is OAUTH_FLOW_FAILED and it stays expired", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", config());
    await ctx.engine.completeOAuthFlow(secretId, "S3CRET-TOKEN-first");
    runSql(
      ctx.dbPath,
      "UPDATE secrets SET expires_at = ? WHERE id = ?",
      Date.now() - 1000,
      secretId,
    );
    await expectVaultError(
      () => ctx.engine["getOAuthAccessToken"](secretId),
      ErrorCode.SECRET_EXPIRED,
    );

    await expectVaultError(
      () => ctx.engine.completeOAuthFlow(secretId, "S3CRET-TOKEN-late"),
      ErrorCode.OAUTH_FLOW_FAILED,
    );

    expect(stored(secretId)).toMatchObject({ status: "expired" });
    expect(callbackRows(secretId)[0]?.detail).toEqual({
      status: "expired",
      error: ErrorCode.OAUTH_FLOW_FAILED,
    });
  });

  it("an unknown secret id is refused SECRET_NOT_FOUND and audited as a failed oauth.callback", async () => {
    await expectVaultError(
      () => ctx.engine.completeOAuthFlow("no-such-id", "S3CRET-TOKEN-late"),
      ErrorCode.SECRET_NOT_FOUND,
    );

    const rows = callbackRows("no-such-id");
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail).toEqual({ error: ErrorCode.SECRET_NOT_FOUND });
  });

  it("a refused completion is audited before its first yield, like the success row (P1R-3)", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", config());
    await ctx.engine.revokeSecret("secret://gh");

    const completion = ctx.engine.completeOAuthFlow(secretId, "S3CRET-TOKEN-late");
    expect(callbackRows(secretId)).toHaveLength(1);
    await expect(completion).rejects.toMatchObject({ code: ErrorCode.SECRET_REVOKED });
  });
});
