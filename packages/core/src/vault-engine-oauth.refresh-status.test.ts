import { describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { CallerContext, OAuthProviderConfig } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { registerAgents } from "./__fixtures__/engine-seams.js";
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

const ACCESS_TOKEN = "S3CRET-TOKEN-access";
const REFRESH_TOKEN = "S3CRET-TOKEN-refresh";
const PROXY_CALLER: CallerContext = {
  principal_type: "agent",
  principal_id: "alice",
  interface: "proxy",
  remote_address: "127.0.0.1",
};

async function activeSecret(expiresAt = Date.now() - 1000): Promise<string> {
  const { secretId } = await ctx.engine.createOAuthSecret("gh", config());
  await ctx.engine.completeOAuthFlow(secretId, ACCESS_TOKEN, REFRESH_TOKEN, expiresAt);
  return secretId;
}

/** The engine's HTTP injector replaced: records the token each use hands it and answers 200. */
function stubHttpInjector(): string[] {
  const handed: string[] = [];
  (
    ctx.engine as unknown as {
      httpInjector: { executeWithSecret: (...args: unknown[]) => Promise<unknown> };
    }
  ).httpInjector = {
    executeWithSecret: (...args: unknown[]) => {
      handed.push(Buffer.from(args[1] as Uint8Array).toString("utf8"));
      return Promise.resolve({ type: "http", status: 200 });
    },
  };
  return handed;
}

/** A use of `secret://gh` whose access token expires within the refresh window, allowlisted. */
async function useWithinRefreshWindow(): Promise<string> {
  const secretId = await activeSecret(Date.now() + 30_000);
  await ctx.engine.setInjectionPolicy("secret://gh", {
    url_allowlist: ["https://api.example.com/*"],
  });
  return secretId;
}

function useSecret(): Promise<unknown> {
  return ctx.engine.useSecret("secret://gh", {
    type: "http",
    method: "GET",
    url: "https://api.example.com/user",
    injection: { type: "bearer" },
  });
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
    expect(ctx.requests[0]?.body.get("refresh_token") === REFRESH_TOKEN).toBe(true);
  });
});

describe("refreshOAuthToken — a revoke during the token-endpoint round trip stores nothing (S7, R11)", () => {
  async function revokeWhileInFlight(
    secretId: string,
    call: () => Promise<unknown> = () => ctx.engine.refreshOAuthToken(secretId),
  ): Promise<void> {
    let release: () => void = () => {};
    ctx.gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const arrived = new Promise<void>((resolve) => {
      ctx.onRequest = resolve;
    });
    const before = tokenColumns(secretId);

    const refresh = expectVaultError(call, ErrorCode.SECRET_REVOKED);
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

  it("a revoke during a refresh hands out no token", async () => {
    const handed = stubHttpInjector();
    const secretId = await useWithinRefreshWindow();

    await revokeWhileInFlight(secretId, useSecret);

    expect(handed.length).toBe(0);
    const rows = ctx.engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(rows.map((row) => ({ secret_id: row.secret_id, success: row.success }))).toEqual([
      { secret_id: secretId, success: false },
    ]);
  });

  it("a failed refresh with an unexpired token still serves the old token", async () => {
    const handed = stubHttpInjector();
    await useWithinRefreshWindow();
    ctx.response = { status: 500, body: { error: "server_error" } };

    await useSecret();

    expect(ctx.requests).toHaveLength(1);
    expect(handed.length).toBe(1);
    expect(handed[0] === ACCESS_TOKEN).toBe(true);
  });

  async function revokeBeforeFailedAnswer(call: () => Promise<unknown>): Promise<void> {
    ctx.response = { status: 500, body: { error: "server_error" } };
    let release: () => void = () => {};
    ctx.gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const arrived = new Promise<void>((resolve) => {
      ctx.onRequest = resolve;
    });

    const pending = expectVaultError(call, ErrorCode.SECRET_REVOKED);
    await Promise.race([arrived, pending]);
    await ctx.engine.revokeSecret("secret://gh");
    release();
    const err = await pending;

    expect(err.message).toBe("Secret revoked: secret://gh");
    expect(ctx.requests).toHaveLength(1);
  }

  function failedUseRows(): unknown[] {
    return ctx.engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .map((row) => ({ secret_id: row.secret_id, success: row.success, error: row.detail?.error }));
  }

  it.each([
    { token: "unexpired", expiresIn: 30_000 },
    { token: "expired", expiresIn: -1000 },
  ])(
    "a revoke during a refresh that then fails hands out no token on the use path, the token $token",
    async ({ expiresIn }) => {
      const handed = stubHttpInjector();
      const secretId = await activeSecret(Date.now() + expiresIn);
      await ctx.engine.setInjectionPolicy("secret://gh", {
        url_allowlist: ["https://api.example.com/*"],
      });

      await revokeBeforeFailedAnswer(useSecret);

      expect(handed.length).toBe(0);
      expect(failedUseRows()).toEqual([
        { secret_id: secretId, success: false, error: ErrorCode.SECRET_REVOKED },
      ]);
    },
  );

  it("a revoke during a refresh that then fails opens no lease on the proxy's resolve", async () => {
    const secretId = await activeSecret(Date.now() + 30_000);
    await ctx.engine.setInjectionPolicy("secret://gh", {
      url_allowlist: ["https://api.example.com/*"],
      proxy: true,
    });
    registerAgents(ctx.engine, "alice");
    ctx.engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alice", permissions: ["use"] },
      "test-admin",
    );
    const lease = vi.spyOn(
      ctx.engine as unknown as { openProxyLease: () => unknown },
      "openProxyLease",
    );

    await revokeBeforeFailedAnswer(() =>
      ctx.engine.resolveForProxy("secret://gh", PROXY_CALLER, {
        method: "GET",
        origin: "https://api.example.com",
        path: "/user",
      }),
    );

    expect(lease).not.toHaveBeenCalled();
    expect(failedUseRows()).toEqual([
      { secret_id: secretId, success: false, error: ErrorCode.SECRET_REVOKED },
    ]);
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
