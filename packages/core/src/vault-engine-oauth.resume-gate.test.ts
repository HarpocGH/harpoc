import { describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, PrincipalType } from "@harpoc/shared";
import type { CallerContext, OAuthProviderConfig, Permission } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { PolicyEngine } from "./access/policy-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";
import { readRow, useOAuthEngine } from "./__fixtures__/oauth-engine.js";

/**
 * S2 (review 2026-10-15, TC-6): resuming a PENDING OAuth flow rewrites the
 * row's token endpoint and client — so a token caller must hold `rotate` (or
 * `admin`) on the secret, the gate `refreshOAuthToken` applies to the same row.
 * A refused resume answers what an ACTIVE collision answers.
 */

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const ctx = useOAuthEngine();

const mallory: CallerContext = {
  principal_type: PrincipalType.AGENT,
  principal_id: "mallory",
  interface: "rest",
};

function operatorConfig(): OAuthProviderConfig {
  return {
    provider: "github",
    grant_type: "authorization_code",
    token_endpoint: ctx.tokenEndpoint,
    auth_endpoint: "https://github.com/login/oauth/authorize",
    client_id: "operator-cid",
    client_secret: "S3CRET-TOKEN-operator",
    scopes: ["repo"],
  };
}

function attackerConfig(): OAuthProviderConfig {
  return {
    provider: "google",
    grant_type: "authorization_code",
    token_endpoint: "https://attacker.example/token",
    client_id: "evil-cid",
    scopes: ["repo"],
  };
}

function grant(secretId: string, principalId: string, permissions: Permission[]): void {
  registerAgents(ctx.engine, principalId);
  ctx.engine.grantPolicy(
    { secretId, principalType: PrincipalType.AGENT, principalId, permissions },
    "test-setup",
  );
}

function storedEndpoint(secretId: string): unknown {
  return readRow(
    ctx.dbPath,
    "SELECT token_endpoint, provider FROM oauth_tokens WHERE secret_id = ?",
    secretId,
  );
}

describe("createOAuthSecret — the resume of a PENDING flow is gated on rotate (S2)", () => {
  it("a grantless token caller's resume is refused DUPLICATE_SECRET, byte-identical to the ACTIVE collision on the same name", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", operatorConfig());

    const pending = await expectVaultError(
      () => ctx.engine.createOAuthSecret("gh", attackerConfig(), undefined, mallory),
      ErrorCode.DUPLICATE_SECRET,
    );

    await ctx.engine.completeOAuthFlow(secretId, "S3CRET-TOKEN-access");
    const active = await expectVaultError(
      () => ctx.engine.createOAuthSecret("gh", attackerConfig(), undefined, mallory),
      ErrorCode.DUPLICATE_SECRET,
    );

    expect(pending.message).toBe("Secret already exists: gh");
    expect(pending.message).toBe(active.message);
  });

  it("a refused resume writes exactly one failed oauth.authorize row — the policy refusal with the secret id — and leaves the stored configuration untouched", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", operatorConfig());

    await expectVaultError(
      () => ctx.engine.createOAuthSecret("gh", attackerConfig(), undefined, mallory),
      ErrorCode.DUPLICATE_SECRET,
    );

    const rows = ctx.engine.queryAudit({ eventType: AuditEventType.OAUTH_AUTHORIZE });
    expect(rows).toHaveLength(2);
    const denied = rows.filter((r) => !r.success);
    expect(denied).toHaveLength(1);
    expect(denied[0]?.secret_id).toBe(secretId);
    expect(denied[0]?.principal_type).toBe(PrincipalType.AGENT);
    expect(denied[0]?.principal_id).toBe("mallory");
    expect(denied[0]?.detail).toEqual({
      name: "gh",
      provider: "google",
      grant_type: "authorization_code",
      required_permission: "rotate",
      error: ErrorCode.ACCESS_DENIED,
      interface: "rest",
    });
    expect(storedEndpoint(secretId)).toEqual({
      token_endpoint: ctx.tokenEndpoint,
      provider: "github",
    });
  });

  it("a caller holding read but not rotate is refused the same way", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", operatorConfig());
    grant(secretId, "mallory", ["read"]);

    const err = await expectVaultError(
      () => ctx.engine.createOAuthSecret("gh", attackerConfig(), undefined, mallory),
      ErrorCode.DUPLICATE_SECRET,
    );
    expect(err.message).toBe("Secret already exists: gh");
    expect(storedEndpoint(secretId)).toEqual({
      token_endpoint: ctx.tokenEndpoint,
      provider: "github",
    });
    const denied = ctx.engine
      .queryAudit({ eventType: AuditEventType.OAUTH_AUTHORIZE })
      .filter((r) => !r.success);
    expect(denied).toHaveLength(1);
    expect(denied[0]?.detail).toMatchObject({
      required_permission: "rotate",
      error: ErrorCode.ACCESS_DENIED,
    });
  });

  it("a fault inside the resume gate surfaces raw, not as DUPLICATE_SECRET, and the outer catch writes its one failed oauth.authorize row for the secret", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", operatorConfig());
    const policy = (ctx.engine as unknown as { policyEngine: PolicyEngine }).policyEngine;
    const spy = vi.spyOn(policy, "grantedPermissions").mockImplementationOnce(() => {
      throw new Error("policy store fault");
    });
    try {
      await expect(
        ctx.engine.createOAuthSecret("gh", attackerConfig(), undefined, mallory),
      ).rejects.toThrow("policy store fault");
    } finally {
      spy.mockRestore();
    }

    const denied = ctx.engine
      .queryAudit({ eventType: AuditEventType.OAUTH_AUTHORIZE })
      .filter((r) => !r.success);
    expect(denied).toHaveLength(1);
    expect(denied[0]?.secret_id).toBe(secretId);
    expect(denied[0]?.principal_id).toBe("mallory");
    expect(denied[0]?.detail).toEqual({
      name: "gh",
      provider: "google",
      grant_type: "authorization_code",
      error: ErrorCode.INTERNAL_ERROR,
      interface: "rest",
    });
    expect(storedEndpoint(secretId)).toEqual({
      token_endpoint: ctx.tokenEndpoint,
      provider: "github",
    });
  });

  it("control: a rotate-granted caller resumes, the row marked resumed and attributed", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", operatorConfig());
    grant(secretId, "mallory", ["rotate"]);

    const resumed = await ctx.engine.createOAuthSecret("gh", attackerConfig(), undefined, mallory);

    expect(resumed).toEqual({ handle: "secret://gh", secretId });
    expect(storedEndpoint(secretId)).toEqual({
      token_endpoint: "https://attacker.example/token",
      provider: "google",
    });
    const rows = ctx.engine.queryAudit({ eventType: AuditEventType.OAUTH_AUTHORIZE });
    expect(rows.every((r) => r.success)).toBe(true);
    expect(rows[0]?.principal_id).toBe("mallory");
    expect(rows[0]?.detail).toMatchObject({ resumed: true, interface: "rest" });
  });

  it("control: an admin-scoped user-type token (R7) resumes without a grant", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", operatorConfig());
    const operator: CallerContext = {
      principal_type: PrincipalType.USER,
      principal_id: "operator",
      admin_scope: true,
      interface: "rest",
    };

    const resumed = await ctx.engine.createOAuthSecret("gh", operatorConfig(), undefined, operator);

    expect(resumed.secretId).toBe(secretId);
  });

  it("control: the trusted local path (no caller) resumes", async () => {
    const { secretId } = await ctx.engine.createOAuthSecret("gh", operatorConfig());

    const resumed = await ctx.engine.createOAuthSecret("gh", attackerConfig());

    expect(resumed.secretId).toBe(secretId);
    expect(storedEndpoint(secretId)).toMatchObject({ provider: "google" });
  });
});
