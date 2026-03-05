import { Hono } from "hono";
import type { PrincipalType, Permission } from "@harpoc/shared";
import { VaultError, ErrorCode, accessPolicyInputSchema } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope, buildHandle, parseHandleParam } from "../middleware/scope.js";

export function createPolicyRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  // List policies for a secret
  router.get("/:handle/policies", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "read", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle);
    const policies = engine.listPolicies(secretId);

    return c.json({ data: policies });
  });

  // Grant a policy
  router.post("/:handle/policies", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "admin", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle);

    const body = await c.req.json<Record<string, unknown>>();
    const parsed = accessPolicyInputSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }

    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: parsed.data.principal_type as PrincipalType,
        principalId: parsed.data.principal_id,
        permissions: parsed.data.permissions as Permission[],
        expiresAt: parsed.data.expires_at,
      },
      token.sub,
    );

    return c.json({ data: policy }, 201);
  });

  // Revoke a policy
  router.delete("/:handle/policies/:policyId", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "admin", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle);
    const policyId = c.req.param("policyId");

    // Verify the policy belongs to this secret to prevent cross-secret IDOR
    const policies = engine.listPolicies(secretId);
    if (!policies.some((p) => p.id === policyId)) {
      throw new VaultError(ErrorCode.POLICY_NOT_FOUND, "Policy not found for this secret");
    }

    engine.revokePolicy(policyId);

    return c.json({ data: { revoked: true } });
  });

  return router;
}
