import { Hono } from "hono";
import type { PrincipalType, Permission } from "@harpoc/shared";
import { accessPolicyInputSchema } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope, buildHandle, parseHandleParam } from "../middleware/scope.js";
import { callerOf } from "../utils/caller.js";
import { readJsonBody } from "../utils/read-json-body.js";
import { schemaValidationError } from "../utils/schema-error.js";

export function createPolicyRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  // List policies for a secret
  router.get("/:handle/policies", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "read", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle, callerOf(c));
    const policies = engine.listPolicies(secretId, callerOf(c), handle);

    return c.json({ data: policies });
  });

  // Grant a policy
  router.post("/:handle/policies", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "admin", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle, callerOf(c));

    const body = await readJsonBody(c);
    const parsed = accessPolicyInputSchema.safeParse(body);
    if (!parsed.success) {
      throw schemaValidationError(parsed.error);
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
      callerOf(c),
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
    const secretId = await engine.resolveSecretId(handle, callerOf(c));
    const policyId = c.req.param("policyId");

    // The cross-secret IDOR guard is the engine's: a policy on another secret
    // refuses exactly like an unknown id, with no caller-less membership read.
    engine.revokePolicy(policyId, callerOf(c), secretId);

    return c.json({ data: { revoked: true } });
  });

  return router;
}
