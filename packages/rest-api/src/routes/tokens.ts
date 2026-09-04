import { Hono } from "hono";
import { listTokensQuerySchema } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope } from "../middleware/scope.js";
import { callerOf } from "../utils/caller.js";
import { schemaValidationError } from "../utils/schema-error.js";

/**
 * The issued-token registry (v1.4): claims metadata only — the JWT itself is
 * never stored, so nothing here can hand a token back. Revocation still writes
 * the denylist, which stays the sole revocation truth.
 */
export function createTokenRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.get("/", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");

    const status = c.req.query("status");
    const agent = c.req.query("agent");
    const parsed = listTokensQuerySchema.safeParse({
      status: status ?? undefined,
      agent: agent ?? undefined,
    });
    if (!parsed.success) {
      throw schemaValidationError(parsed.error);
    }

    const engine = c.get("engine");
    const tokens = engine.listIssuedTokens(
      { status: parsed.data.status, agent: parsed.data.agent },
      callerOf(c),
    );

    return c.json({ data: tokens });
  });

  router.delete("/:jti", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");

    const engine = c.get("engine");
    // No expiry argument — the engine floors the denylist entry at
    // MAX_TOKEN_TTL_MS, which outlives every mintable token; the registry
    // row's expiry is not consulted.
    engine.revokeToken(c.req.param("jti"), undefined, callerOf(c));

    return c.json({ data: { revoked: true } });
  });

  return router;
}
