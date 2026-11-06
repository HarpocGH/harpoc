import { Hono } from "hono";
import type { HarpocEnv } from "../types.js";
import { checkScope } from "../middleware/scope.js";
import { callerOf } from "../utils/caller.js";

/**
 * The one REST administration route (deployment model B, design decision 8):
 * an unscoped admin token seals the serving engine. No body is read. The
 * listener keeps serving; every authenticated request then answers
 * `VAULT_LOCKED` (503) until the vault is unlocked again.
 */
export function createVaultRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.post("/lock", async (c) => {
    checkScope(c, "admin");

    await c.get("engine").lock(callerOf(c));

    return c.json({ data: { locked: true } });
  });

  return router;
}
