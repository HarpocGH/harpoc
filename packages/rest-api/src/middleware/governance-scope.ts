import type { MiddlewareHandler } from "hono";
import { VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

/**
 * Governance is vault-wide (R11/N12): a token carrying a `project` claim is
 * refused on every `/api/v1/agents/*` and `/api/v1/tokens/*` route before a
 * body is read — the same rule the engine enforces on its governance methods,
 * answered at the interface like the `admin` scope check.
 */
export const unscopedTokenMiddleware: MiddlewareHandler<HarpocEnv> = async (c, next) => {
  if (c.get("token").project) {
    throw VaultError.accessDenied("governance requires an unscoped admin token");
  }
  await next();
};
