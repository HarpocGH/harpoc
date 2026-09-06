import type { MiddlewareHandler } from "hono";
import { VaultError } from "@harpoc/shared";
import { callerOf } from "../utils/caller.js";
import type { HarpocEnv } from "../types.js";

/**
 * Governance is vault-wide (R11/N12): a token carrying a `project` claim is
 * refused on every `/api/v1/agents/*` and `/api/v1/tokens/*` route before a
 * body is read — the same rule the engine enforces on its governance methods,
 * answered at the interface like the `admin` scope check. The refusal writes
 * one `access.denied` row first (D4, 2026-09-06): this middleware always
 * answers before the engine's own assertion can, so the engine's row is the
 * SDK/direct-mode row and this one is the REST row — a probe leaves exactly
 * one, whichever layer refused it.
 */
export const unscopedTokenMiddleware: MiddlewareHandler<HarpocEnv> = async (c, next) => {
  if (c.get("token").project) {
    c.get("engine").auditGovernanceRefusal(callerOf(c), `${c.req.method} ${c.req.path}`);
    throw VaultError.accessDenied("governance requires an unscoped admin token");
  }
  await next();
};
