import type { MiddlewareHandler } from "hono";
import { VaultError } from "@harpoc/shared";
import { callerOf } from "../utils/caller.js";
import { requestOperation } from "./request-operation.js";
import type { HarpocEnv } from "../types.js";

/**
 * Governance is vault-wide (R11/N12): a token carrying a `project` claim or a
 * non-empty `secrets` claim — `["*"]` included (S3, 2026-10-20) — is
 * refused on every `/api/v1/agents/*` and `/api/v1/tokens/*` route before a
 * body is read — the same rule the engine enforces on its governance methods,
 * answered at the interface like the `admin` scope check. The refusal writes
 * one `access.denied` row first (D4, 2026-09-06): this middleware always
 * answers before the engine's own assertion can, so the engine's row is the
 * SDK/direct-mode row and this one is the REST row — a probe leaves exactly
 * one, whichever layer refused it. The vault lock (`/api/v1/vault/*`,
 * deployment model B) is vault-wide too and mounts this middleware the same way,
 * and so does the audit chain's verification (`POST /api/v1/audit/verify`, C-12):
 * the chain spans every row of the vault, so a claimed token is refused it while
 * `GET /api/v1/audit` still answers that token, filtered to its claim.
 */
export const unscopedTokenMiddleware: MiddlewareHandler<HarpocEnv> = async (c, next) => {
  const token = c.get("token");
  if (token.project || token.secrets?.length) {
    c.get("engine").auditGovernanceRefusal(callerOf(c), requestOperation(c));
    throw VaultError.accessDenied("governance requires an unscoped admin token");
  }
  await next();
};
