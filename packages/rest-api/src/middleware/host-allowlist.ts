import type { MiddlewareHandler } from "hono";
import { checkRequestHost, VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

/**
 * Listener host allowlist (R11/D61): every request's Host — and Origin, when
 * present — must parse to a name in the listener's set, health included. A
 * DNS-rebinding request is answered 421 MISDIRECTED_REQUEST here, before the
 * limiter, the audit line and the token gate, naming the parsed hostname only.
 */
export function hostAllowlistMiddleware(
  allowed: ReadonlySet<string>,
): MiddlewareHandler<HarpocEnv> {
  return async (c, next) => {
    const check = checkRequestHost(
      { host: c.req.header("host"), origin: c.req.header("origin") },
      allowed,
    );
    if (!check.ok) {
      throw VaultError.misdirectedRequest(check.header, check.hostname);
    }
    await next();
  };
}
