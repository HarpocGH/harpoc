import type { MiddlewareHandler } from "hono";
import type { RateLimiter } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

export { RateLimiter } from "@harpoc/shared";

export function createRateLimitMiddleware(limiter: RateLimiter): MiddlewareHandler<HarpocEnv> {
  return async (_c, next) => {
    limiter.checkGlobal();
    await next();
  };
}
