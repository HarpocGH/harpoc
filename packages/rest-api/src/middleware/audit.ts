import type { MiddlewareHandler } from "hono";
import type { HarpocEnv } from "../types.js";

export const auditMiddleware: MiddlewareHandler<HarpocEnv> = async (c, next) => {
  await next();

  const token = c.get("token");
  const principal = token?.sub ?? "anonymous";
  const ip = c.get("remoteAddress") ?? "unknown";

  console.error(
    "[audit] %s %s → %d principal=%s ip=%s",
    c.req.method,
    c.req.path,
    c.res.status,
    principal,
    ip,
  );
};
