import { Hono } from "hono";
import { callerFromToken, startOAuthFlowInputSchema } from "@harpoc/shared";
import { startOAuthFlowResult } from "@harpoc/oauth-proxy";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope, buildHandle, parseHandleParam } from "../middleware/scope.js";
import { readJsonBody } from "../utils/read-json-body.js";
import { schemaValidationError } from "../utils/schema-error.js";

export function createOAuthRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.post("/authorize", async (c) => {
    const token = c.get("token");
    checkTokenScope(token, "create");
    const body = await readJsonBody(c);
    const parsed = startOAuthFlowInputSchema.safeParse(body);
    if (!parsed.success) {
      throw schemaValidationError(parsed.error);
    }
    checkTokenScope(token, "create", parsed.data.project, parsed.data.name);
    const caller = callerFromToken(token, "rest");
    const manager = c.get("oauthManager");
    // The grant dispatch and its wire-safe projections (never secretId, never
    // a completion promise — D2) live in oauth-proxy, shared with the SDK.
    const result = await startOAuthFlowResult(manager, parsed.data, caller);
    return c.json({ data: result }, 201);
  });

  router.get("/:handle/status", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "read", project, name);
    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    c.get("limiter").checkSecret(handle);
    const secretId = await engine.resolveSecretId(handle);
    const status = engine.getOAuthTokenStatus(secretId, callerFromToken(token, "rest"), handle);
    return c.json({ data: status });
  });

  router.post("/:handle/refresh", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "rotate", project, name);
    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    c.get("limiter").checkSecret(handle);
    const secretId = await engine.resolveSecretId(handle);
    const expiresAt = await engine.refreshOAuthToken(
      secretId,
      callerFromToken(token, "rest"),
      handle,
    );
    return c.json({ data: { refreshed: true, expires_at: expiresAt } });
  });

  return router;
}
