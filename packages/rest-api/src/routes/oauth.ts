import { Hono } from "hono";
import { VaultError, callerFromToken, startOAuthFlowInputSchema } from "@harpoc/shared";
import { providerConfigFromFlowInput } from "@harpoc/oauth-proxy";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope, buildHandle, parseHandleParam } from "../middleware/scope.js";

export function createOAuthRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.post("/authorize", async (c) => {
    const token = c.get("token");
    checkTokenScope(token, "create");
    const body = await c.req.json<Record<string, unknown>>();
    const parsed = startOAuthFlowInputSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }
    checkTokenScope(token, "create", parsed.data.project, parsed.data.name);
    const caller = callerFromToken(token, "rest");
    const manager = c.get("oauthManager");
    const { config, project } = providerConfigFromFlowInput(parsed.data);

    if (parsed.data.grant_type === "client_credentials") {
      if (!config.client_secret) {
        throw VaultError.schemaValidation(
          "client_secret is required for the client_credentials grant",
        );
      }
      const result = await manager.startClientCredentials(
        parsed.data.name,
        config,
        project,
        caller,
      );
      return c.json({ data: result }, 201);
    }
    if (parsed.data.grant_type === "device_code") {
      const device = await manager.startDeviceCode(parsed.data.name, config, project, caller);
      // Field by field: `completion` is the background poll's promise, which
      // serializes as `{}` and is not the client's to await.
      return c.json(
        {
          data: {
            handle: device.handle,
            status: device.status,
            auth_url: device.auth_url,
            user_code: device.user_code,
            message: device.message,
          },
        },
        201,
      );
    }
    const start = await manager.startAuthorizationCodeDeferred(
      parsed.data.name,
      config,
      project,
      caller,
    );
    // Field by field: neither the internal `secretId` nor the `completion`
    // promise belongs on the wire (D2 — the browser leg finishes in background).
    return c.json(
      {
        data: {
          handle: start.handle,
          status: "pending_authorization",
          auth_url: start.authUrl,
          message:
            "Authorize in the browser at auth_url; the token is stored automatically when the callback arrives. Poll the status route until refresh_status is ok.",
        },
      },
      201,
    );
  });

  router.get("/:handle/status", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "read", project, name);
    const engine = c.get("engine");
    const secretId = await engine.resolveSecretId(buildHandle(c.req.param("handle")));
    c.get("limiter").checkSecret(secretId);
    const status = engine.getOAuthTokenStatus(secretId, callerFromToken(token, "rest"));
    return c.json({ data: status });
  });

  router.post("/:handle/refresh", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "rotate", project, name);
    const engine = c.get("engine");
    const secretId = await engine.resolveSecretId(buildHandle(c.req.param("handle")));
    c.get("limiter").checkSecret(secretId);
    const expiresAt = await engine.refreshOAuthToken(secretId, callerFromToken(token, "rest"));
    return c.json({ data: { refreshed: true, expires_at: expiresAt } });
  });

  return router;
}
