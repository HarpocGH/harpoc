import { Hono } from "hono";
import { z } from "zod";
import { VaultError, ErrorCode } from "@harpoc/shared";
import {
  createSecretInputSchema,
  injectionConfigSchema,
  followRedirectsSchema,
  httpMethodSchema,
} from "@harpoc/shared";
import type { InjectionConfig, FollowRedirects, HttpMethod } from "@harpoc/shared";
import { InjectionGuard } from "@harpoc/core";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope, buildHandle, parseHandleParam } from "../middleware/scope.js";

const useSecretRequestSchema = z.object({
  method: httpMethodSchema,
  url: z.string().url(),
  headers: z.record(z.string()).optional(),
  body: z.string().optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

export function createSecretRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();
  const injectionGuard = new InjectionGuard();

  // List secrets
  router.get("/", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "list");

    const engine = c.get("engine");
    const project = c.req.query("project");

    // If token is project-scoped, enforce it
    if (token.project && project && project !== token.project) {
      throw VaultError.accessDenied(`Token is scoped to project: ${token.project}`);
    }
    const effectiveProject = project ?? token.project;

    let secrets = engine.listSecrets(effectiveProject);

    // If token is secret-name-scoped, filter results
    if (token.secrets?.length) {
      secrets = secrets.filter((s) => token.secrets?.includes(s.name));
    }

    return c.json({ data: secrets });
  });

  // Create secret
  router.post("/", async (c) => {
    const token = c.get("token");
    checkTokenScope(token, "create");

    const engine = c.get("engine");
    const body = await c.req.json<Record<string, unknown>>();

    const parsed = createSecretInputSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }

    checkTokenScope(token, "create", parsed.data.project, parsed.data.name);

    let expiresAt: number | undefined;
    if (body.expires_at !== undefined) {
      const expParsed = z.number().int().positive().safeParse(body.expires_at);
      if (!expParsed.success) {
        throw VaultError.schemaValidation("expires_at must be a positive integer (epoch ms)");
      }
      expiresAt = expParsed.data;
    }

    const result = await engine.createSecret({
      name: parsed.data.name,
      type: parsed.data.type,
      project: parsed.data.project,
      value: body.value ? new Uint8Array(Buffer.from(body.value as string, "base64")) : undefined,
      injection: parsed.data.injection as InjectionConfig | undefined,
      expiresAt,
    });

    return c.json({ data: result }, 201);
  });

  // Get secret info
  router.get("/:handle", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "read", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle);
    c.get("limiter").checkSecret(secretId);
    const info = await engine.getSecretInfo(handle);

    return c.json({ data: info });
  });

  // Get secret value (base64-encoded)
  router.get("/:handle/value", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "read", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle);
    c.get("limiter").checkSecret(secretId);
    const value = await engine.getSecretValue(handle);

    return c.json({ data: { value: Buffer.from(value).toString("base64") } });
  });

  // Revoke secret
  router.delete("/:handle", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "revoke", project, name);

    const confirm = c.req.query("confirm");
    if (confirm !== "true") {
      throw VaultError.invalidInput("Query parameter confirm=true is required");
    }

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle);
    c.get("limiter").checkSecret(secretId);
    await engine.revokeSecret(handle);

    return c.json({ data: { revoked: true } });
  });

  // Rotate secret
  router.post("/:handle/rotate", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "rotate", project, name);

    const engine = c.get("engine");
    const body = await c.req.json<{ value: string }>();

    if (!body.value) {
      throw VaultError.invalidInput("value (base64) is required");
    }

    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle);
    c.get("limiter").checkSecret(secretId);
    const newValue = new Uint8Array(Buffer.from(body.value, "base64"));
    await engine.rotateSecret(handle, newValue);

    return c.json({ data: { rotated: true } });
  });

  // Use secret (HTTP injection)
  router.post("/:handle/use", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "use", project, name);

    const engine = c.get("engine");
    const body = await c.req.json<Record<string, unknown>>();

    if (!body.request || !body.injection) {
      throw new VaultError(ErrorCode.INVALID_INPUT, "request and injection are required");
    }

    const reqParsed = useSecretRequestSchema.safeParse(body.request);
    if (!reqParsed.success) {
      throw VaultError.schemaValidation(reqParsed.error.issues.map((i) => i.message).join(", "));
    }

    const injParsed = injectionConfigSchema.safeParse(body.injection);
    if (!injParsed.success) {
      throw VaultError.schemaValidation(injParsed.error.issues.map((i) => i.message).join(", "));
    }

    if (body.follow_redirects !== undefined) {
      const frParsed = followRedirectsSchema.safeParse(body.follow_redirects);
      if (!frParsed.success) {
        throw VaultError.schemaValidation("Invalid follow_redirects value");
      }
    }

    const req = reqParsed.data;
    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle);
    c.get("limiter").checkSecret(secretId, true);
    const result = await engine.useSecret(
      handle,
      {
        method: req.method as HttpMethod,
        url: req.url,
        headers: req.headers,
        body: req.body,
        timeoutMs: req.timeout_ms,
      },
      injParsed.data as InjectionConfig,
      body.follow_redirects as FollowRedirects | undefined,
    );

    // Sanitize response to prevent credential leakage (parity with MCP server)
    if (result.body) {
      result.body = injectionGuard.sanitize(result.body);
    }
    if (result.headers) {
      for (const [key, value] of Object.entries(result.headers)) {
        result.headers[key] = injectionGuard.sanitize(value);
      }
    }
    if (result.error) {
      result.error = injectionGuard.sanitize(result.error);
    }

    return c.json({ data: result });
  });

  return router;
}
