import { Hono } from "hono";
import { VaultError } from "@harpoc/shared";
import {
  connectionConfigSchema,
  createSecretInputSchema,
  matchesSecretNameScope,
  mcpServerConfigSchema,
  setInjectionPolicyRequestSchema,
  useSecretActionSchema,
} from "@harpoc/shared";
import { InjectionGuard, sanitizeUseSecretResult } from "@harpoc/core";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope, buildHandle, parseHandleParam } from "../middleware/scope.js";

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

    // If token is secret-name-scoped, filter results (name patterns, thesis §4.7)
    if (token.secrets?.length) {
      secrets = secrets.filter((s) => matchesSecretNameScope(s.name, token.secrets));
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

    const result = await engine.createSecret({
      name: parsed.data.name,
      type: parsed.data.type,
      project: parsed.data.project,
      value: parsed.data.value
        ? new Uint8Array(Buffer.from(parsed.data.value, "base64"))
        : undefined,
      expiresAt: parsed.data.expires_at,
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

  // Use secret (request- or process-mediated injection)
  router.post("/:handle/use", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "use", project, name);

    const engine = c.get("engine");
    const body = await c.req.json<Record<string, unknown>>();

    const parsed = useSecretActionSchema.safeParse(body.action);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }

    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle);
    c.get("limiter").checkSecret(secretId, true);
    const result = await engine.useSecret(handle, parsed.data);

    // Sanitize response to prevent credential leakage (parity across interfaces)
    sanitizeUseSecretResult(result, injectionGuard);

    return c.json({ data: result });
  });

  // Get injection policy (URL + command allowlists)
  router.get("/:handle/injection-policy", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "read", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const policy = await engine.getInjectionPolicy(handle);
    return c.json({ data: policy });
  });

  // Set injection policy (trusted administrative operation)
  router.put("/:handle/injection-policy", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "rotate", project, name);

    const engine = c.get("engine");
    const body = await c.req.json<Record<string, unknown>>();
    const parsed = setInjectionPolicyRequestSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }

    const handle = buildHandle(c.req.param("handle"));
    const { acknowledge_interpreters, ...policy } = parsed.data;
    await engine.setInjectionPolicy(handle, policy, { acknowledge_interpreters });
    return c.json({ data: { updated: true } });
  });

  // Get downstream MCP server config
  router.get("/:handle/mcp-server", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "read", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const config = await engine.getMcpServerConfig(handle);
    return c.json({ data: config ?? null });
  });

  // Set downstream MCP server config (trusted administrative operation)
  router.put("/:handle/mcp-server", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "rotate", project, name);

    const engine = c.get("engine");
    const body = await c.req.json<Record<string, unknown>>();
    const parsed = mcpServerConfigSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }

    const handle = buildHandle(c.req.param("handle"));
    await engine.setMcpServerConfig(handle, parsed.data);
    return c.json({ data: { updated: true } });
  });

  // Delete downstream MCP server config
  router.delete("/:handle/mcp-server", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "rotate", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const deleted = await engine.deleteMcpServerConfig(handle);
    return c.json({ data: { deleted } });
  });

  // Get endpoint-authentication config (database TLS / SSH host keys)
  router.get("/:handle/connection-config", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "read", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const config = await engine.getConnectionConfig(handle);
    return c.json({ data: config ?? null });
  });

  // Set endpoint-authentication config (trusted administrative operation)
  router.put("/:handle/connection-config", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "rotate", project, name);

    const engine = c.get("engine");
    const body = await c.req.json<Record<string, unknown>>();
    const parsed = connectionConfigSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }

    const handle = buildHandle(c.req.param("handle"));
    await engine.setConnectionConfig(handle, parsed.data);
    return c.json({ data: { updated: true } });
  });

  // Delete endpoint-authentication config
  router.delete("/:handle/connection-config", async (c) => {
    const token = c.get("token");
    const { project, name } = parseHandleParam(c.req.param("handle"));
    checkTokenScope(token, "rotate", project, name);

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const deleted = await engine.deleteConnectionConfig(handle);
    return c.json({ data: { deleted } });
  });

  return router;
}
