import { Hono } from "hono";
import type { Permission } from "@harpoc/shared";
import {
  AgentStatus,
  VaultError,
  agentNameSchema,
  callerFromToken,
  listAgentsQuerySchema,
  registerAgentInputSchema,
  setAgentPermissionsInputSchema,
  updateAgentInputSchema,
} from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope, buildHandle, parseHandleParam } from "../middleware/scope.js";
import { readJsonBody } from "../utils/read-json-body.js";

/**
 * A malformed name never reaches the registry: the lookup would answer
 * `AGENT_NOT_FOUND` for a string that could not name an agent in the first
 * place.
 */
function parseAgentName(raw: string): string {
  const parsed = agentNameSchema.safeParse(raw);
  if (!parsed.success) {
    throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
  }
  return parsed.data;
}

/**
 * Agent governance (v1.4). Governance operations have no per-secret referent,
 * so `admin` at the interface is the gate — checked before any engine call.
 * The permission-matrix cell is the one exception: it names a secret, so the
 * token's project and name dimensions apply on top.
 */
export function createAgentRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.get("/", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");

    const status = c.req.query("status");
    const parsed = listAgentsQuerySchema.safeParse({ status: status ?? undefined });
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }

    const engine = c.get("engine");
    const agents = engine.listAgents(
      parsed.data.status ?? AgentStatus.ACTIVE,
      callerFromToken(token, "rest"),
    );

    return c.json({ data: agents });
  });

  router.post("/", async (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");

    const body = await readJsonBody(c);
    const parsed = registerAgentInputSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }

    const engine = c.get("engine");
    const agent = engine.registerAgent(parsed.data, callerFromToken(token, "rest"));

    return c.json({ data: agent }, 201);
  });

  router.get("/:name", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");
    const name = parseAgentName(c.req.param("name"));

    const engine = c.get("engine");
    return c.json({ data: engine.getAgent(name, callerFromToken(token, "rest")) });
  });

  // Replace semantics: an omitted field is cleared (the CLI merges instead).
  router.put("/:name", async (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");
    const name = parseAgentName(c.req.param("name"));

    const body = await readJsonBody(c);
    const parsed = updateAgentInputSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }

    const engine = c.get("engine");
    const agent = engine.updateAgent(name, parsed.data, callerFromToken(token, "rest"));

    return c.json({ data: agent });
  });

  // Body-less, like /oauth/:handle/refresh.
  router.post("/:name/deactivate", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");
    const name = parseAgentName(c.req.param("name"));

    const engine = c.get("engine");
    const result = engine.deactivateAgent(name, callerFromToken(token, "rest"));

    return c.json({ data: result });
  });

  router.post("/:name/activate", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");
    const name = parseAgentName(c.req.param("name"));

    const engine = c.get("engine");
    const agent = engine.activateAgent(name, callerFromToken(token, "rest"));

    return c.json({ data: agent });
  });

  router.delete("/:name", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");
    const name = parseAgentName(c.req.param("name"));

    const engine = c.get("engine");
    const result = engine.deleteAgent(name, callerFromToken(token, "rest"));

    return c.json({ data: result });
  });

  router.get("/:name/policies", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");
    const name = parseAgentName(c.req.param("name"));

    const engine = c.get("engine");
    const policies = engine.listAgentPolicies(name, callerFromToken(token, "rest"));

    return c.json({ data: policies });
  });

  // The permission matrix cell: replace-semantics per (agent, secret).
  router.put("/:name/secrets/:handle/permissions", async (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");
    const name = parseAgentName(c.req.param("name"));

    const handleParam = c.req.param("handle");
    const { project, name: secretName } = parseHandleParam(handleParam);
    checkTokenScope(token, "admin", project, secretName);

    const body = await readJsonBody(c);
    const parsed = setAgentPermissionsInputSchema.safeParse(body);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }

    const engine = c.get("engine");
    // Resolve the handle here so an unknown secret answers SECRET_NOT_FOUND
    // rather than reaching the policy insert as a dangling reference.
    const secretId = await engine.resolveSecretId(buildHandle(handleParam));
    const result = engine.setAgentPermissions(
      name,
      secretId,
      parsed.data.permissions as Permission[],
      parsed.data.expires_at,
      token.sub,
      callerFromToken(token, "rest"),
    );

    return c.json({ data: result });
  });

  return router;
}
