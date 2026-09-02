import { Hono } from "hono";
import { auditQuerySchema, auditScopeFromToken } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope } from "../middleware/scope.js";
import { schemaValidationError } from "../utils/schema-error.js";

export function createAuditRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.get("/", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");

    const engine = c.get("engine");

    const secretId = c.req.query("secret_id");
    const eventType = c.req.query("event_type");
    const since = c.req.query("since");
    const until = c.req.query("until");
    const limit = c.req.query("limit");
    const success = c.req.query("success");
    const principalType = c.req.query("principal_type");
    const principalId = c.req.query("principal_id");

    const raw = {
      secret_id: secretId ?? undefined,
      event_type: eventType ?? undefined,
      since: since ? parseInt(since, 10) : undefined,
      until: until ? parseInt(until, 10) : undefined,
      limit: limit ? parseInt(limit, 10) : undefined,
      success:
        success === undefined
          ? undefined
          : success === "true"
            ? true
            : success === "false"
              ? false
              : success,
      principal_type: principalType ?? undefined,
      principal_id: principalId ?? undefined,
    };

    const parsed = auditQuerySchema.safeParse(raw);
    if (!parsed.success) {
      throw schemaValidationError(parsed.error);
    }

    // The permission dimension alone is not the token's scope: a project- or
    // name-pattern-scoped admin token must not read audit detail for secrets it
    // cannot address (L10).
    const events = engine.queryAudit(
      {
        secretId: parsed.data.secret_id,
        eventType: parsed.data.event_type,
        since: parsed.data.since,
        until: parsed.data.until,
        limit: parsed.data.limit,
        success: parsed.data.success,
        principalType: parsed.data.principal_type,
        principalId: parsed.data.principal_id,
      },
      auditScopeFromToken(token),
    );

    return c.json({ data: events });
  });

  router.post("/verify", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "admin");

    const engine = c.get("engine");
    const report = engine.verifyAuditChain();
    // The tail is anchor material with a CLI-only export path (`harpoc audit
    // anchor`) — an anchor stored via the browser would live on the same disk
    // it guards.
    return c.json({
      data: {
        valid: report.valid,
        checked: report.checked,
        first_broken_id: report.firstBrokenId,
      },
    });
  });

  return router;
}
