import { Hono } from "hono";
import { auditQuerySchema } from "@harpoc/shared";
import { VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope } from "../middleware/scope.js";

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

    const raw = {
      secret_id: secretId ?? undefined,
      event_type: eventType ?? undefined,
      since: since ? parseInt(since, 10) : undefined,
      until: until ? parseInt(until, 10) : undefined,
      limit: limit ? parseInt(limit, 10) : undefined,
    };

    const parsed = auditQuerySchema.safeParse(raw);
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }

    const events = engine.queryAudit({
      secretId: parsed.data.secret_id,
      eventType: parsed.data.event_type,
      since: parsed.data.since,
      until: parsed.data.until,
      limit: parsed.data.limit,
    });

    return c.json({ data: events });
  });

  return router;
}
