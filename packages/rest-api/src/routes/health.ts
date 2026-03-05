import { Hono } from "hono";
import { VAULT_VERSION, VaultState } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

export function createHealthRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.get("/", (c) => {
    const engine = c.get("engine");
    return c.json({
      data: {
        state: engine.getState(),
        version: VAULT_VERSION,
      },
    });
  });

  return router;
}

export function createExpiringSecretsRoute(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.get("/", (c) => {
    const engine = c.get("engine");
    if (engine.getState() !== VaultState.UNLOCKED) {
      return c.json({ data: { count: 0 } });
    }

    const daysParam = c.req.query("days");
    const days = daysParam ? parseInt(daysParam, 10) : 7;
    const threshold = Date.now() + days * 24 * 60 * 60 * 1000;

    const secrets = engine.listSecrets();
    const expiring = secrets.filter(
      (s) => s.expiresAt !== null && s.expiresAt <= threshold && s.status === "active",
    );

    return c.json({ data: expiring });
  });

  return router;
}
