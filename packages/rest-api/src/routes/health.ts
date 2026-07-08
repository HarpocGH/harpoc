import { Hono } from "hono";
import { matchesSecretNameScope, VAULT_VERSION, VaultError, VaultState } from "@harpoc/shared";
import type { HealthResponse } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import { checkTokenScope } from "../middleware/scope.js";

const MAX_EXPIRING_WINDOW_DAYS = 365;

export function createHealthRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.get("/", (c) => {
    const engine = c.get("engine");
    const health: HealthResponse = {
      state: engine.getState(),
      version: VAULT_VERSION,
    };
    return c.json({ data: health });
  });

  return router;
}

export function createExpiringSecretsRoute(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.get("/", (c) => {
    const token = c.get("token");
    checkTokenScope(token, "list");

    const engine = c.get("engine");
    if (engine.getState() !== VaultState.UNLOCKED) {
      return c.json({ data: { count: 0 } });
    }

    const daysParam = c.req.query("days");
    const days = daysParam === undefined ? 7 : Number(daysParam);
    if (!Number.isInteger(days) || days < 1 || days > MAX_EXPIRING_WINDOW_DAYS) {
      throw VaultError.invalidInput(
        `days must be an integer between 1 and ${MAX_EXPIRING_WINDOW_DAYS}`,
      );
    }
    const threshold = Date.now() + days * 24 * 60 * 60 * 1000;

    let secrets = engine.listSecrets(token.project);
    if (token.secrets?.length) {
      secrets = secrets.filter((s) => matchesSecretNameScope(s.name, token.secrets));
    }
    const expiring = secrets.filter(
      (s) => s.expiresAt !== null && s.expiresAt <= threshold && s.status === "active",
    );

    return c.json({ data: expiring });
  });

  return router;
}
