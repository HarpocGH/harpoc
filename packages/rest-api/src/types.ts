import type { VaultEngine } from "@harpoc/core";
import type { VaultApiToken } from "@harpoc/shared";
import type { RateLimiter } from "./middleware/rate-limit.js";

export type HarpocEnv = {
  Variables: {
    engine: VaultEngine;
    token: VaultApiToken;
    limiter: RateLimiter;
  };
};
