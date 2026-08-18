import type { Context } from "hono";
import { VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

/**
 * Hono's `c.req.json()` rethrows the raw SyntaxError on an empty or malformed
 * body, which the error handler can only turn into a generic 500. Every
 * JSON-body route reads through this instead, so a client-side framing error
 * is a descriptive 400 (D1, deferred-minors tranche 2026-08-18).
 */
export async function readJsonBody(c: Context<HarpocEnv>): Promise<Record<string, unknown>> {
  try {
    return await c.req.json<Record<string, unknown>>();
  } catch {
    throw VaultError.schemaValidation("Request body must be valid JSON");
  }
}
