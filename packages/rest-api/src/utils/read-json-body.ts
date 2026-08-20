import type { Context } from "hono";
import { VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

/**
 * Hono's `c.req.json()` rethrows the raw SyntaxError on an empty or malformed
 * body, which the error handler can only turn into a generic 500. Every
 * JSON-body route reads through this instead, so a client-side framing error
 * is a descriptive 400 (D1, deferred-minors tranche 2026-08-18). A
 * syntactically-valid-but-non-object body (`null`, an array, a bare literal)
 * parses without throwing, so it also needs an explicit guard — without one,
 * a route dereferencing a field off the result (e.g. `body.action`) throws a
 * TypeError that the error handler can only turn into a generic 500 (Task 3,
 * polish tranche 2026-08-20).
 */
export async function readJsonBody(c: Context<HarpocEnv>): Promise<Record<string, unknown>> {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    throw VaultError.schemaValidation("Request body must be valid JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw VaultError.schemaValidation("Request body must be valid JSON");
  }
  return body as Record<string, unknown>;
}
