import type { Context } from "hono";
import {
  MAX_REQUEST_BODY_BYTES,
  VaultError,
  contentLengthExceeds,
  readBodyCapped,
} from "@harpoc/shared";
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
 * Since 2026-09-23 (P1F-7) the body is read under `MAX_REQUEST_BODY_BYTES`: a
 * declared or streamed size over the cap — or a malformed `Content-Length`,
 * fail-closed — is refused `INVALID_INPUT` before any byte is parsed, the MCP
 * listener's bound.
 */
export async function readJsonBody(c: Context<HarpocEnv>): Promise<Record<string, unknown>> {
  if (contentLengthExceeds(c.req.raw.headers, MAX_REQUEST_BODY_BYTES)) {
    throw VaultError.invalidInput("Request body too large");
  }
  const read = await readBodyCapped(c.req.raw.body, MAX_REQUEST_BODY_BYTES);
  if (!read.ok) {
    throw VaultError.invalidInput("Request body too large");
  }
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder().decode(read.bytes));
  } catch {
    throw VaultError.schemaValidation("Request body must be valid JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw VaultError.schemaValidation("Request body must be valid JSON");
  }
  return body as Record<string, unknown>;
}
