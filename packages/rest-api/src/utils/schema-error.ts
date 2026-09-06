import type { ZodError } from "zod";
import { renderSchemaIssues, VaultError } from "@harpoc/shared";

/**
 * The one rendering of a zod refusal on the REST surface, now the shared
 * `renderSchemaIssues` (D5, 2026-09-06): `path: message` per issue, `<root>`
 * for a path-less issue (an unrecognized-keys issue names the keys in its
 * message), issues joined by `; `, and an enum issue rendered `must be one of
 * …` so the rejected value never reaches the message. Before the shared
 * renderer this file and `VaultEngine.setInjectionPolicy` carried the same
 * code twice, and both echoed the value (compromise audit R3, R10/A5).
 */
export function schemaValidationError(error: ZodError): VaultError {
  return VaultError.schemaValidation(renderSchemaIssues(error));
}
