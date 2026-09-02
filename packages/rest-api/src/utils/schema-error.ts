import type { ZodError } from "zod";
import { VaultError } from "@harpoc/shared";

/**
 * The one rendering of a zod refusal on the REST surface: `path: message` per
 * issue, `<root>` for a path-less issue (an unrecognized-keys issue names the
 * keys in its message), issues joined by `; ` — the engine's own write-side
 * format (`VaultEngine.setInjectionPolicy`). Before this every route joined
 * bare messages, so a body missing ten fields read `Required, Required, …`
 * (compromise audit R3, R10/A5).
 */
export function schemaValidationError(error: ZodError): VaultError {
  return VaultError.schemaValidation(
    error.issues.map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`).join("; "),
  );
}
