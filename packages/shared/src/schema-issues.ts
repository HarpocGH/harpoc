/**
 * The one rendering of a zod refusal: `path: message` per issue, `<root>` for
 * a path-less one, joined by `; ` — the shape the engine's write-side refusal
 * and the REST wire mapper both grew independently.
 *
 * One exception. Zod's enum message quotes the value it rejected (`Invalid
 * enum value. Expected 'full' | 'filtered' | 'status_only', received 'X'`),
 * and a refusal message travels into audit details, CLI stderr and the REST
 * error body, where a caller-supplied string has no business being. An enum
 * issue therefore renders as its option list alone, which is the actionable
 * half anyway. `unrecognized_keys` deliberately keeps zod's wording: the key
 * names are the schema's own vocabulary and that exact sentence is pinned on
 * the REST and MCP wires.
 */

import type { ZodError } from "zod";

/** Every issue of a zod refusal, rendered value-free where the value is the caller's. */
export function renderSchemaIssues(error: ZodError): string {
  return error.issues
    .map((issue) => {
      const path = issue.path.join(".") || "<root>";
      return issue.code === "invalid_enum_value"
        ? `${path}: must be one of ${issue.options.join(", ")}`
        : `${path}: ${issue.message}`;
    })
    .join("; ");
}
