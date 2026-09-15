/**
 * The one rendering of a zod refusal: `path: message` per issue, `<root>` for
 * a path-less one, joined by `; ` — the shape the engine's write-side refusal
 * and the REST wire mapper both grew independently.
 *
 * One exception. An enum or literal refusal renders as its option list alone —
 * `must be one of a, b` — never as zod's own sentence: zod 3 quoted the value
 * it rejected, zod 4 (`invalid_value`) omits it by default, and this renderer
 * keeps the vault's wording either way so a refusal message can travel into
 * audit details, CLI stderr and the REST error body without a caller-supplied
 * string. `unrecognized_keys` deliberately keeps zod's wording (`Unrecognized
 * key: "url"`): the key names are the schema's own vocabulary and that exact
 * sentence is pinned on the REST and MCP wires.
 */

import type { ZodError } from "zod";

/** Every issue of a zod refusal, rendered value-free where the value is the caller's. */
export function renderSchemaIssues(error: ZodError): string {
  return error.issues
    .map((issue) => {
      const path = issue.path.map(String).join(".") || "<root>";
      return issue.code === "invalid_value"
        ? `${path}: must be one of ${issue.values.map(String).join(", ")}`
        : `${path}: ${issue.message}`;
    })
    .join("; ");
}
