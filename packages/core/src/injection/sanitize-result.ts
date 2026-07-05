import type { UseSecretResponse } from "@harpoc/shared";
import type { InjectionGuard } from "./injection-guard.js";
import { mapStringLeaves } from "./output-sanitizer.js";

/**
 * Defense-in-depth, pattern-based sanitization of a use_secret result at the
 * interface boundary (MCP tool / REST route), applied atop the engine's
 * exact-value redaction. Exhaustive over every result type in the
 * UseSecretResponse union — a new execution context must be handled here, not
 * fall through to another context's shape.
 */
export function sanitizeUseSecretResult(result: UseSecretResponse, guard: InjectionGuard): void {
  switch (result.type) {
    case "http": {
      if (result.body) result.body = guard.sanitize(result.body);
      if (result.headers) {
        for (const [key, value] of Object.entries(result.headers)) {
          result.headers[key] = guard.sanitize(value);
        }
      }
      if (result.error) result.error = guard.sanitize(result.error);
      return;
    }
    case "process": {
      result.stdout = guard.sanitize(result.stdout);
      result.stderr = guard.sanitize(result.stderr);
      if (result.error) result.error = guard.sanitize(result.error);
      return;
    }
    case "mcp": {
      result.content = mapStringLeaves(result.content, (s) => guard.sanitize(s)) as unknown[];
      if (result.structured_content) {
        result.structured_content = mapStringLeaves(result.structured_content, (s) =>
          guard.sanitize(s),
        ) as Record<string, unknown>;
      }
      return;
    }
  }
}
