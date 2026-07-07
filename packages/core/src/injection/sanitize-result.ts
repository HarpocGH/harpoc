import type { UseSecretResponse } from "@harpoc/shared";
import { assertNever } from "../assert-never.js";
import type { InjectionGuard } from "./injection-guard.js";
import { mapStringLeaves } from "./output-sanitizer.js";

/**
 * Defense-in-depth, pattern-based sanitization of a use_secret result at the
 * interface boundary (MCP tool / REST route), applied atop the engine's
 * exact-value redaction. Exhaustive over every result type in the
 * UseSecretResponse union — the never-typed default makes an unhandled new
 * context a compile error, and a shape unknown at runtime is rejected rather
 * than passed through unsanitized.
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
    case "database": {
      result.rows = mapStringLeaves(result.rows, (s) => guard.sanitize(s)) as unknown[];
      if (result.error) result.error = guard.sanitize(result.error);
      return;
    }
    case "git":
    case "ssh": {
      result.stdout = guard.sanitize(result.stdout);
      result.stderr = guard.sanitize(result.stderr);
      if (result.error) result.error = guard.sanitize(result.error);
      return;
    }

    default:
      return assertNever(result, "result type");
  }
}
