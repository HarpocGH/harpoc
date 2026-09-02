import { describe, expect, it } from "vitest";
import { z } from "zod";
import { ErrorCode } from "@harpoc/shared";
import { schemaValidationError } from "./schema-error.js";

const schema = z
  .object({ name: z.string(), nested: z.object({ n: z.number() }).strict() })
  .strict();

describe("schemaValidationError", () => {
  it("renders each issue as path: message, joined by '; ', with <root> for a path-less issue", () => {
    const parsed = schema.safeParse({
      nested: { n: "x", extra: 1 },
      stray: true,
    });
    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    const err = schemaValidationError(parsed.error);
    expect(err.code).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
    expect(err.message).toBe(
      "name: Required; nested.n: Expected number, received string; nested: Unrecognized key(s) in object: 'extra'; <root>: Unrecognized key(s) in object: 'stray'",
    );
  });

  it("names the unrecognized keys the caller sent, as zod renders them", () => {
    const parsed = schema.safeParse({
      name: "k",
      nested: { n: 1 },
      "sk-live-not-a-key": 1,
    });
    if (parsed.success) throw new Error("expected a refusal");
    expect(schemaValidationError(parsed.error).message).toBe(
      "<root>: Unrecognized key(s) in object: 'sk-live-not-a-key'",
    );
  });
});
