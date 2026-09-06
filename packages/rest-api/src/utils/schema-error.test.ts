import { describe, expect, it } from "vitest";
import { z } from "zod";
import { ErrorCode } from "@harpoc/shared";
import { schemaValidationError } from "./schema-error.js";

const schema = z
  .object({ name: z.string(), nested: z.object({ n: z.number() }).strict() })
  .strict();

const enumSchema = z.object({ response_mode: z.enum(["full", "filtered", "status_only"]) });

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

  /**
   * D5: an enum refusal names the options, never the value the caller sent.
   * zod 3.25.76 renders `Invalid enum value. Expected 'full' | … ,
   * received '1BAD'`, and a rejected value can be a fragment of a credential.
   */
  it("an enum issue names the options and never the rejected value (D5)", () => {
    const parsed = enumSchema.safeParse({ response_mode: "1BAD" });
    if (parsed.success) throw new Error("expected a refusal");
    const { message } = schemaValidationError(parsed.error);
    expect(message).toBe("response_mode: must be one of full, filtered, status_only");
    expect(message).not.toContain("1BAD");
  });
});
