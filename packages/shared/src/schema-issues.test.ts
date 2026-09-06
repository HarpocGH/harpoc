import { describe, expect, it } from "vitest";
import { z } from "zod";
import { renderSchemaIssues } from "./schema-issues.js";

const policy = z
  .object({
    response_mode: z.enum(["full", "filtered", "status_only"]),
    limits: z.object({ port: z.number() }),
  })
  .strict();

function refusalOf(input: unknown): z.ZodError {
  const parsed = policy.safeParse(input);
  if (parsed.success) throw new Error("fixture parsed — the case needs an invalid input");
  return parsed.error;
}

describe("renderSchemaIssues", () => {
  it("joins a nested path with dots", () => {
    const error = refusalOf({ response_mode: "full", limits: { port: "80" } });
    expect(renderSchemaIssues(error)).toBe("limits.port: Expected number, received string");
  });

  it("renders a path-less issue under <root>", () => {
    const parsed = z.string().safeParse(5);
    if (parsed.success) throw new Error("fixture parsed");
    expect(renderSchemaIssues(parsed.error)).toBe("<root>: Expected string, received number");
  });

  it("joins every issue with a semicolon", () => {
    const error = refusalOf({ response_mode: "1BAD", limits: { port: "80" } });
    expect(renderSchemaIssues(error)).toBe(
      "response_mode: must be one of full, filtered, status_only; " +
        "limits.port: Expected number, received string",
    );
  });

  it("renders an enum refusal as its option list", () => {
    const error = refusalOf({ response_mode: "1BAD", limits: { port: 80 } });
    expect(renderSchemaIssues(error)).toBe(
      "response_mode: must be one of full, filtered, status_only",
    );
  });

  it("never echoes the value an enum refused", () => {
    const error = refusalOf({ response_mode: "1BAD", limits: { port: 80 } });
    expect(renderSchemaIssues(error)).not.toContain("1BAD");
  });

  it("renders a path-less enum refusal under <root>", () => {
    const parsed = z.enum(["a", "b"]).safeParse("c");
    if (parsed.success) throw new Error("fixture parsed");
    expect(renderSchemaIssues(parsed.error)).toBe("<root>: must be one of a, b");
  });

  it("keeps zod's unrecognized-keys wording (pinned on both wires)", () => {
    const error = refusalOf({ response_mode: "full", limits: { port: 80 }, url: "http://x" });
    expect(renderSchemaIssues(error)).toBe("<root>: Unrecognized key(s) in object: 'url'");
  });
});
