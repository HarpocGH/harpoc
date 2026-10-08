import { describe, expect, it } from "vitest";
import { z } from "zod";

import {
  accessPolicyInputSchema,
  certificateImportSchema,
  connectionConfigSchema,
  createSecretInputSchema,
  generateCsrRequestSchema,
  httpActionSchema,
  mcpServerConfigSchema,
  permissionListSchema,
  registerAgentInputSchema,
  rotateSecretInputSchema,
  secretIdListSchema,
  setAgentPermissionsInputSchema,
  setInjectionPolicyRequestSchema,
  startOAuthFlowInputSchema,
  updateAgentInputSchema,
  useSecretActionSchema,
  useSecretBodySchema,
} from "./schemas.js";
import { renderSchemaIssues } from "./schema-issues.js";

// ---------------------------------------------------------------------------
// Request-body strictness (compromise audit R10/A5): every object reachable
// from a REST request-body schema refuses unknown keys; records stay open by
// construction. The walker pins the rule once instead of one sample per object.
// ---------------------------------------------------------------------------

const LEAF_KINDS = new Set(["string", "number", "boolean", "enum", "literal", "unknown"]);

// zod 4: refinements live on the schema itself (no ZodEffects), a transform
// makes a ZodPipe (none in this file's schemas, walked for completeness), and
// an object's strictness is a `never` catchall.
function collectObjects(schema: z.ZodType, path: string, out: Array<[string, z.ZodObject]>): void {
  if (schema instanceof z.ZodObject) {
    out.push([path, schema]);
    for (const [key, child] of Object.entries(schema.shape)) {
      collectObjects(child as z.ZodType, `${path}.${key}`, out);
    }
    return;
  }
  if (
    schema instanceof z.ZodOptional ||
    schema instanceof z.ZodNullable ||
    schema instanceof z.ZodDefault
  ) {
    collectObjects(schema.def.innerType as z.ZodType, path, out);
    return;
  }
  if (schema instanceof z.ZodPipe) {
    collectObjects(schema.def.in as z.ZodType, path, out);
    return;
  }
  if (schema instanceof z.ZodArray) {
    collectObjects(schema.element as z.ZodType, `${path}[]`, out);
    return;
  }
  if (schema instanceof z.ZodUnion || schema instanceof z.ZodDiscriminatedUnion) {
    (schema.options as z.ZodType[]).forEach((option, i) =>
      collectObjects(option, `${path}|${i}`, out),
    );
    return;
  }
  if (
    schema instanceof z.ZodRecord &&
    LEAF_KINDS.has((schema.def.valueType as z.ZodType).def.type)
  ) {
    return;
  }
  if (LEAF_KINDS.has(schema.def.type)) return;
  throw new Error(`collectObjects: unhandled ${schema.def.type} at ${path}`);
}

function isStrict(object: z.ZodObject): boolean {
  return object.def.catchall instanceof z.ZodNever;
}

const REQUEST_BODY_SCHEMAS: Array<[string, z.ZodType]> = [
  ["createSecretInputSchema", createSecretInputSchema],
  ["rotateSecretInputSchema", rotateSecretInputSchema],
  ["useSecretBodySchema", useSecretBodySchema],
  ["setInjectionPolicyRequestSchema", setInjectionPolicyRequestSchema],
  ["mcpServerConfigSchema", mcpServerConfigSchema],
  ["connectionConfigSchema", connectionConfigSchema],
  ["accessPolicyInputSchema", accessPolicyInputSchema],
  ["registerAgentInputSchema", registerAgentInputSchema],
  ["updateAgentInputSchema", updateAgentInputSchema],
  ["setAgentPermissionsInputSchema", setAgentPermissionsInputSchema],
  ["certificateImportSchema", certificateImportSchema],
  ["generateCsrRequestSchema", generateCsrRequestSchema],
  ["startOAuthFlowInputSchema", startOAuthFlowInputSchema],
];

describe("request-body schemas refuse unknown keys at every level (R10/A5)", () => {
  it.each(REQUEST_BODY_SCHEMAS)("%s: every reachable object is strict", (_name, schema) => {
    const objects: Array<[string, z.ZodObject]> = [];
    collectObjects(schema, "$", objects);
    expect(objects.length).toBeGreaterThan(0);
    const lax = objects.filter(([, object]) => !isStrict(object)).map(([path]) => path);
    expect(lax).toEqual([]);
  });

  it("the walker reaches useSecretActionSchema's nested unions (self-check)", () => {
    const objects: Array<[string, z.ZodObject]> = [];
    collectObjects(useSecretBodySchema, "$", objects);
    const paths = objects.map(([path]) => path);
    expect(paths).toContain("$.action|0.injection|2"); // http → header injection
    expect(paths).toContain("$.action|7.operation|1"); // imap → fetch operation
    expect(paths.length).toBeGreaterThanOrEqual(24);
  });

  it("the walker refuses a kind it does not handle (self-check)", () => {
    const objects: Array<[string, z.ZodObject]> = [];
    expect(() =>
      collectObjects(z.record(z.string(), z.object({ a: z.string() })), "$", objects),
    ).toThrow("collectObjects: unhandled record at $");
    expect(() => collectObjects(z.tuple([z.string()]), "$", objects)).toThrow(
      "collectObjects: unhandled tuple at $",
    );
  });

  it("a top-level unknown key is refused (create)", () => {
    const result = createSecretInputSchema.safeParse({
      name: "k",
      type: "api_key",
      extra: 1,
    });
    expect(result.success).toBe(false);
    if (!result.success)
      expect(result.error.issues[0]?.message).toContain('Unrecognized key: "extra"');
  });

  it("an unknown key inside a nested action object is refused (http injection)", () => {
    const result = useSecretActionSchema.safeParse({
      type: "http",
      method: "GET",
      url: "https://api.example.com/x",
      injection: { type: "bearer", header_name: "X" },
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.map((i) => i.message).join(" ")).toContain(
        'Unrecognized key: "header_name"',
      );
    }
  });

  it("an unknown key inside a connection group's union arm is refused (mail.tls)", () => {
    const result = connectionConfigSchema.safeParse({
      mail: { tls: { ca: "x", verify: false } },
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const issue = result.error.issues.find((i) => i.path[0] === "mail" && i.path[1] === "tls");
      expect(issue?.message).toContain('Unrecognized key: "verify"');
    }
  });

  it("a record field stays open (http headers are keys by construction)", () => {
    expect(
      httpActionSchema.safeParse({
        type: "http",
        method: "GET",
        url: "https://api.example.com/x",
        injection: { type: "bearer" },
        headers: { "x-anything": "v" },
      }).success,
    ).toBe(true);
  });
});

describe("stored JSON column schemas (P3-11)", () => {
  it("permissionListSchema accepts a permission list and refuses an unknown value, value-free", () => {
    expect(permissionListSchema.safeParse(["read", "use"]).success).toBe(true);
    const refused = permissionListSchema.safeParse(["read", "fly"]);
    expect(refused.success).toBe(false);
    if (!refused.success) {
      expect(renderSchemaIssues(refused.error)).toBe(
        "1: must be one of list, read, use, create, rotate, revoke, admin",
      );
    }
  });

  it("secretIdListSchema refuses an empty id and a non-string", () => {
    expect(secretIdListSchema.safeParse(["a", "b"]).success).toBe(true);
    expect(secretIdListSchema.safeParse([""]).success).toBe(false);
    expect(secretIdListSchema.safeParse([1]).success).toBe(false);
  });
});
