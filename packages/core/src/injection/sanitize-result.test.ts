import { ErrorCode, VaultError } from "@harpoc/shared";
import type { UseSecretResponse } from "@harpoc/shared";
import { describe, expect, it } from "vitest";
import { InjectionGuard } from "./injection-guard.js";
import { sanitizeUseSecretResult } from "./sanitize-result.js";

describe("sanitizeUseSecretResult", () => {
  const guard = new InjectionGuard();

  it("sanitizes credential patterns in a known result shape", () => {
    const result: UseSecretResponse = {
      type: "http",
      status: 200,
      body: "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
    };
    sanitizeUseSecretResult(result, guard);
    expect(result.body).toContain("[REDACTED]");
  });

  // H3: a hostile downstream MCP server chooses its own key names, and the
  // boundary guard is the last layer before JSON.stringify hands the result to
  // the model. Key position must be sanitized like value position.
  it("sanitizes a credential-shaped string in an MCP structured_content key", () => {
    const bearerish = "Bearer abcdefghijklmnopqrstuvwxyz012345";
    const result: UseSecretResponse = {
      type: "mcp",
      content: [{ type: "text", text: "ok" }],
      structured_content: { [bearerish]: 1 },
    };
    sanitizeUseSecretResult(result, guard);
    expect(JSON.stringify(result)).not.toContain(bearerish);
  });

  it("sanitizes a credential-shaped key inside an MCP content block", () => {
    const bearerish = "Bearer abcdefghijklmnopqrstuvwxyz012345";
    const result: UseSecretResponse = {
      type: "mcp",
      content: [{ type: "text", text: "ok", meta: { [bearerish]: true } }],
    };
    sanitizeUseSecretResult(result, guard);
    expect(JSON.stringify(result)).not.toContain(bearerish);
  });

  it("sanitizes a credential-shaped database column name in a row object", () => {
    const bearerish = "Bearer abcdefghijklmnopqrstuvwxyz012345";
    const result: UseSecretResponse = {
      type: "database",
      rows: [{ [bearerish]: 1 }],
      fields: [],
      row_count: 1,
      truncated: false,
    };
    sanitizeUseSecretResult(result, guard);
    expect(JSON.stringify(result.rows)).not.toContain(bearerish);
  });

  it("rejects an unknown result type instead of passing it through unsanitized", () => {
    const bogus = { type: "ftp", payload: "x" } as unknown as UseSecretResponse;
    try {
      sanitizeUseSecretResult(bogus, guard);
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_INPUT);
      expect((e as VaultError).message).toContain("Unsupported result type: ftp");
    }
  });
});
