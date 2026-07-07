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
