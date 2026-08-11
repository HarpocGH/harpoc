import { describe, it, expect } from "vitest";
import { VaultEngine } from "@harpoc/core";
import { SecretType } from "@harpoc/shared";

describe("@harpoc/e2e scaffold", () => {
  it("resolves its workspace dependencies", () => {
    expect(typeof VaultEngine).toBe("function");
    expect(SecretType.API_KEY).toBe("api_key");
  });
});
