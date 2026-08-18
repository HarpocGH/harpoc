import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { VaultEngine } from "@harpoc/core";
import { SecretType } from "@harpoc/shared";
import { describeWorkspaceDeps } from "../../shared/src/scaffold-helpers.js";

const PKG_ROOT = join(import.meta.dirname, "..");

describe("@harpoc/e2e scaffold", () => {
  it("resolves its workspace dependencies", () => {
    expect(typeof VaultEngine).toBe("function");
    expect(SecretType.API_KEY).toBe("api_key");
  });
});

describeWorkspaceDeps(PKG_ROOT, [
  "@harpoc/shared",
  "@harpoc/core",
  "@harpoc/mcp-server",
  "@harpoc/rest-api",
  "@harpoc/sdk",
  "@harpoc/cli",
]);
