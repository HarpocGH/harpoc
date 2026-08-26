import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { describeWorkspaceDeps, getPkgRoot } from "../../shared/src/scaffold-helpers.js";

const pkgRoot = getPkgRoot(import.meta.url);

describe("integration", () => {
  describeWorkspaceDeps(pkgRoot, [
    "@harpoc/shared",
    "@harpoc/core",
    "@harpoc/mcp-server",
    "@harpoc/rest-api",
    "@harpoc/sdk",
    "@harpoc/oauth-proxy",
    "@harpoc/cert-manager",
  ]);

  describe("expectVaultError helper", () => {
    it("is byte-identical to core's canonical copy", () => {
      const here = readFileSync(
        new URL("./test-helpers/expect-vault-error.ts", import.meta.url),
        "utf8",
      );
      const core = readFileSync(
        new URL("../../core/src/test-helpers/expect-vault-error.ts", import.meta.url),
        "utf8",
      );
      expect(here).toBe(core);
    });
  });
});
