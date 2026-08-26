import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  describeBuildOutput,
  describeCrossPackageImports,
  describeWorkspaceDeps,
  getPkgRoot,
} from "../../shared/src/scaffold-helpers.js";

const pkgRoot = getPkgRoot(import.meta.url);
const distDir = resolve(pkgRoot, "dist");

describe("cli", () => {
  describeBuildOutput(distDir, { shebang: true });
  describeCrossPackageImports([
    "@harpoc/shared",
    "@harpoc/core",
    "@harpoc/cert-manager",
    "@harpoc/mcp-server",
    "@harpoc/oauth-proxy",
    "@harpoc/rest-api",
  ]);
  describeWorkspaceDeps(pkgRoot, [
    "@harpoc/shared",
    "@harpoc/core",
    "@harpoc/cert-manager",
    "@harpoc/mcp-server",
    "@harpoc/oauth-proxy",
    "@harpoc/rest-api",
    "@harpoc/web-ui",
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
