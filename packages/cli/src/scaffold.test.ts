import { resolve } from "node:path";
import { describe } from "vitest";
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
    "@harpoc/mcp-server",
    "@harpoc/oauth-proxy",
    "@harpoc/rest-api",
  ]);
  describeWorkspaceDeps(pkgRoot, [
    "@harpoc/shared",
    "@harpoc/core",
    "@harpoc/mcp-server",
    "@harpoc/oauth-proxy",
    "@harpoc/rest-api",
  ]);
});
