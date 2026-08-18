import { describe } from "vitest";
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
});
