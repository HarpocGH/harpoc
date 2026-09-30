import { resolve } from "node:path";
import { describe } from "vitest";
import {
  describeBuildOutput,
  describeCrossPackageImports,
  describeWorkspaceDeps,
  getPkgRoot,
} from "@harpoc/test-utils";

const pkgRoot = getPkgRoot(import.meta.url);
const distDir = resolve(pkgRoot, "dist");

describe("cli", () => {
  describeBuildOutput(distDir, { shebang: true });
  describeCrossPackageImports({
    "@harpoc/shared": () => import("@harpoc/shared"),
    "@harpoc/core": () => import("@harpoc/core"),
    "@harpoc/cert-manager": () => import("@harpoc/cert-manager"),
    "@harpoc/mcp-server": () => import("@harpoc/mcp-server"),
    "@harpoc/oauth-proxy": () => import("@harpoc/oauth-proxy"),
    "@harpoc/rest-api": () => import("@harpoc/rest-api"),
  });
  describeWorkspaceDeps(pkgRoot, [
    "@harpoc/shared",
    "@harpoc/core",
    "@harpoc/cert-manager",
    "@harpoc/mcp-server",
    "@harpoc/oauth-proxy",
    "@harpoc/rest-api",
    "@harpoc/web-ui",
  ]);
});
