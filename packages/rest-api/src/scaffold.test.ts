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

describe("rest-api", () => {
  describeBuildOutput(distDir);
  describeCrossPackageImports({
    "@harpoc/shared": () => import("@harpoc/shared"),
    "@harpoc/core": () => import("@harpoc/core"),
    "@harpoc/oauth-proxy": () => import("@harpoc/oauth-proxy"),
    "@harpoc/cert-manager": () => import("@harpoc/cert-manager"),
  });
  describeWorkspaceDeps(pkgRoot, [
    "@harpoc/shared",
    "@harpoc/core",
    "@harpoc/oauth-proxy",
    "@harpoc/cert-manager",
  ]);
});
