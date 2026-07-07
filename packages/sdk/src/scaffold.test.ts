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

describe("sdk", () => {
  describeBuildOutput(distDir);
  describeCrossPackageImports(["@harpoc/shared", "@harpoc/core"]);
  describeWorkspaceDeps(pkgRoot, ["@harpoc/shared"]);
});
