import { describe } from "vitest";
import {
  describeCrossPackageImports,
  describeWorkspaceDeps,
  getPkgRoot,
} from "../../shared/src/scaffold-helpers.js";

const pkgRoot = getPkgRoot(import.meta.url);

describe("web-ui", () => {
  // No describeBuildOutput: the build artifact is a Vite site (index.html +
  // hashed assets), not a tsc dist/index.js.
  describeCrossPackageImports(["@harpoc/shared"]);
  describeWorkspaceDeps(pkgRoot, ["@harpoc/shared"]);
});
