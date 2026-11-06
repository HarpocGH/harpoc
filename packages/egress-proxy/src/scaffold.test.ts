import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  describeBuildOutput,
  describeCrossPackageImports,
  describeWorkspaceDeps,
} from "@harpoc/test-utils";

const PKG_ROOT = join(import.meta.dirname, "..");
const DIST_ROOT = join(PKG_ROOT, "dist");

describe("package scaffold", () => {
  it("has package.json with correct name", async () => {
    const pkg = await import("../package.json", { with: { type: "json" } });
    expect(pkg.default.name).toBe("@harpoc/egress-proxy");
  });

  it("has package.json with correct type", async () => {
    const pkg = await import("../package.json", { with: { type: "json" } });
    expect(pkg.default.type).toBe("module");
  });

  it("has ESM exports defined", async () => {
    const pkg = await import("../package.json", { with: { type: "json" } });
    const exports = pkg.default.exports["."] as { types: string; import: string };
    expect(exports.types).toBe("./dist/index.d.ts");
    expect(exports.import).toBe("./dist/index.js");
  });
});

describeBuildOutput(DIST_ROOT);
describeCrossPackageImports({
  "@harpoc/shared": () => import("@harpoc/shared"),
  "@harpoc/core": () => import("@harpoc/core"),
});
describeWorkspaceDeps(PKG_ROOT, ["@harpoc/shared", "@harpoc/core"]);
