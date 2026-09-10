import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  describeBuildOutput,
  describeCrossPackageImports,
  describeWorkspaceDeps,
  getPkgRoot,
} from "@harpoc/test-utils";

const pkgRoot = getPkgRoot(import.meta.url);
const distDir = resolve(pkgRoot, "dist");

describe("core", () => {
  describeBuildOutput(distDir);
  describeCrossPackageImports(["@harpoc/shared"]);
  describeWorkspaceDeps(pkgRoot, ["@harpoc/shared"]);

  it("builds the win32 job wrapper after tsc (D3, 2026-09-10)", () => {
    const pkg = JSON.parse(readFileSync(resolve(pkgRoot, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts["build"]).toBe("tsc && node scripts/build-win32-helper.mjs");
    expect(existsSync(resolve(pkgRoot, "scripts", "build-win32-helper.mjs"))).toBe(true);
  });
});
