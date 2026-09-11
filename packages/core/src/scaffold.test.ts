import { spawnSync } from "node:child_process";
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

  it("the build helper exits 0 on every platform — it never fails the build (R8, 2026-09-10)", () => {
    const res = spawnSync(
      process.execPath,
      [resolve(pkgRoot, "scripts", "build-win32-helper.mjs")],
      {
        cwd: pkgRoot,
        encoding: "utf8",
        timeout: 120_000,
        windowsHide: true,
      },
    );
    expect(res.status).toBe(0);
    if (process.platform === "win32") expect(res.stdout + res.stderr).toMatch(/^\[harpoc-job\] /m);
    else expect(res.stdout + res.stderr).toBe("");
  }, 130_000);
});
