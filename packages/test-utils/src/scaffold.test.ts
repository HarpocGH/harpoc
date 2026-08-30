import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { describeWorkspaceDeps, getPkgRoot } from "./scaffold-helpers.js";

const pkgRoot = getPkgRoot(import.meta.url);

describe("test-utils", () => {
  describeWorkspaceDeps(pkgRoot, ["@harpoc/shared"]);

  describe("package shape (source-only, never built)", () => {
    const pkg = JSON.parse(readFileSync(resolve(pkgRoot, "package.json"), "utf-8")) as {
      private?: boolean;
      exports?: Record<string, unknown>;
      scripts?: Record<string, string>;
    };

    it("is private", () => {
      expect(pkg.private).toBe(true);
    });

    it("exports its TypeScript source directly", () => {
      expect(pkg.exports?.["."]).toBe("./src/index.ts");
    });

    it("has no build script", () => {
      expect(pkg.scripts?.build).toBeUndefined();
    });
  });
});
