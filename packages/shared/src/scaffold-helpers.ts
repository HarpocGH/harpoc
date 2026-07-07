/**
 * Shared test helpers for scaffold.test.ts files across all packages.
 * Excluded from the build via tsconfig.json — test-time only.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/** Resolve the package root directory from `import.meta.url` of the caller. */
export function getPkgRoot(importMetaUrl: string): string {
  return resolve(dirname(fileURLToPath(importMetaUrl)), "..");
}

/**
 * Assert that dist/index.js and dist/index.d.ts exist and contain valid ESM exports.
 * Optionally checks for a shebang line (CLI / MCP server executables).
 */
export function describeBuildOutput(distDir: string, options?: { shebang?: boolean }): void {
  describe("build output", () => {
    it("dist/index.js exists", () => {
      expect(existsSync(resolve(distDir, "index.js"))).toBe(true);
    });

    it("dist/index.d.ts exists", () => {
      expect(existsSync(resolve(distDir, "index.d.ts"))).toBe(true);
    });

    it("dist/index.js is valid ESM", () => {
      const content = readFileSync(resolve(distDir, "index.js"), "utf-8");
      expect(content).toMatch(/export\s*[{*]/);
    });

    it("dist/index.d.ts is valid ESM", () => {
      const content = readFileSync(resolve(distDir, "index.d.ts"), "utf-8");
      expect(content).toMatch(/export\s*[{*]/);
    });

    if (options?.shebang) {
      it("dist/index.js has shebang", () => {
        const content = readFileSync(resolve(distDir, "index.js"), "utf-8");
        expect(content.startsWith("#!/usr/bin/env node")).toBe(true);
      });
    }
  });
}

/** Assert that each specifier can be dynamically imported (cross-package wiring). */
export function describeCrossPackageImports(specifiers: string[]): void {
  describe("cross-package imports", () => {
    for (const specifier of specifiers) {
      // The first import of @harpoc/core loads native addons (better-sqlite3,
      // argon2) and large dependency graphs; under a fully parallel suite run
      // that regularly exceeds the 5 s default timeout.
      it(`can import ${specifier}`, { timeout: 30_000 }, async () => {
        const mod = await import(specifier);
        expect(mod).toBeDefined();
      });
    }
  });
}

/** Assert that each dep is declared as `workspace:*` in the package's dependencies. */
export function describeWorkspaceDeps(pkgRoot: string, deps: string[]): void {
  describe("workspace dependencies", () => {
    for (const dep of deps) {
      it(`declares ${dep} as workspace:*`, () => {
        const raw = readFileSync(resolve(pkgRoot, "package.json"), "utf-8");
        const pkgJson = JSON.parse(raw) as Record<string, unknown>;
        expect(pkgJson.dependencies).toBeDefined();
        const dependencies = pkgJson.dependencies as Record<string, string>;
        expect(dependencies[dep]).toBe("workspace:*");
      });
    }
  });
}
