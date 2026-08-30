import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { describeBuildOutput, getPkgRoot } from "@harpoc/test-utils";

const pkgRoot = getPkgRoot(import.meta.url);
const monorepoRoot = resolve(pkgRoot, "..", "..");
const sharedDistDir = resolve(monorepoRoot, "packages", "shared", "dist");

const PACKAGES = ["shared", "core", "mcp-server", "rest-api", "sdk", "cli"] as const;

describe("shared", () => {
  describeBuildOutput(sharedDistDir);
});

describe("monorepo structure", () => {
  for (const pkg of PACKAGES) {
    describe(pkg, () => {
      let pkgJson: Record<string, unknown>;

      beforeAll(() => {
        const raw = readFileSync(resolve(monorepoRoot, "packages", pkg, "package.json"), "utf-8");
        pkgJson = JSON.parse(raw) as Record<string, unknown>;
      });

      it('has "type": "module"', () => {
        expect(pkgJson.type).toBe("module");
      });

      it("has correct exports field", () => {
        expect(pkgJson.exports).toBeDefined();
        const exports = pkgJson.exports as Record<string, Record<string, string>>;
        expect(exports["."]).toBeDefined();
        const entry = exports["."] as Record<string, string>;
        expect(entry.types).toBe("./dist/index.d.ts");
        expect(entry.import).toBe("./dist/index.js");
      });

      it('has "build" script', () => {
        expect(pkgJson.scripts).toBeDefined();
        const scripts = pkgJson.scripts as Record<string, string>;
        expect(scripts.build).toBeDefined();
      });

      it('has "test" script', () => {
        expect(pkgJson.scripts).toBeDefined();
        const scripts = pkgJson.scripts as Record<string, string>;
        expect(scripts.test).toBeDefined();
      });
    });
  }
});

describe("bin entries", () => {
  it('cli declares "harpoc" bin', () => {
    const raw = readFileSync(resolve(monorepoRoot, "packages", "cli", "package.json"), "utf-8");
    const pkgJson = JSON.parse(raw) as Record<string, unknown>;
    expect(pkgJson.bin).toBeDefined();
    const bin = pkgJson.bin as Record<string, string>;
    expect(bin.harpoc).toBe("./dist/index.js");
  });

  it('mcp-server declares "harpoc-mcp" bin', () => {
    const raw = readFileSync(
      resolve(monorepoRoot, "packages", "mcp-server", "package.json"),
      "utf-8",
    );
    const pkgJson = JSON.parse(raw) as Record<string, unknown>;
    expect(pkgJson.bin).toBeDefined();
    const bin = pkgJson.bin as Record<string, string>;
    expect(bin["harpoc-mcp"]).toBe("./dist/index.js");
  });
});
