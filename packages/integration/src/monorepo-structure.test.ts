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

// RED before turbo.json named them: turbo 2 runs tasks in strict env mode, so
// the two variables ci.yml sets for the test step — the required-tier gate
// (review T3, 2026-07-16) and the provisioned macOS keychain — never reached a
// vitest worker under `pnpm test`; the gate was inert and the keychain suites
// ran against the runner's login keychain (found 2026-09-08, D5).
describe("turbo env pass-through (D5, 2026-09-08; the series file 2026-09-09)", () => {
  it("the test task names the three variables ci.yml sets for it", () => {
    const raw = readFileSync(resolve(monorepoRoot, "turbo.json"), "utf-8");
    const turbo = JSON.parse(raw) as {
      tasks: Record<string, { env?: string[] }>;
    };
    expect(turbo.tasks["test"]?.env).toEqual([
      "HARPOC_REQUIRE_PLATFORM_TESTS",
      "HARPOC_TEST_KEYCHAIN",
      "HARPOC_SERIES_FILE",
    ]);
  });
});
