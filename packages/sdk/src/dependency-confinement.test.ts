import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { describeRuntimeDependencyConfinement } from "../../shared/src/scaffold-helpers.js";

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const distDir = resolve(pkgRoot, "dist");

/**
 * §5.2 "dependency-light" made true beyond the SDK's own (empty) third-party
 * dependency list: @harpoc/core is compile-time only (type imports, erased on
 * build) and an *optional peer* — a REST-mode embedding pulls in neither core
 * nor its native dependency graph (argon2, better-sqlite3, pg, mysql2, the
 * MCP SDK). Direct mode requires the host to construct a VaultEngine itself,
 * so that host already depends on core in its own right.
 */
describe("sdk", () => {
  describe("core stays compile-time only", () => {
    const pkgJson = JSON.parse(readFileSync(resolve(pkgRoot, "package.json"), "utf-8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
      peerDependenciesMeta?: Record<string, { optional?: boolean }>;
    };

    it("does not declare @harpoc/core as a runtime dependency", () => {
      expect(pkgJson.dependencies?.["@harpoc/core"]).toBeUndefined();
    });

    it("declares @harpoc/core as an optional peer dependency", () => {
      expect(pkgJson.peerDependencies?.["@harpoc/core"]).toBeDefined();
      expect(pkgJson.peerDependenciesMeta?.["@harpoc/core"]?.optional).toBe(true);
    });

    it("keeps @harpoc/core as a workspace devDependency for typechecking", () => {
      expect(pkgJson.devDependencies?.["@harpoc/core"]).toBe("workspace:*");
    });

    it("built output never references @harpoc/core (type imports must erase)", () => {
      const jsFiles = readdirSync(distDir).filter((file) => file.endsWith(".js"));
      expect(jsFiles.length).toBeGreaterThan(0);
      for (const file of jsFiles) {
        expect(readFileSync(resolve(distDir, file), "utf-8")).not.toContain("@harpoc/core");
      }
    });
  });

  /**
   * D4: the OAuth and certificate peers follow @harpoc/core — optional peers,
   * loaded by `import()` only when an OAuth/cert method is actually called, so
   * a REST-mode (or plain secrets) embedding resolves neither. Their specifiers
   * *do* appear as strings in dist (that is what a dynamic import compiles to),
   * so only the resolve-hook tripwire below can pin this — deliberately no
   * string-absence assertion for these two.
   */
  describe("the OAuth and certificate peers stay lazy", () => {
    const pkgJson = JSON.parse(readFileSync(resolve(pkgRoot, "package.json"), "utf-8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
      peerDependenciesMeta?: Record<string, { optional?: boolean }>;
    };

    for (const peer of ["@harpoc/oauth-proxy", "@harpoc/cert-manager"]) {
      it(`declares ${peer} as an optional peer, never a runtime dependency`, () => {
        expect(pkgJson.dependencies?.[peer]).toBeUndefined();
        expect(pkgJson.peerDependencies?.[peer]).toBeDefined();
        expect(pkgJson.peerDependenciesMeta?.[peer]?.optional).toBe(true);
        expect(pkgJson.devDependencies?.[peer]).toBe("workspace:*");
      });
    }
  });

  describeRuntimeDependencyConfinement({
    entryUrl: pathToFileURL(resolve(distDir, "index.js")).href,
    cwd: pkgRoot,
    forbidden: [
      "@harpoc/core",
      "@harpoc/oauth-proxy",
      "@harpoc/cert-manager",
      "@modelcontextprotocol",
      "argon2",
      "better-sqlite3",
      "pg",
      "mysql2",
    ],
    control: "@harpoc/core",
  });
});
