import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const PKG_ROOT = join(import.meta.dirname, "..");
const DIST_ROOT = join(PKG_ROOT, "dist");

describe("package scaffold", () => {
  it("has package.json with correct name", async () => {
    const pkg = await import("../package.json", { with: { type: "json" } });
    expect(pkg.default.name).toBe("@harpoc/oauth-proxy");
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

  it("dist directory exists after build", () => {
    expect(existsSync(DIST_ROOT)).toBe(true);
  });

  it("dist/index.js exists after build", () => {
    expect(existsSync(join(DIST_ROOT, "index.js"))).toBe(true);
  });

  it("dist/index.d.ts exists after build", () => {
    expect(existsSync(join(DIST_ROOT, "index.d.ts"))).toBe(true);
  });
});
