import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Not `new URL(".", import.meta.url)`: Vite rewrites that pattern into its
// asset-URL form, which resolves against the dev-server origin
// (http://localhost:3000/ui/src) rather than the file system.
const SRC = dirname(fileURLToPath(import.meta.url));

/**
 * The Vite entry point sits outside `src/`, and it is exactly the file an
 * external CDN `<script>` or stylesheet would land in — so the sweep reaches
 * one level up for it rather than leaving the `.html` branch matching nothing.
 */
const ENTRY_HTML = join(dirname(SRC), "index.html");

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

const sources = [
  ...walk(SRC).filter(
    (f) => /\.(ts|tsx|css|html)$/.test(f) && !f.endsWith(".test.ts") && !f.endsWith(".test.tsx"),
  ),
  ENTRY_HTML,
];

describe("web-ui posture", () => {
  it("scans a non-empty source set, entry HTML included", () => {
    // Without this the three tripwires below pass vacuously if the filter ever
    // stops matching (renamed extensions, moved sources).
    expect(sources.length).toBeGreaterThan(0);
    // And this keeps the entry-point arm honest: a renamed or moved
    // `index.html` throws here instead of quietly dropping out of the sweep.
    expect(readFileSync(ENTRY_HTML, "utf-8")).toContain("<script");
  });

  it("never touches localStorage (token lives in sessionStorage only)", () => {
    for (const file of sources) {
      expect(readFileSync(file, "utf-8"), file).not.toContain("localStorage");
    }
  });

  it("never requests a secret value route", () => {
    for (const file of sources) {
      expect(readFileSync(file, "utf-8"), file).not.toContain("/value");
    }
  });

  it("references no external origin (CSP 'self' must hold)", () => {
    for (const file of sources) {
      const text = readFileSync(file, "utf-8");
      expect(/https?:\/\/(?!github\.com|127\.0\.0\.1|localhost)/.test(text), file).toBe(false);
    }
  });
});
