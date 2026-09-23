import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  MAX_PORT,
  MAX_RENEW_BEFORE_DAYS,
  MIN_PORT,
  MIN_RENEW_BEFORE_DAYS,
} from "./option-bounds.js";

function collectSources(dir: URL, prefix = ""): { path: string; url: URL }[] {
  const found: { path: string; url: URL }[] = [];
  for (const entry of readdirSync(fileURLToPath(dir), { withFileTypes: true })) {
    if (entry.isDirectory()) {
      found.push(...collectSources(new URL(`${entry.name}/`, dir), `${prefix}${entry.name}/`));
    } else if (
      entry.name.endsWith(".ts") &&
      !entry.name.endsWith(".test.ts") &&
      !entry.name.endsWith(".spec.ts") &&
      !entry.name.endsWith(".d.ts")
    ) {
      found.push({ path: `${prefix}${entry.name}`, url: new URL(entry.name, dir) });
    }
  }
  return found;
}

describe("option-bounds", () => {
  it("names the four bounds", () => {
    expect(MIN_PORT).toBe(1);
    expect(MAX_PORT).toBe(65535);
    expect(MIN_RENEW_BEFORE_DAYS).toBe(1);
    expect(MAX_RENEW_BEFORE_DAYS).toBe(365);
  });

  it("no command declares a bound of its own (CM-5 tripwire)", () => {
    const declaration = /^\s*(?:export )?const (?:MIN|MAX)_(?:PORT|RENEW_BEFORE_DAYS)\b/m;
    const offenders = collectSources(new URL("../commands/", import.meta.url))
      .filter(({ url }) => declaration.test(readFileSync(url, "utf8")))
      .map(({ path }) => path)
      .sort();
    expect(offenders).toEqual([]);
  });
});
