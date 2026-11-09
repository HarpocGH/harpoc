import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_CA_DAYS,
  DEFAULT_PROXY_PORT,
  DEFAULT_UNCONSTRAINED_CA_DAYS,
  MAX_CA_DAYS,
  MAX_PORT,
  MAX_RENEW_BEFORE_DAYS,
  MAX_UNCONSTRAINED_CA_DAYS,
  MIN_CA_DAYS,
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

  it("names the egress proxy's default port (DB-14)", () => {
    expect(DEFAULT_PROXY_PORT).toBe(3128);
  });

  it("names the Harpoc CA's lifetime bounds: 1–3650 days, 3650 by default; the fallback 1–30, 7 by default (B8)", () => {
    expect(MIN_CA_DAYS).toBe(1);
    expect(MAX_CA_DAYS).toBe(3650);
    expect(DEFAULT_CA_DAYS).toBe(3650);
    expect(DEFAULT_UNCONSTRAINED_CA_DAYS).toBe(7);
    expect(MAX_UNCONSTRAINED_CA_DAYS).toBe(30);
  });

  it("no command declares a bound of its own (CM-5 tripwire)", () => {
    const declaration =
      /^\s*(?:export )?const (?:MIN|MAX|DEFAULT)_(?:PORT|RENEW_BEFORE_DAYS|CA_DAYS|UNCONSTRAINED_CA_DAYS)\b/m;
    const offenders = collectSources(new URL("../commands/", import.meta.url))
      .filter(({ url }) => declaration.test(readFileSync(url, "utf8")))
      .map(({ path }) => path)
      .sort();
    expect(offenders).toEqual([]);
  });
});
