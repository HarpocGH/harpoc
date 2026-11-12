import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

function collectSources(dir: URL, prefix: string): { path: string; url: URL }[] {
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

// A source-text check: an Error subclass, an alias bound to Error and the other built-in error constructors are out of its reach.
const RAW_THROW = /\b(?:new\s+)?Error\s*\(/g;

const ALLOWED: Record<string, { count: number; reason: string }> = {
  "utils/prompt.ts": {
    count: 1,
    reason: "the hidden prompt's Ctrl+C is a cancellation, not an input refusal (C-8)",
  },
  "commands/cert/import.ts": {
    count: 1,
    reason:
      'readPemFile\'s internal "not a file" throw, caught and replaced by its INVALID_INPUT refusal two lines on',
  },
  "utils/secret-value.ts": {
    count: 1,
    reason:
      'readSecretValueFromFile\'s internal "not a file" throw, caught and replaced by its INVALID_INPUT refusal two lines on',
  },
};

describe("the CLI's input refusals are VaultError.invalidInput (T4 tripwire)", () => {
  it("no command or utility throws a raw Error outside the reasoned allowlist, per-file counts pinned", () => {
    const sources = [
      ...collectSources(new URL("../commands/", import.meta.url), "commands/"),
      ...collectSources(new URL("./", import.meta.url), "utils/"),
    ];
    const rawThrows = Object.fromEntries(
      sources
        .map(
          ({ path, url }) =>
            [path, (readFileSync(url, "utf8").match(RAW_THROW) ?? []).length] as const,
        )
        .filter(([, found]) => found > 0),
    );
    const allowed = Object.fromEntries(
      Object.entries(ALLOWED).map(([path, { count }]) => [path, count]),
    );
    expect(rawThrows).toEqual(allowed);
  });
});
