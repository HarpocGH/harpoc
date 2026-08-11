import { readFileSync } from "node:fs";

export interface Expectation {
  scenario: string;
  context: string;
  surface: string;
  arm: "baseline" | "harpoc";
  expected: string;
}

export type ExpectationKey = Omit<Expectation, "expected">;

function keyOf(k: ExpectationKey): string {
  return `${k.scenario}|${k.context}|${k.surface}|${k.arm}`;
}

export function loadExpectations(filePath: string): Expectation[] {
  const parsed: unknown = JSON.parse(readFileSync(filePath, "utf8"));
  if (!Array.isArray(parsed)) {
    throw new Error(`malformed pre-registration: ${filePath} is not an array`);
  }

  return parsed.map((row, i) => {
    const r = row as Partial<Expectation>;
    const ok =
      typeof r.scenario === "string" &&
      typeof r.context === "string" &&
      typeof r.surface === "string" &&
      (r.arm === "baseline" || r.arm === "harpoc") &&
      typeof r.expected === "string";
    if (!ok) throw new Error(`malformed pre-registration row at index ${i} in ${filePath}`);
    return r as Expectation;
  });
}

/**
 * Look up the outcome fixed before the run. An unregistered combination is an
 * error, not a default — that is what stops an outcome from being invented
 * after it was observed.
 */
export function expectationFor(expectations: Expectation[], key: ExpectationKey): string {
  const wanted = keyOf(key);
  const found = expectations.find((e) => keyOf(e) === wanted);
  if (!found) throw new Error(`outcome is not pre-registered: ${wanted}`);
  return found.expected;
}
