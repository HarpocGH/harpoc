import { describe, expect, it } from "vitest";
import { redactSpans, redactValues } from "./output-sanitizer.js";
import { RESIDUALS, TABLE, permutations, randomCases } from "./__fixtures__/redact-cases.js";
import {
  referenceFold,
  referenceMatchAt,
  referenceNeedles,
  referencePositions,
} from "./__fixtures__/redact-reference.js";

const R = "[REDACTED]";
const MASK = "";
const MODEL_LIMIT = 6000;
const CASES = [...TABLE, ...randomCases(20261126, 4000)];

interface Applied {
  out: string;
  removed: Uint8Array;
  origins: number[];
}

/** The applications `redactValues` makes, one `redactSpans` each, with the positions of `text` they removed. */
function applications(text: string, values: readonly string[]): Applied {
  const final = redactValues(text, values);
  const removed = new Uint8Array(text.length);
  let origins = Array.from({ length: text.length }, (_, i) => i);
  let current = text;
  for (let round = 0; round <= values.length + 1 && current !== final; round++) {
    const spans = redactSpans(current, values);
    if (spans.length === 0) break;
    const next: number[] = [];
    let out = "";
    let cursor = 0;
    for (let i = 0; i < spans.length; i += 2) {
      const start = spans[i] as number;
      const end = spans[i + 1] as number;
      for (let p = cursor; p < start; p++) next.push(origins[p] as number);
      for (let p = start; p < end; p++) {
        const origin = origins[p] as number;
        if (origin >= 0) removed[origin] = 1;
      }
      for (let k = 0; k < R.length; k++) next.push(-1);
      out += current.slice(cursor, start) + R;
      cursor = end;
    }
    for (let p = cursor; p < current.length; p++) next.push(origins[p] as number);
    current = out + current.slice(cursor);
    origins = next;
  }
  if (current !== final) throw new Error("the applications do not reach redactValues' output");
  return { out: current, removed, origins };
}

function inputMarkers(text: string): Uint8Array {
  const inside = new Uint8Array(text.length);
  for (let i = text.indexOf(R); i !== -1; i = text.indexOf(R, i + R.length)) {
    inside.fill(1, i, i + R.length);
  }
  return inside;
}

const label = (text: string, values: readonly string[]): string => JSON.stringify({ text, values });

describe("redactValues against the old fold", () => {
  it("the table", () => {
    for (const row of TABLE) expect(redactValues(row.text, row.values), row.name).toBe(row.expect);
    for (const row of RESIDUALS) {
      expect(redactValues(row.text, row.values), row.name).toBe(row.expect);
    }
  });

  it("no form of the text that the old function removes survives", () => {
    const violations: string[] = [];
    let checked = 0;
    let unmodelled = 0;
    for (const { text, values } of CASES) {
      const applied = applications(text, values);
      const inMarker = inputMarkers(text);
      for (const order of permutations(values)) {
        const old = referenceFold(text, order);
        if (old.length > MODEL_LIMIT) continue;
        const model = referencePositions(text, order);
        if (model.output !== old) {
          unmodelled++;
          continue;
        }
        checked++;
        for (const p of model.removed) {
          if (model.throughMarker.has(p) || model.throughReserialization.has(p)) continue;
          if (inMarker[p] === 1 || applied.removed[p] === 1) continue;
          violations.push(`${label(text, order)} at ${p}`);
        }
      }
    }

    expect(unmodelled).toBe(0);
    expect(checked).toBeGreaterThan(10_000);
    expect(violations.length, violations.slice(0, 5).join("\n")).toBe(0);
  }, 120_000);

  it("no marker is cut, no occurrence stays", () => {
    const cut: string[] = [];
    const left: string[] = [];
    for (const { text, values } of CASES) {
      const { out, removed, origins } = applications(text, values);

      let run = 0;
      for (let i = 0; i <= origins.length; i++) {
        if (origins[i] === -1) {
          run++;
          continue;
        }
        if (run % R.length !== 0) cut.push(label(text, values));
        run = 0;
      }
      const written = origins.filter((origin) => origin === -1).length / R.length;
      if (out.split(R).length - 1 < written) cut.push(label(text, values));
      for (let i = text.indexOf(R); i !== -1; i = text.indexOf(R, i + R.length)) {
        const covered = removed.subarray(i, i + R.length).reduce((a, b) => a + b, 0);
        if (covered !== 0 && covered !== R.length) cut.push(label(text, values));
      }

      const tolerant = text.includes("\\");
      for (const needle of values.flatMap(referenceNeedles)) {
        for (let i = 0; i < text.length; i++) {
          const ends = [
            text.startsWith(needle, i) ? i + needle.length : -1,
            tolerant ? referenceMatchAt(text, i, needle) : -1,
          ];
          for (const end of ends) {
            if (end === -1) continue;
            const marker = text.lastIndexOf(R, i);
            if (marker !== -1 && marker + R.length >= end) continue;
            for (let p = i; p < end; p++) {
              if (removed[p] !== 1) left.push(`${label(text, values)} at ${p}`);
            }
          }
        }
      }
    }

    expect(cut.length, cut.slice(0, 5).join("\n")).toBe(0);
    expect(left.length, left.slice(0, 5).join("\n")).toBe(0);
  });

  it("the old function changes nothing in the new output", () => {
    const changed: string[] = [];
    for (const { text, values } of CASES) {
      const masked = redactValues(text, values).split(R).join(MASK);
      for (const order of permutations(values)) {
        if (referenceFold(masked, order) !== masked) changed.push(label(text, order));
      }
    }

    expect(changed.length, changed.slice(0, 5).join("\n")).toBe(0);
  });
});
