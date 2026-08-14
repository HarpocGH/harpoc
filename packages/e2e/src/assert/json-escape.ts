/**
 * Where a value appears in text that may carry it under any valid JSON string
 * escaping.
 *
 * A SEPARATE implementation from the vault's `redactEscapeTolerant`, on purpose
 * (decision D2). The measurement's job is to be able to falsify the product: if
 * the harness scanned with the vault's own matcher, every `BLOCKED` verdict for
 * this class would be true by construction, which is exactly how the V8-only
 * needle survived four reviews. `drift.test.ts` proves the relation that matters
 * — the harness detects a superset of what the vault redacts — and pins the
 * difference, instead of assuming it away by sharing code.
 */
export interface EscapeMatch {
  start: number;
  end: number;
  /** True when at least one character was recovered from an escape sequence. */
  escaped: boolean;
}

const SIMPLE: Record<string, string> = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
};

/** Decode one unit at `at`: the character it yields and how much text it spans. */
function unitAt(text: string, at: number): { ch: string; width: number; escaped: boolean } | null {
  const here = text[at];
  if (here === undefined) return null;
  if (here !== "\\") return { ch: here, width: 1, escaped: false };

  const next = text[at + 1];
  if (next === undefined) return { ch: here, width: 1, escaped: false };

  const simple = SIMPLE[next];
  if (simple !== undefined) return { ch: simple, width: 2, escaped: true };

  if (next === "u") {
    const hex = text.slice(at + 2, at + 6);
    if (/^[0-9a-fA-F]{4}$/.test(hex)) {
      return { ch: String.fromCharCode(Number.parseInt(hex, 16)), width: 6, escaped: true };
    }
  }
  return { ch: here, width: 1, escaped: false };
}

export function findEscapeTolerant(text: string, needle: string): EscapeMatch[] {
  const matches: EscapeMatch[] = [];
  if (text.length === 0 || needle.length === 0) return matches;

  let i = 0;
  while (i < text.length) {
    let at = i;
    let escaped = false;
    let matched = true;

    for (let n = 0; n < needle.length; n++) {
      const unit = unitAt(text, at);
      if (unit === null || unit.ch !== needle[n]) {
        matched = false;
        break;
      }
      if (unit.escaped) escaped = true;
      at += unit.width;
    }

    if (matched) {
      matches.push({ start: i, end: at, escaped });
      i = at;
    } else {
      i++;
    }
  }

  return matches;
}
