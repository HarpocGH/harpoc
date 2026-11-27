// packages/core/src/injection/escape-tolerant.ts

/**
 * Find a needle in text that may carry it under ANY valid JSON string
 * escaping, not just the one V8 emits.
 *
 * `JSON.stringify(s).slice(1, -1)` reproduces exactly one convention: V8's,
 * which does not escape `/`. PHP's `json_encode` escapes it by default, Python's
 * `json.dumps` emits `\uXXXX` for every non-ASCII character under the default
 * `ensure_ascii=True`, and Go's encoder escapes `<`, `>` and `&`. A credential
 * reflected by such a backend does not occur as the V8 needle and passed through
 * untouched — one `JSON.parse` from the model (review 2026-08-14, F1).
 *
 * So this matches the CLASS: each needle character may appear literally, as a
 * simple escape, or as `\uXXXX` in either hex case, and the conventions may be
 * mixed within one value.
 *
 * Matching is biased toward over-redaction, not toward preserving structure:
 * every start is tried, a start inside an unrelated `\uXXXX` (or other) escape
 * included, so a match may begin inside an escape and the surrounding JSON can
 * be left malformed once it is redacted. That is accepted on purpose — skipping
 * whole escape units would also skip a needle that appears literally in non-JSON
 * output (process stdout/stderr and MCP results are scanned too, where
 * `\uXXXX`-shaped text is just characters), turning a would-be match into a
 * miss. A missed redaction — the credential reaching the model — is the one
 * failure this best-effort layer must not have; a malformed downstream JSON
 * body is not (review 2026-08-14, fix round 1).
 *
 * Residual, deliberate: where a text position holds `\` and the following
 * character forms a valid escape, the escape reading is taken without
 * backtracking. A needle containing a literal backslash adjacent to text that
 * admits both readings can therefore be missed. Backtracking would make this
 * exponential, and this is a best-effort layer atop structural opacity — not the
 * property the vault's guarantee rests on.
 *
 * Residual, deliberate: this matches only one escape layer of the text it is
 * given, and does not itself parse or descend into JSON structure.
 * `redactValues` (`output-sanitizer.ts`) runs it on every string value it
 * decodes from a JSON document, to at most `MAX_JSON_PARSES` (4) levels of parse
 * depth. Four levels is enough to reach a credential in a document wrapped
 * inside as many as four further envelopes (five JSON documents nested in
 * total). A credential wrapped a fifth envelope deeper — six documents in total
 * — is still not matched, nor is one inside a body over the descent's size
 * guard. That is characterized, not claimed blocked — the same residual family
 * as the partial-echo and chunking classes — and the e2e harness deliberately
 * parses to a greater depth still (six `JSON.parse` calls, `MAX_PARSE_DEPTH` in
 * `packages/e2e/src/assert/scan.ts`), so the measurement can still observe the
 * band the vault does not cover (review 2026-08-14, F1 whole-branch follow-up;
 * nested-JSON redaction plan, decision D2).
 */

/** Spans of a text as `[start, end, start, end, …]`, each `[start, end)`, ascending by start. */
export type Spans = number[];

const SIMPLE_ESCAPES: Record<string, string> = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
};

function isHex(ch: string | undefined): boolean {
  return ch !== undefined && /^[0-9a-fA-F]$/.test(ch);
}

/**
 * How many characters of `text` at `at` represent `wanted`, or 0 for no match.
 * `wanted` is a single UTF-16 code unit.
 */
function consume(text: string, at: number, wanted: string): number {
  if (at >= text.length) return 0;

  if (text[at] === "\\") {
    const next = text[at + 1];
    if (next !== undefined) {
      const simple = SIMPLE_ESCAPES[next];
      if (simple !== undefined) return simple === wanted ? 2 : 0;
      if (
        next === "u" &&
        isHex(text[at + 2]) &&
        isHex(text[at + 3]) &&
        isHex(text[at + 4]) &&
        isHex(text[at + 5])
      ) {
        const code = Number.parseInt(text.slice(at + 2, at + 6), 16);
        return String.fromCharCode(code) === wanted ? 6 : 0;
      }
    }
  }

  return text[at] === wanted ? 1 : 0;
}

/** The end index of a full needle match starting at `start`, or -1. */
function matchAt(text: string, start: number, needle: string): number {
  let at = start;
  for (let i = 0; i < needle.length; i++) {
    const step = consume(text, at, needle[i] as string);
    if (step === 0) return -1;
    at += step;
  }
  return at;
}

/**
 * Appends to `out`, and returns it, every match of `needle` in `text` whose
 * characters hold a backslash, overlapping ones included. A match without a
 * backslash is a literal occurrence of the needle, which the literal scan
 * reports; and every needle character before the first backslash of a match
 * consumed one character, so only the `needle.length` starts up to each
 * backslash are tried.
 */
export function findEscapeTolerant(text: string, needle: string, out: Spans = []): Spans {
  if (text.length === 0 || needle.length === 0) return out;

  const first = needle[0] as string;
  let from = 0;
  for (let b = text.indexOf("\\"); b !== -1; b = text.indexOf("\\", b + 1)) {
    for (let i = Math.max(from, b - needle.length + 1); i <= b; i++) {
      if (i === b || text[i] === first) {
        const end = matchAt(text, i, needle);
        if (end !== -1) out.push(i, end);
      }
    }
    from = b + 1;
  }
  return out;
}
