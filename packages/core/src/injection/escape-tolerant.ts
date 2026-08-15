// packages/core/src/injection/escape-tolerant.ts

/**
 * Redact a needle from text that may carry it under ANY valid JSON string
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
 * Matching is biased toward over-redaction, not toward preserving structure: a
 * failed match attempt advances the scan by one character rather than skipping
 * the whole escape unit it began to read, so a match may start inside an
 * unrelated `\uXXXX` (or other) escape and the surrounding JSON can be left
 * malformed. That is accepted on purpose — skipping whole escape units on
 * failure would also skip a needle that appears literally in non-JSON output
 * (this function also sanitizes process stdout/stderr and MCP results, where
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
 * Residual, deliberate: nesting depth is now bounded, not unbounded. This
 * function still matches only one escape layer of the text it is given, and
 * does not itself parse or descend into JSON structure. Since 2026-08-15,
 * `redactSecretEncodings` (`output-sanitizer.ts`) wraps it in a structural
 * pass that parses the surrounding JSON document and descends into string
 * leaves that are themselves JSON, to at most `MAX_JSON_PARSES` (4) levels of
 * parse depth — not four `JSON.parse` calls in total; a document with many
 * sibling leaves at one level costs one parse per leaf, so the actual call
 * count scales with the document's shape, not a fixed budget. Four levels is
 * enough to reach a credential in a document wrapped inside as many as four
 * further envelopes (five JSON documents nested in total). A credential
 * wrapped a fifth envelope deeper — six documents in total — is still not
 * matched, nor is one inside a body over the descent's size guard. That is
 * characterized, not claimed blocked — the same residual family as the
 * partial-echo and chunking classes — and the
 * e2e harness deliberately parses to a greater depth still (six `JSON.parse`
 * calls, `MAX_PARSE_DEPTH` in `packages/e2e/src/assert/scan.ts`), so the
 * measurement can still observe the band the vault does not cover (review
 * 2026-08-14, F1 whole-branch follow-up; nested-JSON redaction plan,
 * decision D2).
 */

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

export function redactEscapeTolerant(text: string, needle: string, replacement: string): string {
  if (text.length === 0 || needle.length === 0) return text;

  const first = needle[0] as string;
  let out = "";
  let cursor = 0;
  let i = 0;

  while (i < text.length) {
    // Cheap prefilter: a match can only begin at a literal first character or at
    // a backslash introducing an escape. Without it this is O(n*m) on every byte.
    if (text[i] === first || text[i] === "\\") {
      const end = matchAt(text, i, needle);
      if (end !== -1) {
        out += text.slice(cursor, i) + replacement;
        cursor = end;
        i = end;
        continue;
      }
    }
    i++;
  }

  return cursor === 0 ? text : out + text.slice(cursor);
}
