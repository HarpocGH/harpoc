import { describe, it, expect } from "vitest";
import { redactSecretEncodings } from "@harpoc/core";
import { scan } from "./scan.js";

/**
 * The vault redacts; the harness detects. Decision D2 keeps the two
 * implementations separate so the measurement can falsify the product — but
 * separate implementations drift, and drift in ONE direction is fatal: a form
 * the vault redacts that the harness cannot see means every `BLOCKED` verdict
 * about that form is unfalsifiable.
 *
 * So the invariant is a superset relation, not equality, and the difference is
 * pinned rather than forbidden.
 *
 * `@harpoc/core` resolves to its BUILT `dist/`, not its TypeScript source:
 * `run-e2e.mjs` has no build step of its own, and `turbo.json` wires `build`
 * as a dependency of `test` but NOT of `test:e2e`. Editing
 * `output-sanitizer.ts`/`escape-tolerant.ts` and running this file locally
 * without first `pnpm --filter @harpoc/core build` silently measures the OLD
 * sanitizer and can pass or fail for the wrong reason. CI is safe — the e2e
 * workflow builds before it tests.
 */

const SECRETS = [
  "plain-ascii-token",
  "sk-live/abc+def", // solidus and plus: PHP escapes one, base64url the other
  'quote"and\\backslash', // the V8 convention's own case
  "sk-tür-ünïcode", // ensure_ascii territory
  "emoji-\u{1F600}-tail", // surrogate pair
];

/** `\uXXXX`-escape every non-ASCII character, as Python's ensure_ascii=True does. */
function escapeNonAscii(s: string, upperHex: boolean): string {
  let out = "";
  // Iterate by CODE UNIT: a non-BMP character is a surrogate pair, and each half
  // is escaped separately by every encoder that does this.
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code > 127) {
      const hex = code.toString(16).padStart(4, "0");
      out += `\\u${upperHex ? hex.toUpperCase() : hex}`;
    } else {
      out += JSON.stringify(s[i]).slice(1, -1);
    }
  }
  return out;
}

/** Escaping conventions a real backend emits. */
const CONVENTIONS: Array<[string, (s: string) => string]> = [
  ["v8", (s) => JSON.stringify(s).slice(1, -1)],
  ["php", (s) => JSON.stringify(s).slice(1, -1).replace(/\//g, "\\/")],
  ["ensure_ascii", (s) => escapeNonAscii(s, false)],
  ["ensure_ascii_upper", (s) => escapeNonAscii(s, true)],
  ["php_ensure_ascii", (s) => escapeNonAscii(s, false).replace(/\//g, "\\/")],
];

describe("product/harness drift (decision D2)", () => {
  it("the corpus actually exercises each convention", () => {
    expect(CONVENTIONS.find(([n]) => n === "php")?.[1]("sk-live/abc+def")).toContain("\\/");
    expect(CONVENTIONS.find(([n]) => n === "ensure_ascii")?.[1]("sk-tür")).toContain("\\u00fc");
    expect(CONVENTIONS.find(([n]) => n === "ensure_ascii_upper")?.[1]("sk-tür")).toContain(
      "\\u00FC",
    );
    expect(escapeNonAscii("emoji-\u{1F600}-tail", false)).toContain("\\ud83d\\ude00");
  });

  it("detects every form the vault redacts", () => {
    const blindSpots: string[] = [];
    for (const secret of SECRETS) {
      for (const [name, encode] of CONVENTIONS) {
        const body = `{"echo":"${encode(secret)}"}`;
        const vaultRedacted = redactSecretEncodings(body, secret) !== body;
        const harnessSaw = scan(secret, { body }).length > 0;
        if (vaultRedacted && !harnessSaw) blindSpots.push(`${secret} / ${name}`);
      }
    }
    // A non-empty list means the harness cannot falsify a claim the vault makes.
    expect(blindSpots).toEqual([]);
  });

  it("pins the residual — forms the harness sees that the vault does not redact", () => {
    const residual: string[] = [];
    for (const secret of SECRETS) {
      for (const [name, encode] of CONVENTIONS) {
        const body = `{"echo":"${encode(secret)}"}`;
        const vaultRedacted = redactSecretEncodings(body, secret) !== body;
        const harnessSaw = scan(secret, { body }).length > 0;
        if (harnessSaw && !vaultRedacted) residual.push(`${secret} / ${name}`);
      }
    }
    // Empty after this tranche. A new entry is a real finding: the harness can
    // see a leak the vault ships. It must be acknowledged in a diff, never
    // discovered in a Chapter 6 table.
    expect(residual).toEqual([]);
  });

  it("known shared blind spot: nesting depth — pinned directly, not via blindSpots/residual", () => {
    // `blindSpots` (above) and `residual` (above) are both defined over an
    // XOR: `vaultRedacted !== harnessSaw`. A case where BOTH sides are blind
    // to the credential at the envelope level satisfies neither loop's `if`
    // and is therefore invisible to this file BY CONSTRUCTION unless pinned
    // as its own case, which is what this test is.
    //
    // Both `redactSecretEncodings` (vault, escape-tolerant.ts) and
    // `findEscapeTolerant` (harness, json-escape.ts) decode exactly ONE escape
    // layer of the text they scan. A JSON document embedded as a STRING FIELD
    // of another JSON document — a routine webhook `data`/`payload` wrapper —
    // puts the credential at two escape layers, past what either matcher's
    // grammar reaches. The harness's `scan()` still reports this credential as
    // seen, but not through `findEscapeTolerant` reading two layers at once:
    // it structurally re-parses a string leaf as JSON when the flat test
    // misses (see scan.ts, "F4"), and at that shallower depth only ONE escape
    // layer remains, which its one-layer matcher then reads directly. So the
    // detection below is not evidence the two matchers still agree — nesting
    // is a STRUCTURAL limit (does the caller re-parse JSON documents nested
    // inside JSON documents?), not a GRAMMATICAL one (does the matcher
    // recognize an escape sequence?), and the vault's flat-text scan does not
    // do the former at all.
    //
    // Pinned in BOTH directions on purpose: if a future change makes the vault
    // redact this too, the first assertion goes red and must be updated
    // rather than silently starting to pass; if a future change makes the
    // harness stop seeing it, the second assertion goes red the same way.
    const secret = 'p4-rc-json:tok"en-x';
    const inner = JSON.stringify({ echo: secret });
    const outer = JSON.stringify({ data: inner });

    expect(redactSecretEncodings(outer, secret)).toBe(outer); // vault: NOT redacted
    expect(scan(secret, { body: outer }).length).toBeGreaterThan(0); // harness: detected
  });

  it("negative control: both are blind to a transform outside the class", () => {
    // Base64 OF the escaped form — a second encoding layer neither side claims
    // to cover. Characterized in the evaluation, not claimed to be blocked.
    const secret = "residual-demo-token";
    const body = Buffer.from(JSON.stringify({ echo: secret }), "utf8").toString("base64url");
    expect(redactSecretEncodings(body, secret)).toBe(body);
    expect(scan(secret, { body })).toEqual([]);
  });
});
