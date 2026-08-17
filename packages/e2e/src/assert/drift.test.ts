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

  it("no convention degenerates to the identity over the corpus", () => {
    // If an encoder silently became the identity, its bodies would carry the
    // credential literally — vault and harness would both go green through the
    // LITERAL path, and the two tests below would keep passing while no longer
    // exercising that escaping direction at all (review 2026-08-14, Task 5
    // deferred minor: previously verified by hand for v8 and php_ensure_ascii,
    // pinned by nothing).
    const degenerate = CONVENTIONS.filter(([, encode]) =>
      SECRETS.every((s) => encode(s) === s),
    ).map(([name]) => name);
    expect(degenerate).toEqual([]);
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

  it("nesting: the vault redacts to its cap, the harness sees two levels further", () => {
    // `redactSecretEncodings` (vault, output-sanitizer.ts) structurally
    // re-parses a string leaf as JSON up to `MAX_JSON_PARSES` (4) levels deep;
    // `scan` (harness, this file's sibling scan.ts) does the same up to
    // `MAX_PARSE_DEPTH` (6) — deliberately deeper, per decision D2, so the
    // measurement can still falsify a leak the vault ships. Measured directly
    // (Task 4, nested-json-redaction plan): with `wrap(inner) =
    // JSON.stringify({ data: inner })` and `t1 = JSON.stringify({ echo:
    // secret })`, the vault redacts through five wraps (t5) and is blind from
    // six (t6) on; the harness, at its raised budget, detects through seven
    // (t7) and is blind from eight (t8) on. These numbers match the plan's
    // own arithmetic exactly.
    //
    // Pinned in BOTH directions: if the vault's cap changes, the first block
    // goes red; if the harness's cap DROPS, the second and third do; if it
    // RISES, the t8 blind assertion does — t8 is the only block that catches
    // an upward drift, load-bearing rather than redundant with t6/t7
    // (2026-08-15 deferred minor: an earlier version of this comment omitted
    // it). Neither cap may drift silently.
    const secret = 'p4-rc-json:tok"en-x';
    const wrap = (inner: string): string => JSON.stringify({ data: inner });
    const t1 = JSON.stringify({ echo: secret });

    const t5 = wrap(wrap(wrap(wrap(t1))));
    expect(redactSecretEncodings(t5, secret)).not.toBe(t5); // vault: redacted
    expect(scan(secret, { body: t5 }).length).toBeGreaterThan(0); // harness: detected

    const t6 = wrap(t5);
    expect(redactSecretEncodings(t6, secret)).toBe(t6); // vault: BLIND past its cap
    expect(scan(secret, { body: t6 }).length).toBeGreaterThan(0); // harness: still sees

    const t7 = wrap(t6);
    expect(redactSecretEncodings(t7, secret)).toBe(t7); // vault: blind
    expect(scan(secret, { body: t7 }).length).toBeGreaterThan(0); // harness: still sees

    const t8 = wrap(t7);
    expect(redactSecretEncodings(t8, secret)).toBe(t8); // vault: blind
    expect(scan(secret, { body: t8 })).toEqual([]); // harness: its own cap, stated
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
