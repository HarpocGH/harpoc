import { VaultError } from "@harpoc/shared";
import { redactEscapeTolerant } from "./escape-tolerant.js";

const REDACTION = "[REDACTED]";

/**
 * Assign `value` to `target[key]` as a genuine own data property, even when
 * `key` is `"__proto__"`.
 *
 * A plain `target[key] = value` goes through `[[Set]]`, which for the literal
 * key `"__proto__"` finds the accessor `Object.prototype.__proto__` (Annex B)
 * before it ever finds an own property to shadow — so the assignment attempts
 * to change `target`'s prototype instead of creating a property named
 * `"__proto__"`. `JSON.parse` does not have this problem (object literals it
 * builds use `CreateDataProperty`, which never consults the prototype chain),
 * so a `"__proto__"` key survives parsing and then silently disappears the
 * moment this walker rebuilds the object — worse, if its value happens to be
 * an object, the assignment actually repoints `target`'s prototype.
 * `Object.defineProperty` operates on `target`'s own property table directly
 * ("[[DefineOwnProperty]]") and never triggers an inherited accessor, so it is
 * correct for every key, not just this one.
 */
function setOwnProperty(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * Recursively apply `fn` to every string leaf of a JSON-shaped value, returning
 * a new structure. Used to sanitize structured MCP tool results (content blocks
 * and structuredContent) without corrupting their shape.
 *
 * Object **keys** are mapped as well as values: a downstream MCP server (or a
 * database column alias) chooses its own key names, and a result whose key is
 * the credential reaches the model verbatim if only values are redacted (H3).
 * Redaction can collapse two distinct keys onto one name, so a collision keeps
 * the later entry under a suffixed key rather than silently dropping it.
 */
function mapStringLeavesTracked(
  value: unknown,
  fn: (s: string) => string,
  budget: number,
): { value: unknown; changed: boolean } {
  if (typeof value === "string") {
    const mapped = fn(value);
    if (budget > 0) {
      const trimmed = mapped.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          const parsed: unknown = JSON.parse(trimmed);
          if (typeof parsed === "object" && parsed !== null) {
            const inner = mapStringLeavesTracked(parsed, fn, budget - 1);
            // Re-serialize ONLY on a hit: an untouched document keeps its
            // original bytes, whitespace and key order included.
            if (inner.changed) return { value: JSON.stringify(inner.value), changed: true };
          }
        } catch {
          // Not JSON after all, or the flat pass left it malformed — the
          // mapped form above stands. Fail-safe: never worse than before.
        }
      }
    }
    return { value: mapped, changed: mapped !== value };
  }

  if (Array.isArray(value)) {
    let changed = false;
    const mapped = value.map((item) => {
      const r = mapStringLeavesTracked(item, fn, budget);
      if (r.changed) changed = true;
      return r.value;
    });
    return { value: mapped, changed };
  }

  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    let changed = false;
    for (const [key, val] of Object.entries(value)) {
      let mappedKey = fn(key);
      if (mappedKey !== key) changed = true;
      if (mappedKey !== key && Object.prototype.hasOwnProperty.call(result, mappedKey)) {
        let suffix = 2;
        while (Object.prototype.hasOwnProperty.call(result, `${mappedKey}_${suffix}`)) suffix++;
        mappedKey = `${mappedKey}_${suffix}`;
      }
      const r = mapStringLeavesTracked(val, fn, budget);
      if (r.changed) changed = true;
      setOwnProperty(result, mappedKey, r.value);
    }
    return { value: result, changed };
  }

  return { value, changed: false };
}

/**
 * Public wrapper over {@link mapStringLeavesTracked}, exported from
 * `@harpoc/core`. See that function's doc comment for the walk itself (key
 * redaction, the `__proto__`-safe rebuild, collision handling).
 *
 * `opts.descendJson` bounds how many additional levels of JSON-in-a-string
 * nesting the walk will parse into: a string leaf that trims to `{` or `[`
 * is parsed and walked recursively while the budget is positive, decrementing
 * by one per level, and re-serialized only if something inside it changed.
 * Defaults to `0` — no descent, matching the walker's pre-2026-08-15
 * behaviour: a string leaf is passed to `fn` and returned as-is, even if it
 * is itself a serialized JSON document.
 */
export function mapStringLeaves(
  value: unknown,
  fn: (s: string) => string,
  opts?: { descendJson?: number },
): unknown {
  return mapStringLeavesTracked(value, fn, opts?.descendJson ?? 0).value;
}

/**
 * The credential and the encodings a careless or hostile endpoint may echo it
 * in. Computed once per redaction call and reused at every nesting level —
 * base64 and hex of the same value do not change with depth.
 *
 * The V8 `JSON.stringify(secret).slice(1, -1)` needle is gone: it covered one
 * escaping convention, and the tolerant pass below covers the class it belongs
 * to — including the conventions V8 does not use (review 2026-08-14, F1).
 */
function needlesFor(secret: string): string[] {
  const secretBytes = Buffer.from(secret, "utf8");
  return [
    ...new Set<string>([
      secret,
      secretBytes.toString("base64"),
      secretBytes.toString("base64url"),
      secretBytes.toString("hex"),
      encodeURIComponent(secret),
    ]),
  ].filter((n) => n.length > 0);
}

/**
 * Literal + escape-tolerant redaction of one flat string. This is the pass that
 * shipped before the structural descent; it is unchanged in behaviour and is
 * applied by the descent to every string leaf and key it reaches.
 *
 * `redactEscapeTolerant` can only match a character through an escape
 * sequence, and every escape sequence begins with a backslash, so if `text`
 * contains none at all, any tolerant match is necessarily a purely literal
 * one — which the literal pass below has already made and replaced. The
 * tolerant passes are therefore provably redundant for such text.
 * `[REDACTED]` itself contains no backslash, so replacing a needle with it
 * cannot introduce one partway through the loop — checked once, up front,
 * per call, not per needle (a per-needle check would give back most of the
 * win it buys on non-escaped bodies, the common case on the HTTP response path).
 */
function redactFlat(text: string, needles: string[]): string {
  if (text.length === 0) return text;
  const hasBackslash = text.includes("\\");
  let result = text;
  for (const needle of needles) {
    if (result.includes(needle)) {
      result = result.split(needle).join(REDACTION);
    }
    // hex is case-insensitive on the wire; also strip an uppercase rendering,
    // tolerant of JSON escaping the same as the lowercase form below (a hex
    // credential can be escaped just as any other needle can).
    const upper = needle.toUpperCase();
    const isHexNeedle = upper !== needle && /^[0-9a-fA-F]+$/.test(needle);
    if (isHexNeedle && result.includes(upper)) {
      result = result.split(upper).join(REDACTION);
    }
    if (hasBackslash && isHexNeedle) {
      result = redactEscapeTolerant(result, upper, REDACTION);
    }
    // Then the same needle again, tolerating any JSON string escaping. Run
    // AFTER the literal pass so this change is purely additive: everything the
    // previous implementation removed is already gone by here.
    if (hasBackslash) {
      result = redactEscapeTolerant(result, needle, REDACTION);
    }
  }
  return result;
}

/**
 * Serialization levels the structural pass will parse. A webhook `data` wrapper
 * is one; an MCP result carrying an `HttpResult` carrying a body is two to
 * three. Four is slack, and bounded on purpose: the harness's matcher parses
 * six, so a band remains in which the measurement can still detect what the
 * vault does not redact (review 2026-08-14 follow-up, decision D2).
 */
const MAX_JSON_PARSES = 4;

/**
 * The response body is read with `await response.text()` and is not size-capped,
 * so the flat passes already scan an unbounded string. Parsing it would amplify
 * resident memory several-fold over text that is already there, so above this
 * size the descent is skipped and the flat result stands. Characters, not bytes
 * — a deliberate over-estimate of the real limit.
 *
 * The bound is checked against `flat` — the string the descent actually
 * parses — not the original `text`: every needle occurrence the flat passes
 * already redacted expanded to the 10-character `[REDACTED]`, so for a short,
 * frequently-occurring needle `flat` can run substantially longer than `text`,
 * and comparing `text.length` here would let a parse well past this bound
 * through.
 */
const MAX_STRUCTURAL_CHARS = 4 * 1024 * 1024;

/**
 * Redact `secret` and its encodings from `text`, including occurrences nested
 * inside a JSON document carried as a string value (a webhook `data` envelope,
 * an MCP result whose body is itself serialized JSON) up to `MAX_JSON_PARSES`
 * levels deep.
 *
 * This is the best-effort output-sanitization layer for process-mediated
 * injection (thesis §4.5.2). It removes the raw value and its base64 / base64url
 * / hex / percent-encoded / JSON-escaped forms — raising naive exfiltration (echo
 * the env var) from prompt-injection-only (L1) to at least L3, where the attacker
 * must shape an encoding transform the filter does not cover. It does NOT defeat
 * arbitrary transforms or character-by-character chunking; those residual
 * bypasses are characterized in the evaluation, not claimed to be blocked.
 *
 * Cost is linear in `text` but carries a per-needle constant on escape-dense
 * input (every backslash is a candidate escape start for every needle) — a
 * best-effort layer atop structural opacity, not claimed to be free.
 *
 * **Re-serialization contract:** when the structural descent finds and redacts
 * a nested occurrence, the returned text is `JSON.stringify` output, not the
 * original bytes with a substring replaced. Concretely: the body comes back
 * minified (original whitespace is not preserved), integer-like object keys
 * are reordered to the front per the JS property-enumeration spec, numbers are
 * normalized through IEEE-754 round-tripping (e.g. a 20-digit integer loses
 * trailing precision), and duplicate keys are collapsed to the last one. This
 * is deliberate, not a defect: the descent only ever fires on a body that was
 * actually leaking the credential, and by the time it fires `redactFlat` has
 * already replaced bytes with `[REDACTED]` — so byte-exactness is already void
 * on this path, and every one of these differences (except duplicate-key
 * collapse, which JSON itself does not define behaviour for) is something any
 * caller doing its own `JSON.parse` on the same body would see regardless. A
 * clean body that never hits the descent, or hits it and finds nothing, is
 * still returned byte-identical (see `walked.changed` below) — this contract
 * applies only on an actual redaction.
 */
export function redactSecretEncodings(text: string, secret: string): string {
  if (text.length === 0 || secret.length === 0) return text;

  const needles = needlesFor(secret);
  const flat = redactFlat(text, needles);

  // A nested occurrence is one whose characters are escaped at the outer level,
  // and every escape begins with a backslash — so a body with none cannot hide
  // one, and the common path never pays for a parse. The size check is against
  // `flat`, not `text` — see MAX_STRUCTURAL_CHARS's doc comment.
  if (!text.includes("\\") || flat.length > MAX_STRUCTURAL_CHARS) return flat;

  const trimmed = flat.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return flat;

  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (typeof parsed !== "object" || parsed === null) return flat;
    const walked = mapStringLeavesTracked(
      parsed,
      (s) => redactFlat(s, needles),
      MAX_JSON_PARSES - 1,
    );
    if (!walked.changed) return flat;
    // `JSON.stringify` re-encodes EVERY string in `walked.value`, not just the
    // leaf that changed: an untouched sibling holding a control character
    // (e.g. an actual newline) is re-escaped through V8's short-escape
    // convention (`\n`) — two characters, a backslash followed by the letter
    // "n" — which is byte-identical to a credential that happens to contain a
    // literal backslash followed by "n". That sibling was never near the
    // credential; re-serialization alone introduced the collision. A final
    // flat pass over the fully re-serialized text closes it the same way the
    // first flat pass closes it for the original document — one extra linear
    // pass over a body that is, by construction, already carrying a
    // redaction. Like every other flat pass in this file, it is biased
    // toward over-redaction and can leave the result malformed JSON if it
    // clips a span that turns out to be syntax rather than credential; that
    // is this module's existing doctrine (see escape-tolerant.ts), not a new
    // policy — a missed redaction is the failure this layer must not have, a
    // malformed downstream body is not.
    return redactFlat(JSON.stringify(walked.value), needles);
  } catch {
    // Not a JSON document, or the flat pass left it malformed (that pass is
    // biased toward over-redaction and may break structure by design). The
    // flat result stands — this pass can only ever subtract more, never less.
    return flat;
  }
}

/**
 * Redact the credential from a thrown error's message, preserving its type,
 * code and details.
 *
 * A thrown error is a model-visible channel that no result-shaped redaction
 * layer touches: the MCP SDK turns a thrown handler error into the tool result
 * text, and the REST error handler returns `err.message`. An injector error
 * message can carry attacker-authored text — a redirect target the receiving
 * endpoint chose, a driver message quoting the connection string — so the value
 * is stripped on the way out regardless of which code wrote the message (H2).
 */
export function redactErrorMessage(err: unknown, secret: string): unknown {
  if (!(err instanceof VaultError)) return err;
  const redacted = redactSecretEncodings(err.message, secret);
  if (redacted === err.message) return err;
  return new VaultError(err.code, redacted, err.details);
}
