import { VaultError } from "@harpoc/shared";
import { redactEscapeTolerant } from "./escape-tolerant.js";

const REDACTION = "[REDACTED]";

/**
 * Redact a secret value and its common encodings from captured process output.
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
 */
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
export function mapStringLeaves(value: unknown, fn: (s: string) => string): unknown {
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) return value.map((item) => mapStringLeaves(item, fn));
  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      let mappedKey = fn(key);
      if (mappedKey !== key && Object.prototype.hasOwnProperty.call(result, mappedKey)) {
        let suffix = 2;
        while (Object.prototype.hasOwnProperty.call(result, `${mappedKey}_${suffix}`)) suffix++;
        mappedKey = `${mappedKey}_${suffix}`;
      }
      result[mappedKey] = mapStringLeaves(val, fn);
    }
    return result;
  }
  return value;
}

export function redactSecretEncodings(text: string, secret: string): string {
  if (text.length === 0 || secret.length === 0) return text;

  const secretBytes = Buffer.from(secret, "utf8");
  // The V8 `JSON.stringify(secret).slice(1, -1)` needle is gone: it covered one
  // escaping convention, and the tolerant pass below covers the class it belongs
  // to — including the conventions V8 does not use (review 2026-08-14, F1).
  const needles = new Set<string>([
    secret,
    secretBytes.toString("base64"),
    secretBytes.toString("base64url"),
    secretBytes.toString("hex"),
    encodeURIComponent(secret),
  ]);

  // `redactEscapeTolerant` can only match a character through an escape
  // sequence, and every escape sequence begins with a backslash, so if `text`
  // contains none at all, any tolerant match is necessarily a purely literal
  // one — which the literal pass below has already made and replaced. The
  // tolerant passes are therefore provably redundant for such text.
  // `[REDACTED]` itself contains no backslash, so replacing a needle with it
  // cannot introduce one partway through the loop — checked once, up front,
  // per call, not per needle (a per-needle check would give back most of the
  // win it buys on non-escaped bodies, the common case on the HTTP response path).
  const hasBackslash = text.includes("\\");

  let result = text;
  for (const needle of needles) {
    if (needle.length === 0) continue;
    if (result.includes(needle)) {
      result = result.split(needle).join(REDACTION);
    }
    // hex is case-insensitive on the wire; also strip an uppercase rendering,
    // tolerant of JSON escaping the same as the lowercase form below (a hex
    // credential can be escaped just as any other needle can).
    const upper = needle.toUpperCase();
    if (upper !== needle && /^[0-9a-fA-F]+$/.test(needle) && result.includes(upper)) {
      result = result.split(upper).join(REDACTION);
    }
    if (hasBackslash && upper !== needle && /^[0-9a-fA-F]+$/.test(needle)) {
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
