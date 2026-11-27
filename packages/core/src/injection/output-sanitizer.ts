import type { TextPart } from "@harpoc/shared";
import { VaultError, outsidePart } from "@harpoc/shared";
import { findEscapeTolerant, type Spans } from "./escape-tolerant.js";

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
export function mapStringLeavesTracked(
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
      if (Object.prototype.hasOwnProperty.call(result, mappedKey)) {
        let suffix = 2;
        while (Object.prototype.hasOwnProperty.call(result, `${mappedKey}_${suffix}`)) suffix++;
        mappedKey = `${mappedKey}_${suffix}`;
        changed = true;
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
 * The credential, the encodings a careless or hostile endpoint may echo it
 * in, and the upper-case form of each that is hex-shaped (hex is
 * case-insensitive on the wire). Computed once per redaction call and reused at
 * every nesting level; the buffer the encodings are read from is zeroed before
 * this returns.
 *
 * The V8 `JSON.stringify(secret).slice(1, -1)` needle is gone: it covered one
 * escaping convention, and the tolerant scan covers the class it belongs
 * to — including the conventions V8 does not use (review 2026-08-14, F1).
 */
function needlesFor(secret: string): string[] {
  const secretBytes = Buffer.from(secret, "utf8");
  const needles = new Set<string>();
  try {
    for (const form of [
      secret,
      secretBytes.toString("base64"),
      secretBytes.toString("base64url"),
      secretBytes.toString("hex"),
      encodeURIComponent(secret),
    ]) {
      if (form.length === 0) continue;
      needles.add(form);
      const upper = form.toUpperCase();
      if (upper !== form && /^[0-9a-fA-F]+$/.test(form)) needles.add(upper);
    }
  } finally {
    secretBytes.fill(0);
  }
  return [...needles];
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
 * The bound is checked against the string that is parsed: the text as it
 * stands, or, where only that form parses, the text with its flat matches
 * written.
 */
const MAX_STRUCTURAL_CHARS = 4 * 1024 * 1024;

/** For each prefix of a needle, the length of its longest proper border (Knuth-Morris-Pratt). */
function borders(needle: string): Int32Array {
  const border = new Int32Array(needle.length);
  let k = 0;
  for (let i = 1; i < needle.length; i++) {
    while (k > 0 && needle[i] !== needle[k]) k = border[k - 1] as number;
    if (needle[i] === needle[k]) k++;
    border[i] = k;
  }
  return border;
}

/**
 * Appends every literal occurrence of `needle` in `text` to `out`, overlapping
 * ones included; occurrences that overlap one another are appended as one span.
 * Only a needle that can overlap itself is read character by character, behind
 * an occurrence and while a further one could still begin inside the span.
 */
function findLiteral(text: string, needle: string, out: Spans): void {
  const m = needle.length;
  const border = borders(needle);
  const self = border[m - 1] as number;
  let i = text.indexOf(needle);
  while (i !== -1) {
    let end = i + m;
    if (self > 0) {
      let k = self;
      let q = end;
      while (q < text.length && q - k < end) {
        const ch = text[q];
        while (k > 0 && needle[k] !== ch) k = border[k - 1] as number;
        if (needle[k] === ch) k++;
        q++;
        if (k === m) {
          end = q;
          k = self;
        }
      }
    }
    out.push(i, end);
    i = text.indexOf(needle, end);
  }
}

const PACK = 2 ** 27;

/** Orders spans by start and merges those that overlap; spans that only touch stay apart. */
function mergeSpans(found: Spans): Spans {
  if (found.length === 0) return found;
  let src = found;
  let ordered = true;
  let max = 0;
  for (let i = 0; i < found.length; i += 2) {
    if (i > 0 && (found[i] as number) < (found[i - 2] as number)) ordered = false;
    if ((found[i + 1] as number) > max) max = found[i + 1] as number;
  }
  if (!ordered && max < PACK / 2) {
    const keys = new Float64Array(found.length / 2);
    for (let i = 0; i < keys.length; i++) {
      keys[i] = (found[2 * i] as number) * PACK + (found[2 * i + 1] as number);
    }
    keys.sort();
    src = new Array<number>(found.length);
    for (let i = 0; i < keys.length; i++) {
      const start = Math.floor((keys[i] as number) / PACK);
      src[2 * i] = start;
      src[2 * i + 1] = (keys[i] as number) - start * PACK;
    }
  } else if (!ordered) {
    const pairs: [number, number][] = [];
    for (let i = 0; i < found.length; i += 2) {
      pairs.push([found[i] as number, found[i + 1] as number]);
    }
    pairs.sort((a, b) => a[0] - b[0]);
    src = pairs.flat();
  }
  const out: Spans = [];
  let start = src[0] as number;
  let end = src[1] as number;
  for (let i = 2; i < src.length; i += 2) {
    const next = src[i] as number;
    if (next < end) {
      if ((src[i + 1] as number) > end) end = src[i + 1] as number;
    } else {
      out.push(start, end);
      start = next;
      end = src[i + 1] as number;
    }
  }
  out.push(start, end);
  return out;
}

/**
 * A span that lies inside a `[REDACTED]` of `text` is dropped; one that shares a
 * character with one, without lying inside, is widened to cover it whole.
 */
function respectMarkers(text: string, found: Spans): Spans {
  if (found.length === 0 || !text.includes(REDACTION)) return found;
  const markers: number[] = [];
  for (
    let i = text.indexOf(REDACTION);
    i !== -1;
    i = text.indexOf(REDACTION, i + REDACTION.length)
  ) {
    markers.push(i);
  }
  const out: Spans = [];
  for (let i = 0; i < found.length; i += 2) {
    let start = found[i] as number;
    let end = found[i + 1] as number;
    let lo = 0;
    let hi = markers.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((markers[mid] as number) + REDACTION.length <= start) lo = mid + 1;
      else hi = mid;
    }
    let inside = false;
    for (let k = lo; k < markers.length && (markers[k] as number) < end; k++) {
      const markerStart = markers[k] as number;
      const markerEnd = markerStart + REDACTION.length;
      if (start >= markerStart && end <= markerEnd) {
        inside = true;
        break;
      }
      if (markerStart < start) start = markerStart;
      if (markerEnd > end) end = markerEnd;
    }
    if (!inside) out.push(start, end);
  }
  return out;
}

/** One value's needles in one text: each literally and, where the text holds a backslash, through one escape layer. */
function flatSpans(text: string, needles: readonly string[]): Spans {
  const found: Spans = [];
  if (text.length === 0) return found;
  const tolerant = text.includes("\\");
  for (const needle of needles) {
    findLiteral(text, needle, found);
    if (tolerant) findEscapeTolerant(text, needle, found);
  }
  return respectMarkers(text, found);
}

/** Calls `visit(contentStart, contentEnd, isKey)` for each string token of a valid JSON text. */
function forEachStringToken(
  doc: string,
  visit: (start: number, end: number, isKey: boolean) => void,
): void {
  let i = 0;
  for (;;) {
    const open = doc.indexOf('"', i);
    if (open === -1) return;
    let close = open + 1;
    for (;;) {
      close = doc.indexOf('"', close);
      if (close === -1) return;
      let backslashes = 0;
      for (let b = close - 1; b > open && doc[b] === "\\"; b--) backslashes++;
      if (backslashes % 2 === 0) break;
      close++;
    }
    let after = close + 1;
    while (
      doc[after] === " " ||
      doc[after] === "\t" ||
      doc[after] === "\n" ||
      doc[after] === "\r"
    ) {
      after++;
    }
    visit(open + 1, close, doc[after] === ":");
    i = close + 1;
  }
}

/** The offsets in a string token's raw content at which each decoded code unit starts, and its end. */
function unitOffsets(raw: string): number[] {
  const offsets: number[] = [];
  let i = 0;
  while (i < raw.length) {
    offsets.push(i);
    i += raw[i] === "\\" ? (raw[i + 1] === "u" ? 6 : 2) : 1;
  }
  offsets.push(raw.length);
  return offsets;
}

/** `text` with one marker for each of its merged spans. */
function writeSpans(text: string, merged: Spans): string {
  if (merged.length === 0) return text;
  const parts: string[] = [];
  let cursor = 0;
  for (let i = 0; i < merged.length; i += 2) {
    const start = merged[i] as number;
    if (start > cursor) parts.push(text.slice(cursor, start));
    parts.push(REDACTION);
    cursor = merged[i + 1] as number;
  }
  parts.push(text.slice(cursor));
  return parts.join("");
}

/** Where the positions of `writeSpans(text, merged)` stood in `text`; a span edge at a marker maps to the edge of the span it replaced. */
function mapBack(found: Spans, merged: Spans): Spans {
  const ends: number[] = [];
  const shifts: number[] = [];
  let shift = 0;
  for (let i = 0; i < merged.length; i += 2) {
    const end = merged[i + 1] as number;
    shift += REDACTION.length - (end - (merged[i] as number));
    ends.push(end + shift);
    shifts.push(shift);
  }
  const origin = (p: number, isEnd: boolean): number => {
    let lo = 0;
    let hi = ends.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((ends[mid] as number) <= p) lo = mid + 1;
      else hi = mid;
    }
    if (lo < ends.length && p > (ends[lo] as number) - REDACTION.length) {
      return merged[2 * lo + (isEnd ? 1 : 0)] as number;
    }
    return p - (lo > 0 ? (shifts[lo - 1] as number) : 0);
  };
  const out: Spans = [];
  for (let i = 0; i < found.length; i += 2) {
    out.push(origin(found[i] as number, false), origin(found[i + 1] as number, true));
  }
  return out;
}

function sameSpans(a: Spans, b: Spans): boolean {
  return a.length === b.length && a.every((n, i) => n === b[i]);
}

/**
 * Appends the spans that the string tokens of a JSON document report, mapped
 * back through each token's escaping to the characters of `text` that spell
 * them; false, and nothing appended, when `text` is no JSON object or array. A
 * token whose raw or decoded form holds no backslash is skipped: the scan of
 * `text` has read all it holds. A key is scanned flat, a value is a level of its own.
 */
function leafSpans(
  text: string,
  needles: readonly string[][],
  depth: number,
  found: Spans,
): boolean {
  if (depth === 0 && text.length > MAX_STRUCTURAL_CHARS) return false;
  const doc = text.trim();
  try {
    const parsed: unknown = JSON.parse(doc);
    if (typeof parsed !== "object" || parsed === null) return false;
  } catch {
    return false;
  }
  const lead = text.length - text.trimStart().length;
  let backslash = doc.indexOf("\\");
  forEachStringToken(doc, (start, end, isKey) => {
    if (backslash !== -1 && backslash < start) backslash = doc.indexOf("\\", start);
    if (backslash === -1 || backslash >= end) return;
    const raw = doc.slice(start, end);
    const leaf = JSON.parse(`"${raw}"`) as string;
    if (!leaf.includes("\\")) return;
    const inner = isKey
      ? needles.flatMap((own) => flatSpans(leaf, own))
      : levelSpans(leaf, needles, depth + 1);
    if (inner.length === 0) return;
    const offsets = unitOffsets(raw);
    const base = lead + start;
    if (offsets.length !== leaf.length + 1) {
      found.push(base, base + raw.length);
      return;
    }
    for (let i = 0; i < inner.length; i += 2) {
      found.push(
        base + (offsets[inner[i] as number] as number),
        base + (offsets[inner[i + 1] as number] as number),
      );
    }
  });
  return true;
}

/**
 * The spans of one text in its own coordinates, unmerged: its flat scan, and the
 * spans of its string leaves; `depth` counts the parses made to reach it. A text
 * that is no document as it stands but holds a hit is parsed again with its flat
 * spans written — all of them, and each value's alone — since a marker can be
 * what makes it parse.
 */
function levelSpans(text: string, needles: readonly string[][], depth: number): Spans {
  const perValue = needles.map((own) => flatSpans(text, own));
  const found = perValue.flat();
  if (depth >= MAX_JSON_PARSES || !text.includes("\\")) return found;
  const doc = text.trim();
  if (!doc.startsWith("{") && !doc.startsWith("[")) return found;
  if (leafSpans(text, needles, depth, found) || found.length === 0) return found;
  const candidates = [mergeSpans(found)];
  if (perValue.length > 1) {
    for (const own of perValue) if (own.length > 0) candidates.push(mergeSpans(own));
  }
  const tried: Spans[] = [];
  for (const merged of candidates) {
    if (tried.some((done) => sameSpans(done, merged))) continue;
    tried.push(merged);
    const inner: Spans = [];
    if (!leafSpans(writeSpans(text, merged), needles, depth, inner)) continue;
    for (const p of mapBack(inner, merged)) found.push(p);
  }
  return found;
}

/** A value that can complete a match together with a marker another span wrote. */
function markerAffine(value: string): boolean {
  if (value.includes(REDACTION)) return true;
  for (let n = 1; n < REDACTION.length && n < value.length; n++) {
    if (value.endsWith(REDACTION.slice(0, n))) return true;
    if (value.startsWith(REDACTION.slice(REDACTION.length - n))) return true;
  }
  return false;
}

function distinctValues(values: readonly string[]): string[] {
  return [...new Set(values)].filter((value) => value.length > 0);
}

function applyOnce(text: string, needles: readonly string[][]): { merged: Spans; out: string } {
  if (text.length === 0 || needles.length === 0) return { merged: [], out: text };
  const merged = mergeSpans(levelSpans(text, needles, 0));
  return { merged, out: writeSpans(text, merged) };
}

/** The merged spans one application of {@link redactValues} writes a marker for. */
export function redactSpans(text: string, values: readonly string[]): Spans {
  if (text.length === 0) return [];
  return applyOnce(text, distinctValues(values).map(needlesFor)).merged;
}

/** {@link redactValues}, and whether it changed the text. */
export function redactValuesTracked(
  text: string,
  values: readonly string[],
): { text: string; changed: boolean } {
  const distinct = text.length === 0 ? [] : distinctValues(values);
  if (distinct.length === 0) return { text, changed: false };
  const needles = distinct.map(needlesFor);
  const first = applyOnce(text, needles);
  if (first.merged.length === 0) return { text, changed: false };
  let out = first.out;
  if (distinct.some(markerAffine)) {
    for (let round = 0; round <= distinct.length; round++) {
      const next = applyOnce(out, needles);
      if (next.merged.length === 0) break;
      out = next.out;
    }
  }
  return { text: out, changed: true };
}

/**
 * Redact every value of `values` and its encodings from `text`, including
 * occurrences nested inside a JSON document carried as a string value (a webhook
 * `data` envelope, an MCP result whose body is itself serialized JSON) up to
 * `MAX_JSON_PARSES` levels deep.
 *
 * This is the best-effort output-sanitization layer for process-mediated
 * injection (thesis §4.5.2). It removes the raw value and its base64 / base64url
 * / hex / percent-encoded / JSON-escaped forms — raising naive exfiltration (echo
 * the env var) from prompt-injection-only (L1) to at least L3, where the attacker
 * must shape an encoding transform the filter does not cover. It does NOT defeat
 * arbitrary transforms or character-by-character chunking; those residual
 * bypasses are characterized in the evaluation, not claimed to be blocked.
 *
 * Every match is found on the unchanged text, for all values at once: every
 * occurrence, overlapping ones included, and in each string value and key of a
 * JSON document the text holds, mapped back through the escaping to the
 * characters that spell it. Spans that overlap are merged, spans that only touch
 * stay apart, and one marker is written for each, once, into the text's own
 * bytes: nothing is re-serialized, so a document keeps its whitespace, key
 * order and numbers around a nested marker. A match inside a `[REDACTED]` of the
 * text is dropped and one that overlaps it covers it whole. A value that begins
 * or ends with a piece of the marker gets the function applied again to its
 * result, a bounded number of times, so that one call and two in a row read
 * alike.
 *
 * Cost is linear in `text` but carries a per-needle constant on escape-dense
 * input (every backslash is a candidate escape start for every needle) — a
 * best-effort layer atop structural opacity, not claimed to be free.
 */
export function redactValues(text: string, values: readonly string[]): string {
  return redactValuesTracked(text, values).text;
}

export function redactSecretEncodings(text: string, secret: string): string {
  return redactValues(text, [secret]);
}

/** Outside text as a part of an error text, redacted of every value of its context's list. */
export function outside(text: string, values: readonly string[]): TextPart {
  return outsidePart(redactValues(text, values));
}

/**
 * Strips every value of `secrets` from a VaultError's message and details in
 * one {@link redactValues} each; an error that holds none is returned as it is.
 * Empty strings and repeats are dropped, and no length floor is applied here: a
 * caller that needs one (`MIN_REDACTABLE_FRAGMENT`) applies it where it builds
 * its list.
 *
 * A thrown error is a model-visible channel that no result-shaped redaction
 * layer touches: the MCP SDK turns a thrown handler error into the tool result
 * text, and the REST error handler returns `err.message`. An injector error
 * message can carry attacker-authored text — a redirect target the receiving
 * endpoint chose, a driver message quoting the connection string — so the value
 * is stripped on the way out regardless of which code wrote the message (H2).
 *
 * `details` travels the same channels as the message (the REST error body
 * serializes it, the MCP tool result quotes it), so its string leaves and keys
 * are walked too. An error carrying the credential in neither is returned
 * unchanged, identity included.
 */
export function redactErrorMessage(err: unknown, secrets: readonly string[]): unknown {
  if (!(err instanceof VaultError)) return err;
  const values = distinctValues(secrets);
  if (values.length === 0) return err;
  const message = redactValuesTracked(err.message, values);
  const walked =
    err.details === undefined
      ? undefined
      : mapStringLeavesTracked(err.details, (s) => redactValues(s, values), 0);
  if (!message.changed && walked?.changed !== true) return err;
  const details =
    walked?.changed === true ? (walked.value as Record<string, unknown>) : err.details;
  return new VaultError(err.code, message.text, details);
}
