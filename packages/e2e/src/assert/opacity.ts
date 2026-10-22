import { MAX_PARSE_DEPTH, scan } from "./scan.js";
import type { Sighting } from "./scan.js";
import { serializeError } from "./serialize-error.js";
import { encodingsOf } from "./encodings.js";
import { findEscapeTolerant } from "./json-escape.js";

/** Every channel an agent can observe after a `use_secret` call. */
export interface Observation {
  result?: unknown;
  error?: unknown;
  auditRows?: unknown[];
  stdout?: string;
  stderr?: string;
  parentEnv?: NodeJS.ProcessEnv;
}

function channels(obs: Observation): Array<[string, unknown]> {
  const out: Array<[string, unknown]> = [];
  if ("result" in obs) out.push(["result", obs.result]);
  if ("auditRows" in obs) out.push(["audit", obs.auditRows]);
  if (obs.stdout !== undefined) out.push(["stdout", obs.stdout]);
  if (obs.stderr !== undefined) out.push(["stderr", obs.stderr]);
  if (obs.parentEnv !== undefined) out.push(["parentEnv", { ...obs.parentEnv }]);
  if ("error" in obs && obs.error !== undefined) out.push(["error", serializeError(obs.error)]);
  return out;
}

/**
 * Every position the credential surfaced in, across every channel and every
 * encoding — the sweep behind `assertOpaque`, without the throw.
 *
 * Exposed because a two-arm scenario must CLASSIFY its outcome (LEAKED versus
 * OPAQUE) rather than assert one: the baseline arm is expected to leak, so a
 * throwing check is the wrong shape there. Sharing this one implementation is
 * what keeps the scenarios' verdict and the demonstration cells' assertion from
 * drifting apart — a scenario-local re-derivation would be the copy nobody
 * guard-flips.
 */
export function sightings(secret: string, obs: Observation): Sighting[] {
  const hits: Sighting[] = [];
  for (const [name, node] of channels(obs)) {
    for (const hit of scan(secret, node)) {
      hits.push({ ...hit, path: `${name}${hit.path.slice(1)}` });
    }
  }
  return hits;
}

/**
 * Success criteria 1 and 2 as one callable check: the credential must not
 * appear in any encoding, at any structural position, in any observable
 * channel — result, thrown error, audit rows, child stdio, parent environment.
 */
export function assertOpaque(secret: string, obs: Observation): void {
  const hits = sightings(secret, obs);
  if (hits.length === 0) return;

  const detail = hits.map((h) => `  ${h.path} (${h.position}, ${h.encoding})`).join("\n");
  throw new Error(
    `credential plaintext reached the caller in ${hits.length} position(s):\n${detail}`,
  );
}

/**
 * A diagnostic excerpt safe to put in a thrown error or a CI log.
 *
 * A harness error message is one of the few places the credential can escape
 * the measurement: the baseline fixture redacts nothing by design, and its
 * counterpart arms carry an SSH private key, a database password and an HTTP
 * credential (review 2026-08-14, F10).
 *
 * Matches within one encoding are spliced from the end of `out` backward —
 * `findEscapeTolerant` returns them left-to-right and non-overlapping, so
 * processing the highest `start` first never invalidates the indices of the
 * matches still waiting to be spliced.
 */
export function redactForDiagnostics(text: string, secret: string): string {
  return redactEncodings(text, secret, "[REDACTED]");
}

/**
 * The marker the evidence records write in place of a credential
 * (`EvidenceRecord.calls`, test-review-2026-10-09 I1). Not the sanitizer's
 * `[REDACTED]`: that marker is one of the things a reader re-checks a record
 * for, so the record's own redaction must be tellable apart from it.
 */
export const RECORD_REDACTION = "[CREDENTIAL]";

/**
 * The record-time redaction: every credential given, in every encoding
 * `encodingsOf` knows, replaced by `RECORD_REDACTION`. The same splice as the
 * diagnostics form, with its marker.
 */
export function redactForRecord(text: string, ...secrets: string[]): string {
  return redactRecordText(
    text,
    secrets.filter((secret) => secret.length > 0),
    0,
  );
}

/**
 * The flat pass first (every encoding, one level of JSON escaping); then, while
 * the opacity scan still sights a credential and the text is JSON, the
 * structure is parsed and every string leaf and key redacted at its own level
 * — the descent `scan` makes, so what the verdict's instrument can see the
 * record's redaction can reach. The text is re-serialized only on that path —
 * compactly, so its whitespace is not kept; a record's text is read for its
 * markers and sentinels, not byte for byte.
 */
function redactRecordText(text: string, secrets: string[], depth: number): string {
  let out = text;
  for (const secret of secrets) out = redactEncodings(out, secret, RECORD_REDACTION);
  if (depth >= MAX_PARSE_DEPTH) return out;
  if (!secrets.some((secret) => scan(secret, out).length > 0)) return out;
  const trimmed = out.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return out;
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return out;
  }
  if (typeof parsed !== "object" || parsed === null) return out;
  return JSON.stringify(redactRecordNode(parsed, secrets, depth + 1));
}

function redactRecordNode(node: unknown, secrets: string[], depth: number): unknown {
  if (typeof node === "string") return redactRecordText(node, secrets, depth);
  if (Array.isArray(node)) return node.map((item) => redactRecordNode(item, secrets, depth));
  if (typeof node === "object" && node !== null) {
    const out = Object.create(null) as Record<string, unknown>;
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      out[redactRecordText(key, secrets, depth)] = redactRecordNode(value, secrets, depth);
    }
    return out;
  }
  return node;
}

function redactEncodings(text: string, secret: string, marker: string): string {
  if (secret.length === 0) return text;
  let out = text;
  for (const enc of encodingsOf(secret)) {
    for (const match of findEscapeTolerant(out, enc.needle).reverse()) {
      out = out.slice(0, match.start) + marker + out.slice(match.end);
    }
  }
  return out;
}

/**
 * Negative control. Blanket redaction would satisfy every opacity assertion,
 * so each scenario also pins that a benign marker survived untouched.
 */
export function assertPresent(needle: string, obs: Observation): void {
  for (const [, node] of channels(obs)) {
    if (scan(needle, node).length > 0) return;
  }
  throw new Error(
    `expected the benign marker "${needle}" to survive, but it appears in no channel — ` +
      `redaction is blanket, not targeted`,
  );
}
