import { realpathSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import type { Arm, CallOutcome } from "../arms/arm.js";
import { RECORD_REDACTION, redactForRecord } from "../assert/opacity.js";
import { MAX_PARSE_DEPTH, scan } from "../assert/scan.js";

/**
 * Per-field cap on the texts a record carries. A `use_secret` response is a
 * few hundred bytes; the metadata probe's text joins ten sub-calls — the
 * pretty-printed listing of every secret in the harness vault and the
 * `tools/list` schemas among them — and ran past 16 KiB on the 2026-10-15
 * rehearsal, so the cap sits well above it: a cut field is a field the
 * re-check can judge only in part (`truncated`). The redaction and the host-root
 * replacement run before the cut, so neither a credential nor a root straddling
 * the boundary can survive as a fragment.
 */
export const EVIDENCE_TEXT_CAP = 65_536;

/**
 * One surface call as a record carries it (test-review-2026-10-09 I1): the
 * fields the Harpoc verdicts are judged on — `ok`, the response text (where the
 * sanitizer's `[REDACTED]` and the benign marker are read), the error text
 * (where a refusal is read by name) and the child's stderr for the surfaces
 * that spawn one — with the credential and its encodings replaced by
 * `RECORD_REDACTION`, never by the sanitizer's own marker, and the host's temp
 * and home roots (`os.tmpdir()`, `os.homedir()` and their realpaths, in either
 * separator, at every JSON escaping level the opacity scan parses down to) by
 * `<TMP>` and `<HOME>` — temp first, since it lies under home on win32
 * (review 2026-10-15, S10).
 */
export interface CallEvidence {
  ok: boolean;
  /** `errorText`, redacted; absent when the outcome carried none. */
  error?: string;
  /** The surface's response text, redacted and capped. */
  text: string;
  /** The spawned child's stderr for the surfaces that have one, redacted and capped. */
  stderr?: string;
  /** Present when a field was cut at `EVIDENCE_TEXT_CAP`. */
  truncated?: true;
  /**
   * Present when a field was replaced whole by `RECORD_REDACTION`: the
   * redaction decodes one level of JSON escaping, the opacity scan several, so
   * when the scan still sights a credential after the redaction the field is
   * elided rather than committed with the credential in it (fail-closed).
   */
  elided?: true;
}

const TMP_PLACEHOLDER = "<TMP>";
const HOME_PLACEHOLDER = "<HOME>";
const NAME_CHAR = "[\\p{L}\\p{N}_.~-]";
const LEFT_BOUNDARY = `(?:(?<!${NAME_CHAR})|(?<=\\\\[bfnrt])|(?<=\\\\u[0-9A-Fa-f]{4}))`;

function realpathOf(root: string): string {
  try {
    return realpathSync.native(root);
  } catch {
    return root;
  }
}

function hostRootPatterns(): Array<[RegExp, string]> {
  const roots: Array<[string, string]> = [];
  for (const [root, placeholder] of [
    [tmpdir(), TMP_PLACEHOLDER],
    [homedir(), HOME_PLACEHOLDER],
  ] as const) {
    for (const form of [root, realpathOf(root)]) {
      if (/^([A-Za-z]:)?[\\/]*$/.test(form)) continue;
      roots.push([form, placeholder], [form.replaceAll("\\", "/"), placeholder]);
    }
  }
  roots.sort(([a], [b]) => b.length - a.length);
  const seen = new Set<string>();
  const patterns: Array<[RegExp, string]> = [];
  for (const [root, placeholder] of roots) {
    let form = root;
    for (let level = 0; level <= MAX_PARSE_DEPTH; level++) {
      if (!seen.has(form)) {
        seen.add(form);
        const literal = form.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        patterns.push([
          new RegExp(`${LEFT_BOUNDARY}${literal}(?!${NAME_CHAR})`, "gu"),
          placeholder,
        ]);
      }
      form = JSON.stringify(form).slice(1, -1);
    }
  }
  return patterns;
}

export function callEvidence(outcome: CallOutcome, ...credentials: string[]): CallEvidence {
  let truncated = false;
  let elided = false;
  const roots = hostRootPatterns();
  const field = (value: string): string => {
    let redacted = redactForRecord(value, ...credentials);
    if (credentials.some((credential) => scan(credential, redacted).length > 0)) {
      elided = true;
      redacted = RECORD_REDACTION;
    }
    for (const [pattern, placeholder] of roots) redacted = redacted.replace(pattern, placeholder);
    if (redacted.length <= EVIDENCE_TEXT_CAP) return redacted;
    truncated = true;
    return redacted.slice(0, EVIDENCE_TEXT_CAP);
  };
  const evidence: CallEvidence = { ok: outcome.ok, text: field(outcome.text) };
  if (outcome.errorText !== undefined) evidence.error = field(outcome.errorText);
  if (outcome.stderr !== undefined) evidence.stderr = field(outcome.stderr);
  if (truncated) evidence.truncated = true;
  if (elided) evidence.elided = true;
  return evidence;
}

export interface RecordingArm extends Arm {
  /** The calls captured so far, in order — a copy, so a caller cannot edit the capture. */
  calls(): CallEvidence[];
}

/**
 * An `Arm` that captures every outcome it hands back. Wrapped around the arm
 * `ScenarioArm.observe` drives, it records exactly the calls the verdict was
 * formed on without touching any scenario — the one site that emits the
 * scenario records (`scenarios.e2e.test.ts`) attaches `calls()` to the record.
 * A call that throws is not captured: the verdict throws with it and no record
 * is written.
 */
export function recordingArm(arm: Arm, ...credentials: string[]): RecordingArm {
  const captured: CallEvidence[] = [];
  const capture = async (call: Promise<CallOutcome>): Promise<CallOutcome> => {
    const outcome = await call;
    captured.push(callEvidence(outcome, ...credentials));
    return outcome;
  };
  return {
    name: arm.name,
    invoke: (handle, action) => capture(arm.invoke(handle, action)),
    probeMetadata: (handle) => capture(arm.probeMetadata(handle)),
    close: () => arm.close(),
    calls: () => captured.map((call) => ({ ...call })),
  };
}
