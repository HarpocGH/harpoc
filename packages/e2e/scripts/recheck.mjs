// The re-check over a committed evidence run, from the records' own content
// (test-review-2026-10-09 I1). Plain ESM like tables.mjs: runnable under bare
// `node`, typed for its test by recheck.d.mts; the CLI is recheck-evidence.mjs.
//
// A record carries the calls its verdict was judged on (`calls`, since
// 2026-10-15): `ok`, the response text, the error text and the child's stderr,
// the credential and its encodings replaced by the record-time marker. What the
// verdict must agree with, judged from that alone:
//
//   held      a Harpoc arm that BLOCKED, was OPAQUE, found the CHANNEL_ABSENT,
//             SUCCEEDED, returned the HANDLE_ONLY, REFUSED_UNAVAILABLE or
//             REJECTED shows the credential in no call;
//   leaked    LEAKED and CREDENTIAL_CAPTURED — the credential reached the
//             caller, or the logging tool that captures what the caller holds
//             (log-to-leak builds its log from the recorded calls) — some call
//             shows the marker, except where the leak is one the full-credential
//             encodings cannot mark (LEAK_NOT_MARKABLE below);
//   SUCCEEDED some call completed (`ok`).
//
// LEAK_NOT_MARKABLE names the eight baseline arms whose LEAKED is proven off
// the call text or on a fragment: the output-channel `chunking` (one character
// per line, reassembled by the verdict), `interpreter-collapse` (split around a
// `|`), `file-write` (the credential on disk), `dedicated-context-git` and
// `dedicated-context-ssh` (the binary's marker file), and the response-channel
// `partial-first8`, `partial-last4` and `partial-alternating` (a fragment
// echoed). They are judged by the held rule when a Harpoc arm shares the key,
// and by nothing on the baseline side.
//
// Not judged: EXFILTRATED (the attacker sink saw the credential) and BYPASSED
// (a partial reveal). A record without `calls` — every run before 2026-10-15 —
// or with an empty `calls` is counted, not judged. A call entry that is not the
// shape the capture writes (an object with a boolean `ok`, a string `text`, and
// `error` / `stderr` strings where present) is an inconsistency of its record,
// whose other calls are judged. A record whose calls carry `truncated` or
// `elided` is judged on what it carries and counted `partial`: its text is a
// prefix or a placeholder, so a held verdict there is checked in part only.
import { keyOf } from "./tables.mjs";

export { keyOf, readJsonl } from "./tables.mjs";

/** Mirrors `RECORD_REDACTION` in src/assert/opacity.ts (pinned by recheck.test.ts). */
export const RECORD_MARKER = "[CREDENTIAL]";

export const HELD_OUTCOMES = Object.freeze([
  "BLOCKED",
  "OPAQUE",
  "CHANNEL_ABSENT",
  "SUCCEEDED",
  "HANDLE_ONLY",
  "REFUSED_UNAVAILABLE",
  "REJECTED",
]);

export const LEAKED_OUTCOMES = Object.freeze(["LEAKED", "CREDENTIAL_CAPTURED"]);

/** `scenario|context|variant` of the baseline leaks the marker cannot show (pinned against preregistration.json). */
export const LEAK_NOT_MARKABLE = Object.freeze([
  "output-channel-leakage|process|chunking",
  "output-channel-leakage|process|interpreter-collapse",
  "output-channel-leakage|process|file-write",
  "output-channel-leakage|process|dedicated-context-git",
  "output-channel-leakage|process|dedicated-context-ssh",
  "response-channel-echo|http|partial-first8",
  "response-channel-echo|http|partial-last4",
  "response-channel-echo|http|partial-alternating",
]);

export function leakKeyOf(r) {
  return `${r.scenario}|${r.context}|${r.variant ?? ""}`;
}

function textsOf(call) {
  return [call.text, call.error, call.stderr].filter((f) => typeof f === "string");
}

function anyText(calls, predicate) {
  return calls.some((call) => textsOf(call).some(predicate));
}

function isCallEvidence(call) {
  return (
    typeof call === "object" &&
    call !== null &&
    !Array.isArray(call) &&
    typeof call.ok === "boolean" &&
    typeof call.text === "string" &&
    ["error", "stderr"].every(
      (field) => call[field] === undefined || typeof call[field] === "string",
    )
  );
}

export function recheck(records) {
  const out = { total: records.length, checked: 0, unchecked: 0, partial: 0, inconsistent: [] };
  for (const r of records) {
    if (!Array.isArray(r.calls) || r.calls.length === 0) {
      out.unchecked += 1;
      continue;
    }
    out.checked += 1;
    const flag = (reason) => out.inconsistent.push({ key: keyOf(r), observed: r.observed, reason });
    r.calls.forEach((call, i) => {
      if (!isCallEvidence(call)) flag(`malformed call entry at index ${String(i)}`);
    });
    const calls = r.calls.filter(isCallEvidence);
    if (calls.some((call) => call.truncated === true || call.elided === true)) out.partial += 1;
    const markerSeen = anyText(calls, (text) => text.includes(RECORD_MARKER));
    if (r.arm === "harpoc" && HELD_OUTCOMES.includes(r.observed) && markerSeen) {
      flag(`credential marker in a held ${r.observed} verdict`);
    }
    if (
      LEAKED_OUTCOMES.includes(r.observed) &&
      !markerSeen &&
      !LEAK_NOT_MARKABLE.includes(leakKeyOf(r))
    ) {
      flag(`${r.observed}, but no call shows the credential`);
    }
    if (r.observed === "SUCCEEDED" && !calls.some((call) => call.ok === true)) {
      flag("SUCCEEDED, but no call completed");
    }
  }
  return out;
}

export function renderRecheck(out) {
  const lines = [
    `recheck: ${String(out.total)} record(s), ${String(out.checked)} re-checkable, ` +
      `${String(out.unchecked)} without calls, ${String(out.partial)} partial (truncated or elided), ` +
      `${String(out.inconsistent.length)} inconsistent`,
  ];
  for (const i of out.inconsistent) lines.push(`  ${i.key}: ${i.observed} — ${i.reason}`);
  return lines.join("\n");
}
