import { describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { Arm, CallOutcome } from "../arms/arm.js";
import { RECORD_REDACTION, redactForRecord } from "../assert/opacity.js";
import { scan } from "../assert/scan.js";
import { EVIDENCE_TEXT_CAP, callEvidence, recordingArm } from "./calls.js";

// The redaction is spied so the fail-closed elision can be driven: a
// pass-through keeps every other case on the real redaction.
vi.mock("../assert/opacity.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../assert/opacity.js")>();
  return { ...actual, redactForRecord: vi.fn(actual.redactForRecord) };
});
const redactForRecordMock = vi.mocked(redactForRecord);

const CREDENTIAL = "p4-calls-marker:not/a-credential";
const B64 = Buffer.from(CREDENTIAL, "utf8").toString("base64");

function completed(text: string, extra: Partial<CallOutcome> = {}): CallOutcome {
  return { ok: true, result: { content: [{ type: "text", text }] }, text, ...extra };
}

/**
 * The capture layer behind `EvidenceRecord.calls` (test-review-2026-10-09 I1):
 * a record carries the surface calls its verdict was judged on, so the verdict
 * can be re-checked from the record alone. The credential is replaced by a
 * marker of its own — never the sanitizer's `[REDACTED]`, which is itself one of
 * the things a reader re-checks.
 */
describe("callEvidence", () => {
  it("carries ok, the texts and the error, with the credential and its encodings marked", () => {
    const ev = callEvidence(
      completed(`{"stdout":"${CREDENTIAL} and ${B64}"}`, {
        errorText: `refused for ${CREDENTIAL}`,
        stderr: `child saw ${CREDENTIAL}`,
      }),
      CREDENTIAL,
    );
    expect(ev).toEqual({
      ok: true,
      error: `refused for ${RECORD_REDACTION}`,
      text: `{"stdout":"${RECORD_REDACTION} and ${RECORD_REDACTION}"}`,
      stderr: `child saw ${RECORD_REDACTION}`,
    });
    expect(JSON.stringify(ev)).not.toContain(CREDENTIAL);
    expect(JSON.stringify(ev)).not.toContain(B64);
  });

  it("uses a marker distinct from the sanitizer's, so the two redactions stay tellable apart", () => {
    const ev = callEvidence(completed(`[REDACTED] then ${CREDENTIAL}`), CREDENTIAL);
    expect(RECORD_REDACTION).not.toBe("[REDACTED]");
    expect(ev.text).toBe(`[REDACTED] then ${RECORD_REDACTION}`);
  });

  it("marks every credential it is given", () => {
    const second = "second-credential-value";
    const ev = callEvidence(completed(`${CREDENTIAL}|${second}`), CREDENTIAL, second);
    expect(ev.text).toBe(`${RECORD_REDACTION}|${RECORD_REDACTION}`);
  });

  it("omits the error and stderr keys when the outcome carries none", () => {
    const ev = callEvidence({ ok: false, text: "nothing" }, CREDENTIAL);
    expect(ev).toEqual({ ok: false, text: "nothing" });
    expect(Object.keys(ev)).toEqual(["ok", "text"]);
  });

  it("caps each text at EVIDENCE_TEXT_CAP after the redaction and says so", () => {
    const long = `${CREDENTIAL}${"x".repeat(EVIDENCE_TEXT_CAP * 2)}`;
    const ev = callEvidence(completed(long, { stderr: "short" }), CREDENTIAL);
    expect(ev.text).toHaveLength(EVIDENCE_TEXT_CAP);
    expect(ev.text.startsWith(RECORD_REDACTION)).toBe(true);
    expect(ev.truncated).toBe(true);
    expect(ev.stderr).toBe("short");

    const within = callEvidence(completed("x".repeat(EVIDENCE_TEXT_CAP)), CREDENTIAL);
    expect(within.text).toHaveLength(EVIDENCE_TEXT_CAP);
    expect("truncated" in within).toBe(false);
  });

  it("leaves room for the metadata probe's joined text", () => {
    // The probe joins ten sub-calls — the pretty-printed listing of every secret
    // in the harness vault and the tools/list schemas among them — and ran past
    // 16 KiB on the 2026-10-15 rehearsal; a cap below it would leave the H2
    // error channel the probe exists to check uncaptured.
    expect(EVIDENCE_TEXT_CAP).toBeGreaterThanOrEqual(65_536);
  });

  it("marks a credential nested three JSON levels deep in place — no elision needed", () => {
    const quoted = 'sk-quoted"credential';
    const deep = JSON.stringify({ a: JSON.stringify({ b: JSON.stringify({ c: quoted }) }) });
    expect(scan(quoted, deep).length).toBeGreaterThan(0);
    const ev = callEvidence(completed(deep), quoted);
    expect(scan(quoted, ev.text)).toEqual([]);
    expect(ev.text).toContain(RECORD_REDACTION);
    expect(ev.text).not.toBe(RECORD_REDACTION);
    expect("elided" in ev).toBe(false);
  });

  it("elides a field whole when the redaction leaves a sighting (fail-closed)", () => {
    // The redaction made to miss once: whatever it cannot reach must never be
    // committed with the credential in it.
    redactForRecordMock.mockImplementationOnce((text) => text);
    const ev = callEvidence(completed(`x ${CREDENTIAL}`, { errorText: "plain" }), CREDENTIAL);
    expect(ev.text).toBe(RECORD_REDACTION);
    expect(ev.elided).toBe(true);
    expect(ev.error).toBe("plain");
    expect(scan(CREDENTIAL, ev)).toEqual([]);
  });
});

describe("recordingArm", () => {
  function fakeArm(
    invokeOutcome: CallOutcome,
    probeOutcome: CallOutcome,
  ): Arm & {
    invoke: Mock<Arm["invoke"]>;
    probeMetadata: Mock<Arm["probeMetadata"]>;
    close: Mock<Arm["close"]>;
  } {
    return {
      name: "harpoc",
      invoke: vi.fn(() => Promise.resolve(invokeOutcome)),
      probeMetadata: vi.fn(() => Promise.resolve(probeOutcome)),
      close: vi.fn(() => Promise.resolve()),
    };
  }

  it("forwards every call unchanged and captures each outcome in order, redacted", async () => {
    const invoked = completed(`{"stdout":"${CREDENTIAL}"}`);
    const probed: CallOutcome = {
      ok: false,
      text: "",
      errorText: `Secret not found: ${CREDENTIAL}`,
    };
    const inner = fakeArm(invoked, probed);
    const arm = recordingArm(inner, CREDENTIAL);

    expect(arm.name).toBe("harpoc");
    await expect(arm.invoke("secret://x", { type: "process" })).resolves.toBe(invoked);
    await expect(arm.probeMetadata("secret://x")).resolves.toBe(probed);
    await expect(arm.probeMetadata()).resolves.toBe(probed);
    expect(inner.invoke).toHaveBeenCalledWith("secret://x", { type: "process" });
    expect(inner.probeMetadata.mock.calls).toEqual([["secret://x"], [undefined]]);

    expect(arm.calls()).toEqual([
      { ok: true, text: `{"stdout":"${RECORD_REDACTION}"}` },
      { ok: false, text: "", error: `Secret not found: ${RECORD_REDACTION}` },
      { ok: false, text: "", error: `Secret not found: ${RECORD_REDACTION}` },
    ]);
    expect(JSON.stringify(arm.calls())).not.toContain(CREDENTIAL);
  });

  it("captures nothing for a call that threw, and forwards close()", async () => {
    const inner = fakeArm(completed("unused"), completed("unused"));
    inner.invoke.mockImplementation(() => Promise.reject(new Error("transport down")));
    const arm = recordingArm(inner, CREDENTIAL);

    await expect(arm.invoke("secret://x", {})).rejects.toThrow("transport down");
    expect(arm.calls()).toEqual([]);

    await arm.close();
    expect(inner.close).toHaveBeenCalledTimes(1);
  });

  it("returns a fresh copy of the captured calls each time", async () => {
    const arm = recordingArm(fakeArm(completed("a"), completed("b")), CREDENTIAL);
    await arm.invoke("secret://x", {});
    const first = arm.calls();
    first.length = 0;
    expect(arm.calls()).toHaveLength(1);
  });
});
