import { describe, it, expect } from "vitest";
import { redactForDiagnostics } from "../assert/opacity.js";
import { encodingsOf } from "../assert/encodings.js";
import { targetedVerdict, counterpartVerdict } from "./targeted.js";
import { Outcome } from "./scenario.js";
import type { Arm, CallOutcome } from "../arms/arm.js";

describe("thrown verdict diagnostics (F10)", () => {
  it("strips a PEM private key from an excerpt", () => {
    const key = "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADAN\n-----END PRIVATE KEY-----";
    const text = `ssh failed loading ${key} at line 3`;
    const out = redactForDiagnostics(text, key);
    expect(out).not.toContain("MIIBVgIBADAN");
    expect(out).toContain("[REDACTED]");
  });

  it("strips the base64 form as well as the raw one", () => {
    const cred = "db-counterpart-password";
    const b64 = Buffer.from(cred, "utf8").toString("base64");
    expect(redactForDiagnostics(`auth failed: ${b64}`, cred)).not.toContain(b64);
  });

  it("leaves unrelated diagnostic text intact (negative control)", () => {
    expect(redactForDiagnostics("exit code 128, host unreachable", "secret")).toBe(
      "exit code 128, host unreachable",
    );
  });
});

/**
 * Wiring pins (F10 fix round 1): `redactForDiagnostics` being correct is not
 * the same property as every call site actually using it. These drive the
 * real `targetedVerdict`/`counterpartVerdict` throw branches directly — the
 * only way to falsify a site that forgot to redact, since a green fleet run
 * never executes a broken-fixture throw path.
 */
describe("thrown verdict wiring (F10 fix round 1)", () => {
  const CREDENTIAL =
    "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASCAQAB\n-----END PRIVATE KEY-----";

  function thrownMessage(fn: () => unknown): string {
    try {
      fn();
    } catch (err) {
      return (err as Error).message;
    }
    throw new Error("expected the call to throw, but it returned normally");
  }

  it("targetedVerdict redacts the credential from its thrown diagnostic", () => {
    const outcome = {
      ok: false,
      text: `ssh failed loading ${CREDENTIAL} at line 3`,
    } as CallOutcome;
    const arm = { name: "baseline" } as Arm;

    const message = thrownMessage(() => targetedVerdict(arm, false, outcome, CREDENTIAL));

    for (const enc of encodingsOf(CREDENTIAL)) {
      expect(message).not.toContain(enc.needle);
    }
    // A test that passes because the message became useless is not a fix:
    // the diagnostic context has to survive redaction.
    expect(message).toContain("ok=false");
    expect(message).toContain("baseline did not reach the attacker target");
  });

  it("counterpartVerdict redacts the credential from its thrown diagnostic", () => {
    const outcome = {
      ok: false,
      text: `git clone failed: ${CREDENTIAL} rejected`,
    } as CallOutcome;

    const message = thrownMessage(() =>
      counterpartVerdict(false, Outcome.EXFILTRATED, outcome, CREDENTIAL),
    );

    for (const enc of encodingsOf(CREDENTIAL)) {
      expect(message).not.toContain(enc.needle);
    }
    expect(message).toContain("ok=false");
    expect(message).toContain("baseline counterpart did not complete the operation");
  });

  it("targetedVerdict (non-discriminating refusal) redacts the credential from its thrown diagnostic", () => {
    // Fix round 2: the third `redactForDiagnostics` call site — the
    // non-baseline "arm is not discriminating" branch, which interpolates
    // `errorText` rather than `text`.
    const outcome = {
      ok: false,
      text: "",
      errorText: `authentication rejected: bad key ${CREDENTIAL}`,
    } as CallOutcome;
    const arm = { name: "harpoc" } as Arm;

    const message = thrownMessage(() => targetedVerdict(arm, false, outcome, CREDENTIAL));

    for (const enc of encodingsOf(CREDENTIAL)) {
      expect(message).not.toContain(enc.needle);
    }
    expect(message).toContain("ok=false");
    expect(message).toContain("arm is not discriminating");
    expect(message).toContain("the refusal does not name");
  });
});
