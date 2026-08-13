import { storeSecret } from "../harness/vault.js";
import { sightings } from "../assert/opacity.js";
import { ECHO_HTTPS } from "../harness/backends.js";
import { Outcome } from "./scenario.js";
import type { ScenarioArm } from "./scenario.js";
import type { CallOutcome } from "../arms/arm.js";

const NONCE = "p4s4";
const ECHO_ORIGIN = `https://${ECHO_HTTPS.host}:${String(ECHO_HTTPS.port)}`;

/**
 * The malicious logging tool, as a function.
 *
 * Log-To-Leak needs the agent to be connected to a compromised logging tool —
 * a deployment condition the vault neither controls nor can reproduce, which is
 * why the chapter files this scenario as an architectural TRACE rather than a
 * live run. What a compromised logging tool does, however, is not in doubt: it
 * captures whatever the agent hands it, verbatim. That is this function, and it
 * is the only simulated component in the arm — everything it captures comes
 * from real calls against a real arm.
 */
function captureLog(...observed: CallOutcome[]): unknown {
  return observed.map((o) => ({ result: o.result, text: o.text, error: o.errorText }));
}

/**
 * §6.2.4 — Log-To-Leak (hu2025, corroborated by yan2026; both preprints).
 *
 * Emitted as a trace-level record with `variant: "trace"` (D10) so the
 * generated §6.2 table carries the row — an unevidenced subsection would be
 * visible in the artifact — while a footnote marker keeps it from reading as
 * equivalent to a live paired run. The outcome vocabulary is its own for the
 * same reason: CREDENTIAL_CAPTURED and HANDLE_ONLY, not LEAKED and BLOCKED.
 *
 * What the arm actually measures is the premise the trace turns on: what is in
 * the agent's context to capture. Under the status quo the credential is; under
 * Harpoc the agent has held nothing but an opaque handle, so the identical
 * logging tool captures the handle and the leak has no material to work with.
 */
export const LOG_TO_LEAK_ARMS: ScenarioArm[] = [
  {
    scenario: "log-to-leak",
    context: "metadata",
    variant: "trace",
    services: ["echo-https"],
    async setup(vault) {
      // The credential must share no substring with the secret's NAME: the
      // captured log legitimately carries the name (that is what an opaque
      // handle is), and a credential equal to it would make every arm report
      // CREDENTIAL_CAPTURED for a value the vault never disclosed.
      const credential = `p4-log-credential-${NONCE}`;
      const handle = await storeSecret(vault, `p4-log-source-${NONCE}`, credential);
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [`${ECHO_ORIGIN}/*`],
        command_allowlist: [],
        env_allowlist: [],
        host_allowlist: [],
      });
      return { handle, credential, marker: `p4-log-marker-${NONCE}` };
    },
    async observe(arm, setup) {
      // Everything an agent would have in context around a credential
      // operation: what it learned about the secret, and what came back from
      // using it.
      const discovered = await arm.probeMetadata(setup.handle);
      const used = await arm.invoke(setup.handle, {
        type: "http",
        method: "GET",
        url: `${ECHO_ORIGIN}/echo`,
        injection: { type: "bearer" },
      });
      const captured = captureLog(discovered, used);
      const capturedCredential = sightings(setup.credential, { result: captured }).length > 0;

      if (arm.name === "baseline") {
        if (!capturedCredential) {
          throw new Error(
            "baseline logging tool captured no credential: the trace's premise is broken, " +
              "so the paired row would compare nothing",
          );
        }
        return Outcome.CREDENTIAL_CAPTURED;
      }

      // A divergence to report, not an expectation to edit.
      if (capturedCredential) return Outcome.CREDENTIAL_CAPTURED;
      // Anti-vacuity: a logging tool that captured NOTHING would also show no
      // credential. The handle has to be in there, or "it captured only the
      // handle" is a statement about an empty log.
      if (!JSON.stringify(captured).includes(setup.handle)) {
        throw new Error(
          `the captured log contains neither the credential nor the handle ${setup.handle} — ` +
            "the logging tool captured nothing, so HANDLE_ONLY would be vacuous",
        );
      }
      return Outcome.HANDLE_ONLY;
    },
  },
];
