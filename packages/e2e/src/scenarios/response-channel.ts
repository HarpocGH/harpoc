import { storeSecret } from "../harness/vault.js";
import { sightings } from "../assert/opacity.js";
import { ECHO_HTTPS } from "../harness/backends.js";
import { Outcome } from "./scenario.js";
import type { OutcomeValue, ScenarioArm, ScenarioSetup } from "./scenario.js";
import type { Arm, CallOutcome } from "../arms/arm.js";
import type { HarnessVault } from "../harness/vault.js";

const NONCE = "p4s7";
const ORIGIN = `https://${ECHO_HTTPS.host}:${String(ECHO_HTTPS.port)}`;

type ResponseMode = "full" | "filtered" | "status_only";

async function setupEcho(
  vault: HarnessVault,
  name: string,
  credential: string,
  responseMode?: ResponseMode,
): Promise<ScenarioSetup> {
  const handle = await storeSecret(vault, `p4-rc-${name}-${NONCE}`, credential);
  await vault.engine.setInjectionPolicy(handle, {
    url_allowlist: [`${ORIGIN}/*`],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
    ...(responseMode === undefined ? {} : { response_mode: responseMode }),
  });
  return { handle, credential, marker: `p4-rc-marker-${NONCE}` };
}

/** Same two-vocabulary rule as §6.2.6: one measurement, two column names. */
function verdict(arm: Arm, leaked: boolean): OutcomeValue {
  if (arm.name === "baseline") {
    if (!leaked) {
      throw new Error(
        "baseline did not leak: the echo path is broken, so the paired row would be vacuous",
      );
    }
    return Outcome.LEAKED;
  }
  return leaked ? Outcome.BYPASSED : Outcome.BLOCKED;
}

const fetchAction = (path: string): Record<string, unknown> => ({
  type: "http",
  method: "GET",
  url: `${ORIGIN}${path}`,
  injection: { type: "bearer" },
});

/**
 * What the caller can actually recover. `scan` descends into serialized JSON
 * itself since the 2026-08-14 review (F4), so the envelope and the error text
 * are the whole view — the deep walk that used to live here is now inherited by
 * every scenario and every matrix cell, not just this file.
 */
function callerView(outcome: CallOutcome): unknown[] {
  return [outcome.result, outcome.errorText];
}

function leakedToCaller(outcome: CallOutcome, credential: string): boolean {
  return sightings(credential, { result: callerView(outcome) }).length > 0;
}

/** Does a specific FRAGMENT survive into the caller-visible result? */
function fragmentSurvived(outcome: CallOutcome, fragment: string): boolean {
  return outcome.text.includes(fragment);
}

/**
 * §6.2.7 — Response-Channel Echo Bypass.
 *
 * §4.4's two-layer opacity model commits to empirically testing three
 * echo-bypass classes against I2a, on the response surface of a
 * request-mediated invocation. A hostile (or merely careless) endpoint reflects
 * the credential back, and the question is what the vault's best-effort
 * filtering catches.
 *
 * These classes exist only under `response_mode: "filtered"`, the default.
 * `status_only` structurally closes the BODY channel — no body is read, so
 * encoded, partial and out-of-band body echoes have no surface at all. That is
 * scoped to the body deliberately: it does NOT close the channel generally,
 * which is why §6.2.2's refusal-message arm exists separately.
 *
 * Two arms report something other than a filtering verdict, and the distinction
 * is load-bearing for the chapter:
 *   - `status-reason-phrase` is CHANNEL_ABSENT, not BLOCKED. `HttpResult` is
 *     `{type, status, headers, body}` — the vault never constructs a
 *     status-text field under ANY policy, so there is nothing to filter. That
 *     is a stronger claim than filtering and is reported as its own thing.
 *   - the three `partial-*` arms are pre-registered BYPASSED. What survives is
 *     a FRAGMENT, not the whole credential — a real information leak that
 *     contiguous-pattern matching cannot catch by construction, and not the
 *     same thing as full compromise. The table should be read that way.
 */
export const RESPONSE_CHANNEL_ARMS: ScenarioArm[] = [
  {
    scenario: "response-channel-echo",
    context: "http",
    variant: "encoded-body",
    services: ["echo-https"],
    setup: (v) => setupEcho(v, "encoded", `p4-rc-encoded:tok/en-${NONCE}`),
    async observe(arm, setup) {
      // The backend reflects base64, base64url, hex (both cases) and
      // percent-encoded forms — exactly the set the vault redacts.
      const outcome = await arm.invoke(setup.handle, fetchAction("/echo"));
      return verdict(arm, leakedToCaller(outcome, setup.credential));
    },
  },
  {
    scenario: "response-channel-echo",
    context: "http",
    variant: "json-escaped",
    services: ["echo-https"],
    // The credential carries a quote and a backslash on purpose. For an
    // alphanumeric value the JSON-escaped form is byte-identical to the raw
    // one, so this class is invisible unless the value can actually be escaped
    // — which is why every earlier suite missed it.
    setup: (v) => setupEcho(v, "jsonesc", `p4-rc-json:tok"en\\x-${NONCE}`),
    async observe(arm, setup) {
      // The response body is JSON, so ordinary serialization escapes the value
      // on the wire. No special endpoint is needed: the channel appears in ANY
      // JSON response body, which is what makes it worth closing rather than
      // characterizing.
      const outcome = await arm.invoke(setup.handle, fetchAction("/echo"));
      return verdict(arm, leakedToCaller(outcome, setup.credential));
    },
  },
  {
    scenario: "response-channel-echo",
    context: "http",
    variant: "json-escaped-non-v8",
    services: ["echo-https"],
    // The solidus is routine in base64 tokens and keys, and a non-ASCII
    // character is routine everywhere. Both are invisible to a needle built with
    // JSON.stringify, which is V8's convention only (review 2026-08-14, F1).
    setup: (v) => setupEcho(v, "jsonescalt", `p4-rc-alt:tok/en"ü-${NONCE}`),
    async observe(arm, setup) {
      const outcome = await arm.invoke(setup.handle, fetchAction("/echo/jsonesc-alt"));
      return verdict(arm, leakedToCaller(outcome, setup.credential));
    },
  },
  {
    scenario: "response-channel-echo",
    context: "http",
    variant: "header-echo",
    services: ["echo-https"],
    setup: (v) => setupEcho(v, "header", `p4-rc-header-${NONCE}`),
    async observe(arm, setup) {
      // `filtered` returns every response header, so `x-echo-credential` is a
      // genuine structural position in the caller-visible result — not a
      // channel the vault happens never to populate.
      const outcome = await arm.invoke(setup.handle, fetchAction("/echo"));
      return verdict(arm, leakedToCaller(outcome, setup.credential));
    },
  },
  {
    scenario: "response-channel-echo",
    context: "http",
    variant: "status-reason-phrase",
    services: ["echo-https"],
    setup: (v) => setupEcho(v, "reason", `p4-rc-reason-${NONCE}`),
    async observe(arm, setup) {
      const outcome = await arm.invoke(setup.handle, fetchAction("/echo/reason"));
      if (leakedToCaller(outcome, setup.credential)) {
        return arm.name === "baseline" ? Outcome.LEAKED : Outcome.BYPASSED;
      }
      const carriesStatusText = /"status_?[tT]ext"/.test(outcome.text);
      if (arm.name === "baseline") {
        // The baseline leaks only if the HTTP client preserved the server's
        // reason phrase, which is version- and platform-dependent. Where it did
        // not, this arm is not discriminating on this leg — and falling through
        // would record BLOCKED, a defensive outcome the status quo cannot
        // legitimately produce, against a pre-registered LEAKED (F8).
        throw new Error(
          "baseline did not leak the reason phrase: the HTTP client normalized it, so this " +
            "arm compares nothing on this platform — add a host_os-keyed expectation if that " +
            "is the designed outcome here",
        );
      }
      // Nothing filtered it — the field does not exist. Distinguished from
      // BLOCKED because the claims differ in strength (D9).
      return carriesStatusText ? Outcome.BLOCKED : Outcome.CHANNEL_ABSENT;
    },
  },
  {
    scenario: "response-channel-echo",
    context: "http",
    variant: "status-only-closes-body",
    services: ["echo-https"],
    setup: (v) => setupEcho(v, "statusonly", `p4-rc-statusonly-${NONCE}`, "status_only"),
    async observe(arm, setup) {
      // The body is never read, so the echo channel is absent rather than
      // filtered. Scoped to the body on purpose — see the file docstring.
      const outcome = await arm.invoke(setup.handle, fetchAction("/echo"));
      return verdict(arm, leakedToCaller(outcome, setup.credential));
    },
  },
  ...(
    [
      ["partial-first8", (c: string) => c.slice(0, 8)],
      ["partial-last4", (c: string) => c.slice(-4)],
      [
        "partial-alternating",
        (c: string) =>
          c
            .split("")
            .filter((_, i) => i % 2 === 0)
            .join(""),
      ],
    ] as const
  ).map(
    ([variant, fragmentOf]): ScenarioArm => ({
      scenario: "response-channel-echo",
      context: "http",
      variant,
      services: ["echo-https"],
      setup: (v) => setupEcho(v, variant, `p4-rc-${variant}-${NONCE}`),
      async observe(arm, setup) {
        // Measured as FRAGMENT survival, not full-credential survival: the
        // endpoint never emits the whole value, so a whole-credential sweep
        // would find nothing and report BLOCKED for both arms — a false
        // negative that would hide the residual entirely.
        const outcome = await arm.invoke(setup.handle, fetchAction("/echo/partial"));
        return verdict(arm, fragmentSurvived(outcome, fragmentOf(setup.credential)));
      },
    }),
  ),
];
