import { storeSecret } from "../harness/vault.js";
import { sightings } from "../assert/opacity.js";
import { Outcome } from "./scenario.js";
import type { ScenarioArm } from "./scenario.js";

const NONCE = "p4s1";

/**
 * §6.2.1 — Prompt Injection Credential Exfiltration.
 *
 * The attack targets every MCP-reachable surface on which credential plaintext
 * could plausibly appear: the arguments and return values of `use_secret`, the
 * metadata from `list_secrets` and `get_secret_info`, tool-call error messages
 * and MCP resources.
 *
 * Tier 1 (scripted): the probe is issued directly, with no model in the loop,
 * so the outcome is a deterministic property of the server rather than of
 * whether some LLM version chose to emit the call. What a prompt injection can
 * *induce* is bounded by what these surfaces can *return* — so the surface is
 * probed exhaustively and the injection prose is not simulated.
 *
 * Harpoc's expected outcome is structural, not filtered: no MCP tool accepts or
 * returns a credential, and creation and rotation collect values out of band.
 * The baseline is the §2.3 status quo, where the value is simply available.
 */
export const PROMPT_INJECTION_ARMS: ScenarioArm[] = [
  {
    scenario: "prompt-injection",
    context: "metadata",
    variant: "surface-probe",
    async setup(vault) {
      const credential = `p4-prompt-injection-credential-${NONCE}`;
      const handle = await storeSecret(vault, `p4-prompt-injection-${NONCE}`, credential);
      return { handle, credential, marker: `p4-prompt-injection-marker-${NONCE}` };
    },
    async observe(arm, setup) {
      const outcome = await arm.probeMetadata(setup.handle);
      // Every channel, every encoding, keys as well as values — the same sweep
      // the demonstration cells assert with, used here to classify instead.
      const hits = sightings(setup.credential, {
        result: outcome.result,
        stderr: outcome.stderr,
      });
      return hits.length > 0 ? Outcome.LEAKED : Outcome.OPAQUE;
    },
  },
];
