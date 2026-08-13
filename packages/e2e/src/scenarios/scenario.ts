import type { FleetService } from "../harness/backends.js";
import type { HarnessVault } from "../harness/vault.js";
import type { Arm } from "../arms/arm.js";

/**
 * The pre-registered outcome vocabulary. A closed set rather than free strings:
 * an outcome is compared against a value fixed before the run, so a typo on
 * either side must be a compile error, not a silent mismatch that reads as a
 * divergent finding.
 *
 * The distinctions carry weight in the generated §6.2 table and are not
 * interchangeable:
 *
 *   BLOCKED         the defence under test refused the attack.
 *   BYPASSED        it did not — a PRE-REGISTERED honest residual, never a
 *                   surprise. Six arms carry this by design.
 *   CHANNEL_ABSENT  there was nothing to block: the vault constructs no such
 *                   field at all (D9). A stronger claim than BLOCKED, and
 *                   reported as its own thing rather than folded in.
 *   REFUSED_UNAVAILABLE  the platform cannot deliver the defence and the vault
 *                   failed closed — the designed outcome, OS-keyed (R-1).
 */
export const Outcome = {
  OPAQUE: "OPAQUE",
  LEAKED: "LEAKED",
  /**
   * The operation completed. Shared with the Phase 1–3 demonstration cells,
   * which emit it as a literal; the baseline counterparts of the targeted
   * refusals need it as a scenario outcome, because what they show is precisely
   * that the status quo does not stop the call — not that anything hostile
   * received the credential. Rounding those up to EXFILTRATED would overstate
   * the row, and the four cells of a paired row are read together.
   */
  SUCCEEDED: "SUCCEEDED",
  EXFILTRATED: "EXFILTRATED",
  BLOCKED: "BLOCKED",
  BYPASSED: "BYPASSED",
  CHANNEL_ABSENT: "CHANNEL_ABSENT",
  REFUSED_UNAVAILABLE: "REFUSED_UNAVAILABLE",
  HANDLE_ONLY: "HANDLE_ONLY",
  CREDENTIAL_CAPTURED: "CREDENTIAL_CAPTURED",
} as const;

export type OutcomeValue = (typeof Outcome)[keyof typeof Outcome];

/** Per-scenario vault state: the secret under attack and its policy. */
export interface ScenarioSetup {
  handle: string;
  credential: string;
  /**
   * A benign string travelling the same path as the credential. Blanket
   * redaction would satisfy every opacity check, so an arm that reports OPAQUE
   * must also show this survived.
   */
  marker: string;
  cleanup?: () => void | Promise<void>;
}

/**
 * One row of the §6.2 paired table: a single attack, run against both arms.
 *
 * `observe` is written ONCE and called with each arm in turn — that is the
 * mechanical guarantee behind C-3's "same harness, same payloads". Two separate
 * per-arm functions could drift into issuing different calls, and the resulting
 * table would compare two attacks rather than two credential-handling layers.
 */
export interface ScenarioArm {
  scenario: string;
  context: string;
  /**
   * Distinguishes arms of one scenario sharing scenario+context. Part of the
   * pre-registration key; absent is its own key, never a wildcard.
   */
  variant?: string;
  /**
   * Which sides to run; both by default.
   *
   * The Phase 1–2 targeted refusals already emit their Harpoc half from the
   * context suites that own them (`git.e2e.test.ts` and friends), so Phase 4B
   * supplies only the missing baseline. Re-running the Harpoc side here would
   * write a second evidence record under a key that already has one, and the
   * generated table would then have two observations for one cell.
   */
  arms?: ReadonlyArray<"baseline" | "harpoc">;
  services?: FleetService[];
  setup(vault: HarnessVault): Promise<ScenarioSetup>;
  observe(arm: Arm, setup: ScenarioSetup): Promise<OutcomeValue>;
}

/** The sides a scenario arm runs, defaulted once so callers cannot disagree. */
export function armsOf(arm: ScenarioArm): ReadonlyArray<"baseline" | "harpoc"> {
  return arm.arms ?? ["baseline", "harpoc"];
}
