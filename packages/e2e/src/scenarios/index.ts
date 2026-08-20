import type { ScenarioArm } from "./scenario.js";
import { PROMPT_INJECTION_ARMS } from "./prompt-injection.js";
import { URL_MANIPULATION_ARMS } from "./url-manipulation.js";
import { SHADOW_ESCAPE_ARMS } from "./shadow-escape.js";
import { OUTPUT_CHANNEL_ARMS } from "./output-channel.js";
import { RESPONSE_CHANNEL_ARMS } from "./response-channel.js";
import { TOOL_POISONING_ARMS } from "./tool-poisoning.js";
import { LOG_TO_LEAK_ARMS } from "./log-to-leak.js";
import { CONTEXT_OPACITY_ARMS } from "./context-opacity.js";
import { TARGETED_ARMS, BASELINE_COUNTERPART_ARMS } from "./targeted.js";

/**
 * Every §6.2 attack arm, as data.
 *
 * The runner iterates this list and the coverage assertion compares it against
 * the committed pre-registration, so an arm that is deleted, renamed or never
 * wired up fails the suite instead of shrinking the evidence in silence —
 * `expectationFor` errors on an unregistered key, never on a registered
 * expectation that no arm exercised.
 */
export const SCENARIO_ARMS: ScenarioArm[] = [
  ...PROMPT_INJECTION_ARMS,
  ...URL_MANIPULATION_ARMS,
  ...SHADOW_ESCAPE_ARMS,
  ...OUTPUT_CHANNEL_ARMS,
  ...RESPONSE_CHANNEL_ARMS,
  ...TOOL_POISONING_ARMS,
  ...LOG_TO_LEAK_ARMS,
  ...CONTEXT_OPACITY_ARMS,
  ...TARGETED_ARMS,
  ...BASELINE_COUNTERPART_ARMS,
];

/** The canonical per-arm setup key — includes context (review 2026-08-14,
 *  F12): two arms sharing scenario+variant across contexts must not collide. */
export function armSetupKey(s: { scenario: string; context: string; variant?: string }): string {
  return `${s.scenario}|${s.context}|${s.variant ?? ""}`;
}

export { Outcome, armsOf } from "./scenario.js";
export type { ScenarioArm, ScenarioSetup, OutcomeValue } from "./scenario.js";
