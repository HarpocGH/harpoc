import type { ResponseMode } from "@harpoc/shared";

const STRICTNESS: Record<ResponseMode, number> = {
  full: 0,
  filtered: 1,
  status_only: 2,
};

/**
 * Tighten-only override check for the HTTP response mode (thesis §4.5.2).
 * A per-invocation mode may equal or tighten the secret's policy floor, never
 * loosen it — the action is agent-supplied, so a loosening override would
 * reopen the echo channel the policy closed.
 */
export function isResponseModeAllowed(floor: ResponseMode, requested: ResponseMode): boolean {
  return STRICTNESS[requested] >= STRICTNESS[floor];
}
