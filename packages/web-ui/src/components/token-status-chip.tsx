import type { IssuedTokenStatus } from "@harpoc/shared";

/**
 * Token statuses carry their own tones rather than the shared `StatusChip`
 * map's: an expired *secret* is a fault worth wax-red, an expired *token* is
 * ordinary history — and under the `all` filter most rows are expired.
 */
const TONE: Record<IssuedTokenStatus, string> = {
  active: "ok",
  revoked: "bad",
  expired: "",
};

export function TokenStatusChip({ status }: { status: IssuedTokenStatus }) {
  return (
    <span class="chip" data-tone={TONE[status]}>
      {status}
    </span>
  );
}
