/**
 * CI guard against silent platform-suite skips (review T3).
 *
 * A CI leg that provisions a real platform tier (keychain, secret-service,
 * keyring, isolation) exports HARPOC_REQUIRE_PLATFORM_TESTS naming it: a
 * failing availability probe is then a FAILURE, not a skip — a regressed
 * provisioning step (missing package, lost keyring possession, dead D-Bus,
 * re-tightened AppArmor) must not silently drop real-path coverage to zero
 * while every leg stays green. Local dev (var unset) keeps attempt-and-skip.
 */
export function tierRequired(tier: string): boolean {
  return (process.env["HARPOC_REQUIRE_PLATFORM_TESTS"] ?? "")
    .split(",")
    .map((t) => t.trim())
    .includes(tier);
}

export function assertTierAvailable(tier: string, available: boolean, probeError?: unknown): void {
  if (!available && tierRequired(tier)) {
    throw new Error(
      `HARPOC_REQUIRE_PLATFORM_TESTS demands the "${tier}" tier but its probe failed` +
        (probeError ? `: ${String(probeError)}` : ""),
    );
  }
}
