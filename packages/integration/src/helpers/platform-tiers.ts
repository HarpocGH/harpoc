/**
 * CI guard against silent platform-suite skips (review T3).
 *
 * A CI leg that provisions a real platform tier (keychain, secret-service,
 * keyring, isolation, fs-isolation) exports HARPOC_REQUIRE_PLATFORM_TESTS
 * naming it: a failing availability probe is then a FAILURE, not a skip — a
 * regressed provisioning step (missing package, lost keyring possession, dead
 * D-Bus, re-tightened AppArmor) must not silently drop real-path coverage to
 * zero while every leg stays green. Local dev (var unset) keeps
 * attempt-and-skip.
 *
 * A tier is named on a leg only where the platform is EXPECTED to deliver it;
 * membership is per-leg in `.github/workflows/ci.yml`, not global:
 *
 *  - `keychain` — macOS only.
 *  - `secret-service`, `keyring` — Linux only.
 *  - `isolation` (network isolation) — Linux (`unshare -rn`) and macOS
 *    (`sandbox-exec`).
 *  - `fs-isolation` (filesystem isolation) — **macOS only** (`sandbox-exec`
 *    deny-write). The Linux leg deliberately omits it: ubuntu-24.04 ships
 *    util-linux 2.39, whose `setpriv` has no `--landlock-*` options, so the
 *    tier is expected-unavailable there until the runner image carries
 *    util-linux >= 2.40. Omitting it does NOT disable the suite on a capable
 *    Linux host — the live probe, not this list, gates the enforcement
 *    describe; the list only decides whether a failed probe is fatal.
 *  - `ssh-live` — every leg.
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
