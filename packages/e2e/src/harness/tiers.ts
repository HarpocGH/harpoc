/**
 * The e2e harness's guard against a silent platform skip, in the shape of
 * integration's `helpers/platform-tiers.ts` (e2e does not depend on
 * integration). A job that provisions a tier names it in
 * HARPOC_REQUIRE_PLATFORM_TESTS: a failed availability probe is then a
 * failure, not a skip. Unset — a local run — the suite attempts and skips.
 *
 *  - `two-uid` — Linux: the users named by HARPOC_TWO_UID_VAULT_USER and
 *    HARPOC_TWO_UID_AGENT_USER exist, `sudo -n -u` runs the built CLI as each,
 *    and the agent user runs `curl` and `ssh` (`model-b.e2e.test.ts`).
 *  - `docker` — the agent user reaches the Docker daemon (through the `docker`
 *    group: the runner has no rootless Docker) and the image the docker row
 *    runs is present (`MODEL_B_DOCKER_IMAGE`).
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
