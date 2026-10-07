/**
 * Whether this run demands a platform tier: `HARPOC_REQUIRE_PLATFORM_TESTS` holds a
 * comma-separated list of tier names, and a suite whose tier is listed fails instead of
 * skipping when its probe finds the facility absent (the review T3 pattern: a regressed
 * provisioning step must not drop real-path coverage to zero while the leg stays green).
 * Local runs leave the variable unset and skip.
 *
 * The `ssh-live` tier covers the ssh, sftp and git clients: every leg that exports it
 * (all three CI legs) ships git too, so git's suites are guarded under it (TM-11) —
 * `git-injector.spawn.test.ts` beside `ssh-live-auth.test.ts` and `sftp-injector.spawn.test.ts`.
 * Core's own copy of integration's `tierRequired` (`platform-tiers.ts`): core does not
 * depend on integration.
 */
export function tierRequired(tier: string): boolean {
  return (process.env["HARPOC_REQUIRE_PLATFORM_TESTS"] ?? "")
    .split(",")
    .map((t) => t.trim())
    .includes(tier);
}
