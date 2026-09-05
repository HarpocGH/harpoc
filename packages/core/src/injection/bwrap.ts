/**
 * bubblewrap (`bwrap`) — the second Linux isolation tier (compromise audit
 * D50, Wave 3 step 9). Consulted only after a dimension's primary is absent
 * or its live probe failed: `unshare -rn` for the network, `setpriv
 * --landlock-*` for the filesystem. Every argv here is a vault constant, one
 * token per element, never interpolated; the payload follows the trailing
 * `--`, so a first argument starting with `-` can never be read as a bwrap
 * option.
 *
 * Process model (bubblewrap.c, 0.9.0 and main): unlike the primaries, bwrap
 * does not exec the payload in place — its parent stays as a monitor that
 * returns the payload's exit status, and `--die-with-parent` arms
 * PR_SET_PDEATHSIG on both the monitor and the payload, so a SIGKILL on the
 * process the vault spawned reaches the payload. The pid the vault records is
 * the monitor's, which is the kill target.
 *
 * Availability: bwrap needs the same unprivileged user-namespace grant as
 * `unshare` (Ubuntu 24.04 ships no AppArmor profile for it), so the tier does
 * not escape that restriction; what it buys is filesystem isolation on hosts
 * whose util-linux predates 2.40 (Ubuntu 24.04 LTS among them), and a network
 * fallback where an operator grants `userns` to `/usr/bin/bwrap` alone.
 */

/** Pinned absolute candidates — PATH is never consulted. */
export const LINUX_BWRAP_CANDIDATES = ["/usr/bin/bwrap", "/bin/bwrap"] as const;

/**
 * Network only: the whole host tree bound read-write (no filesystem
 * restriction rides a network demand), a fresh network namespace — bwrap
 * raises an empty loopback inside it, with nothing listening — and the kill
 * chain.
 */
export const BWRAP_NETWORK_PREFIX_ARGS = [
  "--bind",
  "/",
  "/",
  "--unshare-net",
  "--die-with-parent",
  "--",
] as const;

/**
 * Filesystem only: the host tree bound read-only and a fresh devtmpfs on
 * `/dev`, so `/dev/null` stays writable as under Landlock's explicit rule and
 * the macOS allow clause. No `--tmpfs /tmp`: the other mechanisms deny `/tmp`
 * writes too, and a private tmpfs would hide a working directory under it.
 */
export const BWRAP_FS_PREFIX_ARGS = [
  "--ro-bind",
  "/",
  "/",
  "--dev",
  "/dev",
  "--die-with-parent",
  "--",
] as const;

/** Both dimensions in ONE wrapper — never bwrap nested inside another wrapper. */
export const BWRAP_COMBINED_PREFIX_ARGS = [
  "--ro-bind",
  "/",
  "/",
  "--dev",
  "/dev",
  "--unshare-net",
  "--die-with-parent",
  "--",
] as const;
