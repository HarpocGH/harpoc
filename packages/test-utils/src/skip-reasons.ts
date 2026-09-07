/**
 * The two host conditions a dual-stack listener test may legitimately skip on
 * (D7, 2026-09-07): a host with no IPv6 stack refuses the `::` bind, and a host
 * that binds `::` v6-only refuses the IPv4 connect that follows. Everything
 * else — an occupied port, a refused audit row, a rejected handshake, a
 * malformed body — is a failure the test must report, never skip. The lists
 * are deliberately short: a code is added when a CI leg produces it, never in
 * anticipation.
 */

const IPV6_BIND_UNAVAILABLE: ReadonlySet<string> = new Set(["EAFNOSUPPORT", "EADDRNOTAVAIL"]);
const CONNECTION_REFUSED: ReadonlySet<string> = new Set(["ECONNREFUSED"]);

/** Every `code` on `err`, down its `cause` chain and across any `errors[]`. */
function errnoCodes(err: unknown, seen = new Set<unknown>()): string[] {
  if (typeof err !== "object" || err === null || seen.has(err)) return [];
  seen.add(err);
  const record = err as { code?: unknown; cause?: unknown; errors?: unknown };
  const own = typeof record.code === "string" ? [record.code] : [];
  const nested: unknown[] = Array.isArray(record.errors) ? record.errors : [];
  return [
    ...own,
    ...errnoCodes(record.cause, seen),
    ...nested.flatMap((inner) => errnoCodes(inner, seen)),
  ];
}

/** The `::` bind failed because the host has no usable IPv6 stack. */
export function isIpv6BindUnavailable(err: unknown): boolean {
  return errnoCodes(err).some((code) => IPV6_BIND_UNAVAILABLE.has(code));
}

/** The connect was refused — a `::` listener bound v6-only, an IPv4 client. */
export function isConnectionRefused(err: unknown): boolean {
  return errnoCodes(err).some((code) => CONNECTION_REFUSED.has(code));
}
