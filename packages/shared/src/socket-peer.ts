/**
 * Socket-peer normalization for the audit trail (D9, 2026-09-06).
 *
 * A dual-stack listener (`--host ::` plus an `--allowed-host`) reports an IPv4
 * peer through the v4-mapped form `::ffff:127.0.0.1`, so the same client lands
 * in `audit_log.ip_address` under two spellings depending on how the vault was
 * bound, and an operator filtering on a dotted quad sees only half of them.
 * The mapped prefix is stripped when what follows is a dotted quad; everything
 * else is recorded verbatim — a scope-suffixed link-local address
 * (`fe80::1%eth0`) included, where the scope id names the interface the peer
 * arrived on and is part of the address.
 */

const IPV4_MAPPED =
  /^::ffff:((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})$/i;

/** The dotted-quad form of a v4-mapped peer address; any other address verbatim. */
export function normalizeSocketPeer(address: string): string {
  return IPV4_MAPPED.exec(address)?.[1] ?? address;
}
