import { VaultError } from "./errors.js";

/**
 * Listener host allowlist (R11/D61, 2026-09-04). Both HTTP listeners — the
 * MCP Streamable HTTP transport and the REST API — validate every request's
 * `Host` (and, when present, `Origin`) against one set: the operator's
 * `--allowed-host` entries plus, on a loopback bind, the three loopback
 * names. Matching is on the parsed hostname, port-agnostic and case-
 * insensitive, so `vault.example` admits `Host: vault.example:3001` and the
 * `Host: vault.example:443` a TLS-terminating proxy preserves; the raw header
 * is never compared and never echoed. A non-loopback bind without an entry is
 * refused before anything listens. Pure string logic — this module is
 * bundled into the Web UI like the rest of shared.
 */

/** Bind addresses whose listener never leaves the host (thesis §4.1). */
export const LOOPBACK_BIND_HOSTS: ReadonlySet<string> = new Set(["127.0.0.1", "::1", "localhost"]);

const HOST_CHARS = /^[a-z0-9.:-]+$/;
const IPV6_CHARS = /^[0-9a-f:.]+$/;
const PORT = /^\d{1,5}$/;

export function isLoopbackBindHost(host: string): boolean {
  return LOOPBACK_BIND_HOSTS.has(host.trim().toLowerCase());
}

/**
 * One `--allowed-host` entry as the set stores it: trimmed, lowercased, IPv6
 * brackets stripped. Null for anything but a host name or IP literal — a
 * scheme, a path, a port or a stray character is an operator mistake, not a
 * name clients send. A leading hyphen is refused too (RFC 952/1123: no label
 * starts with one), so a repeatable `--allowed-host` cannot swallow the next
 * flag as an entry and turn a start-time refusal into a listener that 403s
 * every request.
 */
export function normalizeAllowedHost(entry: string): string | null {
  const trimmed = entry.trim().toLowerCase();
  const unbracketed =
    trimmed.startsWith("[") && trimmed.endsWith("]") ? trimmed.slice(1, -1) : trimmed;
  if (unbracketed === "" || unbracketed.startsWith("-") || !HOST_CHARS.test(unbracketed))
    return null;
  // A colon is legal only inside an IPv6 literal, which carries at least two.
  if (unbracketed.includes(":")) {
    if (!IPV6_CHARS.test(unbracketed) || unbracketed.split(":").length < 3) return null;
  }
  return unbracketed;
}

/**
 * The hostname of an RFC 9110 `Host` value (`host [":" port]`), lowercased,
 * IPv6 brackets stripped, the port dropped; null when absent or unparsable.
 */
export function parseHostHeader(value: string | undefined): string | null {
  if (value === undefined) return null;
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "") return null;
  if (trimmed.startsWith("[")) {
    const end = trimmed.indexOf("]");
    if (end < 0) return null;
    const rest = trimmed.slice(end + 1);
    if (rest !== "" && !(rest.startsWith(":") && PORT.test(rest.slice(1)))) return null;
    const literal = trimmed.slice(1, end);
    return literal !== "" && IPV6_CHARS.test(literal) ? literal : null;
  }
  const colon = trimmed.indexOf(":");
  const host = colon < 0 ? trimmed : trimmed.slice(0, colon);
  if (colon >= 0 && !PORT.test(trimmed.slice(colon + 1))) return null;
  return host !== "" && HOST_CHARS.test(host) && !host.includes(":") ? host : null;
}

/**
 * The hostname of an `Origin` value; null when it is not a URL (an opaque
 * `null` included) or when its hostname is not one `parseHostHeader` would
 * accept. `URL` leaves a non-special scheme's authority almost unvalidated
 * (`foo://a"b` parses), so the same character class gates both headers and
 * such a value is refused as unparsable rather than reaching a refusal
 * message.
 */
export function parseOriginHeader(value: string | undefined): string | null {
  if (value === undefined) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) {
    const literal = host.slice(1, -1);
    return literal !== "" && IPV6_CHARS.test(literal) ? literal : null;
  }
  return host !== "" && HOST_CHARS.test(host) && !host.includes(":") ? host : null;
}

/**
 * Refuse a bind the allowlist cannot cover: a non-loopback address with no
 * entry, or an entry that is not a host name. Called by both listeners
 * before anything is bound and by both binaries before any vault is opened.
 */
export function assertBindAllowed(bindHost: string, allowedHosts: readonly string[]): void {
  for (const entry of allowedHosts) {
    if (normalizeAllowedHost(entry) === null) {
      throw VaultError.invalidInput(
        `Invalid allowed host "${entry}": a host name or IP address, without scheme, path or port`,
      );
    }
  }
  if (!isLoopbackBindHost(bindHost) && allowedHosts.length === 0) {
    throw VaultError.invalidInput(
      `A non-loopback bind (${bindHost}) requires --allowed-host <name> naming every host name clients use to reach this listener (repeatable); loopback binds allow 127.0.0.1, ::1 and localhost automatically`,
    );
  }
}

/** The set a listener checks against: the entries, plus the loopback names on a loopback bind. */
export function buildAllowedHostSet(
  bindHost: string,
  allowedHosts: readonly string[],
): ReadonlySet<string> {
  const allowed = new Set<string>();
  for (const entry of allowedHosts) {
    const normalized = normalizeAllowedHost(entry);
    if (normalized !== null) allowed.add(normalized);
  }
  if (isLoopbackBindHost(bindHost)) {
    for (const name of LOOPBACK_BIND_HOSTS) allowed.add(name);
  }
  return allowed;
}

export type HostCheck =
  | { ok: true }
  | { ok: false; header: "Host" | "Origin"; hostname: string | null };

/**
 * The allow decision for one request. `Host` must parse and be listed;
 * `Origin` is checked only when present (API clients send none, a browser
 * always does) and must parse to a listed name — an unparsable value refuses.
 */
export function checkRequestHost(
  headers: { host?: string; origin?: string },
  allowed: ReadonlySet<string>,
): HostCheck {
  const host = parseHostHeader(headers.host);
  if (host === null || !allowed.has(host)) {
    return { ok: false, header: "Host", hostname: host };
  }
  if (headers.origin !== undefined) {
    const origin = parseOriginHeader(headers.origin);
    if (origin === null || !allowed.has(origin)) {
      return { ok: false, header: "Origin", hostname: origin };
    }
  }
  return { ok: true };
}
