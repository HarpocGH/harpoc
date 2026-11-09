/**
 * The bounds every numeric option naming a TCP port or a renewal lead shares —
 * one declaration for the cert commands, `server start` and `oauth connect`
 * (CM-5, 2026-09-23); the engine and the manager re-check each value. The
 * egress proxy's default port is declared beside them, once for `server start
 * --proxy-port` and `proxy env --proxy-port` (DB-14).
 */
export const MIN_PORT = 1;
export const MAX_PORT = 65_535;
export const MIN_RENEW_BEFORE_DAYS = 1;
export const MAX_RENEW_BEFORE_DAYS = 365;
export const DEFAULT_PROXY_PORT = 3128;

/**
 * `proxy ca init --days`, the Harpoc CA's lifetime (RX-B8-16; B8-U1/U2, the user's rulings): the
 * name-constrained CA 1–3650 days, 3650 by default; the unconstrained fallback 1–30, 7 by default,
 * its cap cert-manager's own (`createCa` enforces it too). Refused over the cap, never clamped.
 */
export { MAX_UNCONSTRAINED_CA_DAYS } from "@harpoc/cert-manager";
export const MIN_CA_DAYS = 1;
export const MAX_CA_DAYS = 3650;
export const DEFAULT_CA_DAYS = 3650;
export const DEFAULT_UNCONSTRAINED_CA_DAYS = 7;
