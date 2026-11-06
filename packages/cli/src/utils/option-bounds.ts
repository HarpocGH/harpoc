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
