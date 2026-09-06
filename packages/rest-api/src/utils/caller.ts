import type { Context } from "hono";
import { getConnInfo } from "@hono/node-server/conninfo";
import type { CallerContext } from "@harpoc/shared";
import { callerFromToken, normalizeSocketPeer } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

/**
 * The socket peer of this request — never a forwarded header (E75i,
 * 2026-09-02): behind a reverse proxy the trail records the proxy,
 * deliberately. A dual-stack listener reports an IPv4 peer as
 * `::ffff:127.0.0.1`; `normalizeSocketPeer` records the dotted form, so one
 * client is one `audit_log.ip_address` value whichever address was bound (D9,
 * 2026-09-06). Undefined off a real listener (`app.request` in tests supplies
 * no connection), where the audit row keeps a NULL `ip_address`.
 */
export function socketPeer(c: Context<HarpocEnv>): string | undefined {
  try {
    const address = getConnInfo(c).remote.address;
    return address ? normalizeSocketPeer(address) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The request's caller: the verified token, this interface, and the socket
 * peer the auth middleware captured — the one construction point for every
 * route (E75i).
 */
export function callerOf(c: Context<HarpocEnv>): CallerContext {
  return callerFromToken(c.get("token"), "rest", c.get("remoteAddress"));
}
