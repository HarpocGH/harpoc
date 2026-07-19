import type { AccessInterface, CallerContext, PrincipalType } from "@harpoc/shared";
import type { AuditLogOptions } from "./audit-logger.js";

/**
 * Per-invocation audit attribution threaded from the engine into the
 * injectors' audit writes (thesis §4.3.4 "by whom" / "through which
 * interface"). The injectors are engine-constructed singletons sharing one
 * AuditLogger, so attribution travels per call, never as constructor state.
 * Absent attribution marks the trusted local path (CLI, in-process SDK,
 * tokenless stdio MCP) — those rows keep NULL principal columns by design.
 */
export interface AuditAttribution {
  principal_type?: PrincipalType;
  principal_id?: string;
  session_id?: string;
  interface?: AccessInterface;
}

/**
 * Build the attribution for one use_secret invocation from the caller (V1's
 * policy-enforcement channel) and the engine's session id. Returns undefined
 * when both are empty so the fully-local case writes byte-identical rows.
 */
export function attributionFromCaller(
  caller: CallerContext | undefined,
  sessionId: string | null | undefined,
): AuditAttribution | undefined {
  if (!caller && !sessionId) return undefined;
  const attribution: AuditAttribution = {};
  if (caller) {
    attribution.principal_type = caller.principal_type;
    attribution.principal_id = caller.principal_id;
    if (caller.interface) attribution.interface = caller.interface;
  }
  if (sessionId) attribution.session_id = sessionId;
  return attribution;
}

/**
 * Interface tag for the encrypted detail of a caller-attributed engine row —
 * the engine's own audit sites stamp the principal columns directly and add
 * only this to their detail ("through which interface", ch4 §4.3.4).
 */
export function callerInterfaceDetail(caller: CallerContext | undefined): Record<string, unknown> {
  return caller?.interface ? { interface: caller.interface } : {};
}

/**
 * Merge an attribution into an audit entry: principal and session land in the
 * plaintext columns (covered by the row-chain HMAC), the interface in the
 * encrypted detail — ch4 §4.3.4 keeps the plaintext envelope minimal.
 */
export function withAttribution(
  options: AuditLogOptions,
  attribution: AuditAttribution | undefined,
): AuditLogOptions {
  if (!attribution) return options;
  const merged: AuditLogOptions = { ...options };
  if (attribution.principal_type !== undefined) merged.principalType = attribution.principal_type;
  if (attribution.principal_id !== undefined) merged.principalId = attribution.principal_id;
  if (attribution.session_id !== undefined) merged.sessionId = attribution.session_id;
  if (attribution.interface !== undefined) {
    merged.detail = { ...(options.detail ?? {}), interface: attribution.interface };
  }
  return merged;
}
