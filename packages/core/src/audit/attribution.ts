import type { AccessInterface, CallerContext, PrincipalType } from "@harpoc/shared";
import type { AuditLogOptions } from "./audit-logger.js";

/**
 * Per-invocation audit attribution threaded from the engine into the
 * injectors' audit writes (thesis §4.3.4 "by whom" / "through which
 * interface"). The injectors are engine-constructed singletons sharing one
 * AuditLogger, so attribution travels per call, never as constructor state.
 * Absent attribution marks the trusted local path (CLI, in-process SDK) —
 * those rows keep NULL principal columns by design; a `--allow-tokenless`
 * stdio server is attributed to `tokenless-stdio` instead (R4/E78b,
 * 2026-09-02).
 */
export interface AuditAttribution {
  principal_type?: PrincipalType;
  principal_id?: string;
  session_id?: string;
  interface?: AccessInterface;
  /** The caller's socket peer, landing in `ip_address` (E75i). */
  remote_address?: string;
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
    if (caller.remote_address) attribution.remote_address = caller.remote_address;
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
 * The plaintext principal columns of a caller-attributed engine row — type,
 * id and the socket peer (`ip_address`, E75i) — spread into the log options
 * at every engine-inline audit site, so no site can carry the principal
 * without the address. Empty for the trusted local path.
 */
export function callerColumns(
  caller: CallerContext | undefined,
): Pick<AuditLogOptions, "principalType" | "principalId" | "ipAddress"> {
  if (!caller) return {};
  const columns: Pick<AuditLogOptions, "principalType" | "principalId" | "ipAddress"> = {
    principalType: caller.principal_type,
    principalId: caller.principal_id,
  };
  if (caller.remote_address) columns.ipAddress = caller.remote_address;
  return columns;
}

/**
 * Merge an attribution into an audit entry: principal, session and peer land
 * in the plaintext columns (covered by the row-chain HMAC), the interface in
 * the encrypted detail — ch4 §4.3.4 keeps the plaintext envelope minimal.
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
  if (attribution.remote_address !== undefined) merged.ipAddress = attribution.remote_address;
  if (attribution.interface !== undefined) {
    merged.detail = {
      ...(options.detail ?? {}),
      interface: attribution.interface,
    };
  }
  return merged;
}
