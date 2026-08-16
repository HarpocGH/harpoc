import type { VaultEngine } from "@harpoc/core";
import type { CallerContext, Permission, VaultApiToken } from "@harpoc/shared";
import { callerFromToken, checkTokenScope, parseHandle } from "@harpoc/shared";

export const TOKEN_OPTION_DESCRIPTION =
  "Scoped API token: enforces token scope and per-secret access policies, and attributes the call (omit for the trusted local path); prefer the HARPOC_TOKEN environment variable — command-line arguments are visible to other local processes";

export interface TokenScopeTarget {
  permission: Permission;
  project?: string;
  name?: string;
}

export interface ResolvedToken {
  payload: VaultApiToken;
  caller: CallerContext;
}

/**
 * A present-but-empty token is refused rather than treated as absent. Every
 * other direction in this codebase fails closed on an unusable token; here
 * the fallback direction is the more privileged one, so silently ignoring an
 * empty `--token ""` or an exported-but-empty `HARPOC_TOKEN` would run the
 * call on the trusted local path — no scope check, no per-secret policy, no
 * attribution — while the operator believes the session was attenuated.
 */
export function refuseEmptyToken(token: string | undefined): void {
  if (token !== undefined && token.trim() === "") {
    throw new Error(
      "--token (or HARPOC_TOKEN) was supplied but empty. Provide a token, or omit it entirely to use the trusted local path.",
    );
  }
}

/**
 * A supplied token *attenuates* the unlocked session (thesis §4.7): its scope
 * is enforced with the same predicate the REST routes use, and the call is
 * attributed to the token's principal, so per-secret access policies apply as
 * they do on every other token-bearing interface. No token = the trusted
 * local path, unchanged: no caller, no policy check, unattributed audit rows.
 */
export function resolveTokenCaller(
  engine: Pick<VaultEngine, "verifyToken">,
  target: TokenScopeTarget,
  token: string | undefined,
): ResolvedToken | undefined {
  if (token === undefined) return undefined;
  refuseEmptyToken(token);
  const payload = engine.verifyToken(token);
  checkTokenScope(payload, target.permission, target.project, target.name);
  return { payload, caller: callerFromToken(payload, "cli") };
}

/**
 * Handle-addressed variant: on the trusted local path (no token) the handle
 * is NOT parsed here — the engine parses it, so a malformed handle still
 * produces the engine's denial audit row exactly as before token support.
 * With a token present, precedence is: empty-token refusal, then handle
 * validity, then verification, then scope.
 */
export function resolveTokenCallerForHandle(
  engine: Pick<VaultEngine, "verifyToken">,
  permission: Permission,
  handle: string,
  token: string | undefined,
): ResolvedToken | undefined {
  if (token === undefined) return undefined;
  refuseEmptyToken(token);
  const { project, name } = parseHandle(handle);
  return resolveTokenCaller(engine, { permission, project, name }, token);
}
