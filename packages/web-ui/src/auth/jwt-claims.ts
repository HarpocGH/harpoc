/** The claims the UI reads off its own bearer — never any other token's. */
export interface JwtClaims {
  jti?: string;
  sub?: string;
  exp?: number;
  principal_type?: string;
}

function decodeSegment(segment: string): string | null {
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  try {
    const binary = atob(padded);
    return new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
  } catch {
    return null;
  }
}

/**
 * Read the payload of the JWT this session already holds. Nothing here
 * verifies anything: the signature is the server's business, and the only
 * question asked of the claims is whether a `jti` about to be revoked is the
 * one this tab is authenticating with. A malformed or foreign-shaped token is
 * therefore not an error — it is simply a token whose jti is unknown, and every
 * failure path answers `null` so the caller falls back to the ordinary
 * confirmation.
 *
 * Each claim is picked out under a type guard: a `jti` that arrives as a number
 * would typecheck as a string and lose the identity comparison silently.
 */
export function decodeJwtClaims(token: string): JwtClaims | null {
  const segments = token.split(".");
  if (segments.length !== 3) return null;
  const payload = segments[1];
  if (payload === undefined || payload === "") return null;
  const json = decodeSegment(payload);
  if (json === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const claims = parsed as Record<string, unknown>;
  return {
    ...(typeof claims["jti"] === "string" ? { jti: claims["jti"] } : {}),
    ...(typeof claims["sub"] === "string" ? { sub: claims["sub"] } : {}),
    ...(typeof claims["exp"] === "number" ? { exp: claims["exp"] } : {}),
    ...(typeof claims["principal_type"] === "string"
      ? { principal_type: claims["principal_type"] }
      : {}),
  };
}
