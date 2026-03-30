import { createHash, randomBytes } from "node:crypto";

/**
 * Generate a PKCE code verifier (43–128 chars, base64url-encoded random bytes).
 * We use 32 random bytes → 43 base64url characters.
 */
export function generateCodeVerifier(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * Generate a PKCE S256 code challenge from a verifier.
 * challenge = BASE64URL(SHA256(verifier))
 */
export function generateCodeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}
