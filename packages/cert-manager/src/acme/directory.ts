import { VaultError } from "@harpoc/shared";

export const LETS_ENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";
export const LETS_ENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";

/* Loopback set mirrors the shared OAuth endpoint schema. ACME URLs address
 * orders, authorizations and challenges by unguessable token, so a rejection
 * names the origin and never the rest of the URL. */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function validateAcmeUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw VaultError.certAcmeFailed("URL is not parseable");
  }
  if (parsed.protocol === "https:") return;
  if (parsed.protocol === "http:" && LOOPBACK_HOSTS.has(parsed.hostname)) return;
  throw VaultError.certAcmeFailed(
    `URL must use HTTPS (plain HTTP is allowed for loopback only): ${originOf(parsed)}`,
  );
}

function originOf(url: URL): string {
  return url.origin === "null" ? `${url.protocol}//${url.host}` : url.origin;
}
