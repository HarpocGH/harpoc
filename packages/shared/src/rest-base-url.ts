import { LOOPBACK_URL_HOSTS } from "./host-allowlist.js";

/** Why a REST base URL is refused — the surfaces (`harpoc --url`, `harpoc-mcp --url`) render
 * their own message per reason, never the value. */
export type RestBaseUrlRefusal =
  "flag" | "not_a_url" | "scheme" | "credentials" | "query_or_fragment" | "plain_http_off_loopback";

export type RestBaseUrlParse =
  { ok: true; url: URL; baseUrl: string } | { ok: false; reason: RestBaseUrlRefusal };

/**
 * The base URL of a Harpoc REST server as the CLI's `--url` and `harpoc-mcp --url` take it
 * (deployment model B): `https:` anywhere or `http:` on a loopback host — the bearer must not
 * cross a network in the clear — with no credentials and no query or fragment; a path prefix
 * is kept, so `baseUrl` (origin and path) is what `RestClient` prepends to `/api/v1/…`.
 */
export function parseRestBaseUrl(value: string): RestBaseUrlParse {
  if (value.startsWith("-")) return { ok: false, reason: "flag" };
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, reason: "not_a_url" };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return { ok: false, reason: "scheme" };
  if (url.username !== "" || url.password !== "") return { ok: false, reason: "credentials" };
  if (url.search !== "" || url.hash !== "") return { ok: false, reason: "query_or_fragment" };
  if (url.protocol === "http:" && !LOOPBACK_URL_HOSTS.has(url.hostname)) {
    return { ok: false, reason: "plain_http_off_loopback" };
  }
  return { ok: true, url, baseUrl: `${url.origin}${url.pathname}` };
}
