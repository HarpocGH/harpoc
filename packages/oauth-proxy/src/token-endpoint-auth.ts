import type { OAuthProviderConfig } from "@harpoc/shared";

/**
 * Client authentication at the token endpoint (RFC 6749 §2.3.1).
 *
 * `client_secret_basic` sends `Authorization: Basic base64(id:secret)` with
 * both halves application/x-www-form-urlencoded first, and keeps the
 * credentials out of the request body (a request must not carry them twice).
 * `client_secret_post` — the default and today's behavior — puts them in the
 * body. Providers that only accept Basic (the method servers are required to
 * support) are unusable without this.
 */
export function applyTokenEndpointAuth(
  config: OAuthProviderConfig,
  params: URLSearchParams,
  headers: Record<string, string>,
): void {
  const method = config.token_endpoint_auth_method ?? "client_secret_post";
  if (method === "client_secret_basic" && config.client_secret) {
    const pair = `${encodeURIComponent(config.client_id)}:${encodeURIComponent(config.client_secret)}`;
    headers.Authorization = `Basic ${Buffer.from(pair, "utf8").toString("base64")}`;
    return;
  }
  params.set("client_id", config.client_id);
  if (config.client_secret) {
    params.set("client_secret", config.client_secret);
  }
}
