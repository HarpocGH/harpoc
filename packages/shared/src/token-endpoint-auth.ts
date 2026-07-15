/**
 * Structural subset of an OAuth provider config sufficient to authenticate a
 * client at the token endpoint. `OAuthProviderConfig` satisfies it as-is; the
 * core refresh path builds it from decrypted `oauth_tokens` row fields.
 */
export interface TokenEndpointClientAuth {
  client_id: string;
  client_secret?: string | undefined;
  token_endpoint_auth_method?: "client_secret_post" | "client_secret_basic" | undefined;
}

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
  auth: TokenEndpointClientAuth,
  params: URLSearchParams,
  headers: Record<string, string>,
): void {
  const method = auth.token_endpoint_auth_method ?? "client_secret_post";
  if (method === "client_secret_basic" && auth.client_secret) {
    const pair = `${encodeURIComponent(auth.client_id)}:${encodeURIComponent(auth.client_secret)}`;
    // encodeURIComponent output is ASCII-only, so btoa (latin1-limited, but
    // available in Node and browsers alike — shared has no Node types) is safe.
    headers.Authorization = `Basic ${btoa(pair)}`;
    return;
  }
  params.set("client_id", auth.client_id);
  if (auth.client_secret) {
    params.set("client_secret", auth.client_secret);
  }
}
