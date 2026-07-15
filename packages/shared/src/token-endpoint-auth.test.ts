import { describe, expect, it } from "vitest";
import { applyTokenEndpointAuth } from "./token-endpoint-auth.js";
import type { TokenEndpointClientAuth } from "./token-endpoint-auth.js";

function apply(auth: TokenEndpointClientAuth): {
  params: URLSearchParams;
  headers: Record<string, string>;
} {
  const params = new URLSearchParams({ grant_type: "refresh_token" });
  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  };
  applyTokenEndpointAuth(auth, params, headers);
  return { params, headers };
}

describe("applyTokenEndpointAuth", () => {
  it("client_secret_basic sets the Authorization header and keeps credentials out of the body", () => {
    const { params, headers } = apply({
      client_id: "my-id",
      client_secret: "my-secret",
      token_endpoint_auth_method: "client_secret_basic",
    });

    expect(headers.Authorization).toBe(
      `Basic ${Buffer.from("my-id:my-secret", "utf8").toString("base64")}`,
    );
    expect(params.has("client_id")).toBe(false);
    expect(params.has("client_secret")).toBe(false);
  });

  it("form-urlencodes each credential half before Basic encoding (RFC 6749 §2.3.1)", () => {
    const clientId = "id:with/reserved%chars+ü";
    const clientSecret = "se:cret%20+/ü";
    const { headers } = apply({
      client_id: clientId,
      client_secret: clientSecret,
      token_endpoint_auth_method: "client_secret_basic",
    });

    const encoded = (headers.Authorization as string).replace(/^Basic /, "");
    const pair = Buffer.from(encoded, "base64").toString("utf8");
    const separator = pair.indexOf(":");
    expect(separator).toBeGreaterThan(0);
    expect(decodeURIComponent(pair.slice(0, separator))).toBe(clientId);
    expect(decodeURIComponent(pair.slice(separator + 1))).toBe(clientSecret);
  });

  it("defaults to client_secret_post when no method is given", () => {
    const { params, headers } = apply({ client_id: "my-id", client_secret: "my-secret" });

    expect(params.get("client_id")).toBe("my-id");
    expect(params.get("client_secret")).toBe("my-secret");
    expect(headers.Authorization).toBeUndefined();
  });

  it("explicit client_secret_post puts credentials in the body", () => {
    const { params, headers } = apply({
      client_id: "my-id",
      client_secret: "my-secret",
      token_endpoint_auth_method: "client_secret_post",
    });

    expect(params.get("client_id")).toBe("my-id");
    expect(params.get("client_secret")).toBe("my-secret");
    expect(headers.Authorization).toBeUndefined();
  });

  it("client_secret_basic without a secret falls through to the body branch (public client)", () => {
    const { params, headers } = apply({
      client_id: "public-id",
      token_endpoint_auth_method: "client_secret_basic",
    });

    expect(params.get("client_id")).toBe("public-id");
    expect(params.has("client_secret")).toBe(false);
    expect(headers.Authorization).toBeUndefined();
  });

  it("leaves pre-existing headers and params untouched", () => {
    const { params, headers } = apply({
      client_id: "my-id",
      client_secret: "my-secret",
      token_endpoint_auth_method: "client_secret_basic",
    });

    expect(headers["Content-Type"]).toBe("application/x-www-form-urlencoded");
    expect(params.get("grant_type")).toBe("refresh_token");
  });
});
