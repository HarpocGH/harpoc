import { describe, expect, it } from "vitest";
import { OAuthGrantType } from "@harpoc/shared";
import { buildOAuthProviderConfig } from "./oauth-config.js";

describe("buildOAuthProviderConfig", () => {
  it("merges github preset token and auth endpoints", () => {
    const { config } = buildOAuthProviderConfig(
      "gh-token",
      OAuthGrantType.AUTHORIZATION_CODE,
      { provider: "github", clientId: "client-1" },
      undefined,
    );
    expect(config.token_endpoint).toBe("https://github.com/login/oauth/access_token");
    expect(config.auth_endpoint).toBe("https://github.com/login/oauth/authorize");
    expect(config.client_id).toBe("client-1");
  });

  it("leaves scopes to the flow-time preset merge when --scopes is omitted", () => {
    const { config } = buildOAuthProviderConfig(
      "gh-token",
      OAuthGrantType.AUTHORIZATION_CODE,
      { provider: "github", clientId: "client-1" },
      undefined,
    );
    expect(config.scopes).toBeUndefined();
  });

  it("splits --scopes on commas and trims entries", () => {
    const { config } = buildOAuthProviderConfig(
      "gh-token",
      OAuthGrantType.AUTHORIZATION_CODE,
      { provider: "github", clientId: "client-1", scopes: "repo, read:org ,user" },
      undefined,
    );
    expect(config.scopes).toEqual(["repo", "read:org", "user"]);
  });

  it("resolves the google device endpoint from the preset", () => {
    const { config } = buildOAuthProviderConfig(
      "g-token",
      OAuthGrantType.DEVICE_CODE,
      { provider: "google", clientId: "client-1" },
      undefined,
    );
    expect(config.device_authorization_endpoint).toBe("https://oauth2.googleapis.com/device/code");
  });

  it("rejects --device with the slack preset (no device endpoint)", () => {
    expect(() =>
      buildOAuthProviderConfig(
        "slack-token",
        OAuthGrantType.DEVICE_CODE,
        { provider: "slack", clientId: "client-1" },
        undefined,
      ),
    ).toThrow(/device_authorization_endpoint is required/);
  });

  it("requires --token-endpoint for a custom provider", () => {
    expect(() =>
      buildOAuthProviderConfig(
        "custom-token",
        OAuthGrantType.CLIENT_CREDENTIALS,
        { provider: "custom", clientId: "client-1" },
        "secret",
      ),
    ).toThrow(/--token-endpoint is required for provider "custom"/);
  });

  it("requires an auth endpoint for authorization_code with a custom provider", () => {
    expect(() =>
      buildOAuthProviderConfig(
        "custom-token",
        OAuthGrantType.AUTHORIZATION_CODE,
        {
          provider: "custom",
          clientId: "client-1",
          tokenEndpoint: "https://auth.example.com/token",
        },
        undefined,
      ),
    ).toThrow(/auth_endpoint is required/);
  });

  it("accepts loopback HTTP endpoints", () => {
    const { config } = buildOAuthProviderConfig(
      "loop-token",
      OAuthGrantType.CLIENT_CREDENTIALS,
      {
        provider: "custom",
        clientId: "client-1",
        tokenEndpoint: "http://127.0.0.1:8080/token",
      },
      "secret",
    );
    expect(config.token_endpoint).toBe("http://127.0.0.1:8080/token");
  });

  it("rejects non-loopback HTTP endpoints (negative control)", () => {
    expect(() =>
      buildOAuthProviderConfig(
        "bad-token",
        OAuthGrantType.CLIENT_CREDENTIALS,
        {
          provider: "custom",
          clientId: "client-1",
          tokenEndpoint: "http://192.168.1.10:8080/token",
        },
        "secret",
      ),
    ).toThrow(/HTTPS/);
  });

  it("rejects an invalid --auth-method", () => {
    expect(() =>
      buildOAuthProviderConfig(
        "gh-token",
        OAuthGrantType.AUTHORIZATION_CODE,
        { provider: "github", clientId: "client-1", authMethod: "basic" },
        undefined,
      ),
    ).toThrow(/token_endpoint_auth_method/);
  });

  it("passes a valid --auth-method through", () => {
    const { config } = buildOAuthProviderConfig(
      "gh-token",
      OAuthGrantType.AUTHORIZATION_CODE,
      { provider: "github", clientId: "client-1", authMethod: "client_secret_basic" },
      "secret",
    );
    expect(config.token_endpoint_auth_method).toBe("client_secret_basic");
  });

  it("rejects an unknown provider", () => {
    expect(() =>
      buildOAuthProviderConfig(
        "x-token",
        OAuthGrantType.AUTHORIZATION_CODE,
        { provider: "gitlab", clientId: "client-1" },
        undefined,
      ),
    ).toThrow(/provider/);
  });

  it("requires --provider and --client-id", () => {
    expect(() =>
      buildOAuthProviderConfig("x", OAuthGrantType.AUTHORIZATION_CODE, {}, undefined),
    ).toThrow(/--provider is required/);
    expect(() =>
      buildOAuthProviderConfig(
        "x",
        OAuthGrantType.AUTHORIZATION_CODE,
        { provider: "github" },
        undefined,
      ),
    ).toThrow(/--client-id is required/);
  });

  it("passes project through and includes the client secret in the config", () => {
    const { config, project } = buildOAuthProviderConfig(
      "proj-token",
      OAuthGrantType.CLIENT_CREDENTIALS,
      { provider: "github", clientId: "client-1", project: "my-project" },
      "s3cret",
    );
    expect(project).toBe("my-project");
    expect(config.client_secret).toBe("s3cret");
  });

  it("rejects an invalid secret name", () => {
    expect(() =>
      buildOAuthProviderConfig(
        "has space",
        OAuthGrantType.AUTHORIZATION_CODE,
        { provider: "github", clientId: "client-1" },
        undefined,
      ),
    ).toThrow(/name/);
  });
});
