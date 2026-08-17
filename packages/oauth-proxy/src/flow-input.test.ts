import { describe, expect, it } from "vitest";
import { ErrorCode, OAuthGrantType, VaultError } from "@harpoc/shared";
import type { StartOAuthFlowInput } from "@harpoc/shared";
import { providerConfigFromFlowInput } from "./flow-input.js";

function baseInput(overrides: Partial<StartOAuthFlowInput> = {}): StartOAuthFlowInput {
  return {
    name: "gh-token",
    provider: "github",
    grant_type: OAuthGrantType.AUTHORIZATION_CODE,
    client_id: "client-1",
    ...overrides,
  };
}

function captureVaultError(fn: () => unknown): VaultError {
  try {
    fn();
  } catch (err) {
    if (err instanceof VaultError) return err;
    throw err;
  }
  throw new Error("expected providerConfigFromFlowInput to throw a VaultError");
}

describe("providerConfigFromFlowInput", () => {
  it("fills the endpoints from the github preset", () => {
    const { config } = providerConfigFromFlowInput(
      baseInput({ grant_type: OAuthGrantType.DEVICE_CODE }),
    );
    expect(config.token_endpoint).toBe("https://github.com/login/oauth/access_token");
    expect(config.auth_endpoint).toBe("https://github.com/login/oauth/authorize");
    expect(config.device_authorization_endpoint).toBe("https://github.com/login/device/code");
  });

  it("leaves scopes to the flow-time preset merge when the input omits them", () => {
    const { config } = providerConfigFromFlowInput(baseInput());
    expect(config.scopes).toBeUndefined();
  });

  it("passes input scopes through", () => {
    const { config } = providerConfigFromFlowInput(baseInput({ scopes: ["repo", "user:email"] }));
    expect(config.scopes).toEqual(["repo", "user:email"]);
  });

  it("lets explicit endpoints win over the preset", () => {
    const { config } = providerConfigFromFlowInput(
      baseInput({
        grant_type: OAuthGrantType.DEVICE_CODE,
        auth_endpoint: "https://ghe.example.com/login/oauth/authorize",
        token_endpoint: "https://ghe.example.com/login/oauth/access_token",
        device_authorization_endpoint: "https://ghe.example.com/login/device/code",
      }),
    );
    expect(config.auth_endpoint).toBe("https://ghe.example.com/login/oauth/authorize");
    expect(config.token_endpoint).toBe("https://ghe.example.com/login/oauth/access_token");
    expect(config.device_authorization_endpoint).toBe("https://ghe.example.com/login/device/code");
  });

  it("rejects a custom provider without a token endpoint", () => {
    const err = captureVaultError(() =>
      providerConfigFromFlowInput(
        baseInput({ provider: "custom", grant_type: OAuthGrantType.CLIENT_CREDENTIALS }),
      ),
    );
    expect(err.code).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
    expect(err.message).toBe('token_endpoint is required for provider "custom"');
  });

  it("rejects an authorization_code custom config without an auth endpoint", () => {
    const err = captureVaultError(() =>
      providerConfigFromFlowInput(
        baseInput({
          provider: "custom",
          token_endpoint: "https://auth.example.com/token",
        }),
      ),
    );
    expect(err.code).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
    expect(err.message).toBe(
      "auth_endpoint: auth_endpoint is required for authorization_code grant type",
    );
  });

  it("puts extras.redirect_uri on the config", () => {
    const { config } = providerConfigFromFlowInput(baseInput(), {
      redirect_uri: "http://127.0.0.1:8123/callback",
    });
    expect(config.redirect_uri).toBe("http://127.0.0.1:8123/callback");
  });

  it("omits redirect_uri when no extras are given", () => {
    const { config } = providerConfigFromFlowInput(baseInput());
    expect(config.redirect_uri).toBeUndefined();
  });

  it("passes project through", () => {
    const { project } = providerConfigFromFlowInput(baseInput({ project: "my-project" }));
    expect(project).toBe("my-project");
  });

  it("leaves project undefined when the input has none", () => {
    const { project } = providerConfigFromFlowInput(baseInput());
    expect(project).toBeUndefined();
  });
});
