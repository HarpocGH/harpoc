import { describe, expect, it } from "vitest";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { PROVIDER_PRESETS, getScopesSeparator, resolveProvider } from "./providers.js";

function baseConfig(overrides: Partial<OAuthProviderConfig> = {}): OAuthProviderConfig {
  return {
    provider: "github",
    grant_type: "authorization_code",
    token_endpoint: "https://example.com/token",
    client_id: "test-client",
    ...overrides,
  };
}

describe("PROVIDER_PRESETS", () => {
  it("has GitHub preset with correct endpoints", () => {
    const gh = PROVIDER_PRESETS["github"];
    expect(gh).toBeDefined();
    expect(gh?.auth_endpoint).toContain("github.com");
    expect(gh?.token_endpoint).toContain("github.com");
    expect(gh?.device_authorization_endpoint).toContain("github.com");
  });

  it("has Google preset with correct endpoints", () => {
    const google = PROVIDER_PRESETS["google"];
    expect(google).toBeDefined();
    expect(google?.auth_endpoint).toContain("accounts.google.com");
    expect(google?.token_endpoint).toContain("googleapis.com");
  });

  it("has Microsoft preset with correct endpoints", () => {
    const ms = PROVIDER_PRESETS["microsoft"];
    expect(ms).toBeDefined();
    expect(ms?.auth_endpoint).toContain("microsoftonline.com");
    expect(ms?.token_endpoint).toContain("microsoftonline.com");
    expect(ms?.device_authorization_endpoint).toContain("microsoftonline.com");
  });

  it("has Slack preset with comma scopes separator", () => {
    const slack = PROVIDER_PRESETS["slack"];
    expect(slack).toBeDefined();
    expect(slack?.scopes_separator).toBe(",");
  });
});

describe("resolveProvider", () => {
  it("merges GitHub preset defaults", () => {
    const config = baseConfig({
      provider: "github",
      token_endpoint: "https://custom.example.com/token",
    });
    const resolved = resolveProvider(config);

    expect(resolved.auth_endpoint).toBe("https://github.com/login/oauth/authorize");
    expect(resolved.token_endpoint).toBe("https://custom.example.com/token");
    expect(resolved.scopes).toEqual(["repo", "user"]);
  });

  it("preserves user-specified auth_endpoint override", () => {
    const config = baseConfig({
      provider: "google",
      auth_endpoint: "https://custom-auth.example.com/auth",
    });
    const resolved = resolveProvider(config);

    expect(resolved.auth_endpoint).toBe("https://custom-auth.example.com/auth");
    expect(resolved.token_endpoint).toBe("https://example.com/token");
  });

  it("preserves user-specified scopes", () => {
    const config = baseConfig({
      provider: "github",
      scopes: ["read:org"],
    });
    const resolved = resolveProvider(config);

    expect(resolved.scopes).toEqual(["read:org"]);
  });

  it("returns custom provider config unchanged", () => {
    const config = baseConfig({
      provider: "custom",
      auth_endpoint: "https://custom.example.com/auth",
      token_endpoint: "https://custom.example.com/token",
    });
    const resolved = resolveProvider(config);

    expect(resolved).toEqual(config);
  });

  it("throws OAUTH_PROVIDER_NOT_FOUND for unknown preset", () => {
    const config = baseConfig({ provider: "unknown" as never });
    expect(() => resolveProvider(config)).toThrow();
    try {
      resolveProvider(config);
    } catch (err) {
      expect((err as { code: string }).code).toBe(ErrorCode.OAUTH_PROVIDER_NOT_FOUND);
    }
  });
});

describe("getScopesSeparator", () => {
  it("returns space for most providers", () => {
    expect(getScopesSeparator("github")).toBe(" ");
    expect(getScopesSeparator("google")).toBe(" ");
    expect(getScopesSeparator("microsoft")).toBe(" ");
  });

  it("returns comma for Slack", () => {
    expect(getScopesSeparator("slack")).toBe(",");
  });

  it("returns space for custom provider", () => {
    expect(getScopesSeparator("custom")).toBe(" ");
  });
});
