import { describe, expect, it } from "vitest";
import { OAuthProviderPreset } from "./types.js";
import { oauthScopesSeparator } from "./oauth-scopes.js";

describe("oauthScopesSeparator", () => {
  it("joins the slack preset's scopes with a comma", () => {
    expect(oauthScopesSeparator(OAuthProviderPreset.SLACK)).toBe(",");
  });

  it.each([
    OAuthProviderPreset.GITHUB,
    OAuthProviderPreset.GOOGLE,
    OAuthProviderPreset.MICROSOFT,
    OAuthProviderPreset.CUSTOM,
  ])("joins %s's scopes with RFC 6749's space", (provider) => {
    expect(oauthScopesSeparator(provider)).toBe(" ");
  });
});
