import { afterEach, describe, expect, it } from "vitest";
import { assertTierAvailable, tierRequired } from "./platform-tiers.js";

const saved = process.env["HARPOC_REQUIRE_PLATFORM_TESTS"];

afterEach(() => {
  if (saved === undefined) {
    delete process.env["HARPOC_REQUIRE_PLATFORM_TESTS"];
  } else {
    process.env["HARPOC_REQUIRE_PLATFORM_TESTS"] = saved;
  }
});

describe("HARPOC_REQUIRE_PLATFORM_TESTS guard (review T3)", () => {
  it("unset: nothing is required — attempt-and-skip preserved for local dev", () => {
    delete process.env["HARPOC_REQUIRE_PLATFORM_TESTS"];
    expect(tierRequired("keychain")).toBe(false);
    expect(() => assertTierAvailable("keychain", false)).not.toThrow();
  });

  it("a required tier with a failed probe throws, carrying the probe error", () => {
    process.env["HARPOC_REQUIRE_PLATFORM_TESTS"] = "secret-service,keyring,isolation";
    expect(() => assertTierAvailable("keyring", false, new Error("EACCES possession"))).toThrow(
      /demands the "keyring" tier.*EACCES possession/,
    );
  });

  it("a required tier that probed available passes", () => {
    process.env["HARPOC_REQUIRE_PLATFORM_TESTS"] = "isolation";
    expect(() => assertTierAvailable("isolation", true)).not.toThrow();
  });

  it("an unlisted tier keeps skipping even when others are required", () => {
    process.env["HARPOC_REQUIRE_PLATFORM_TESTS"] = "keychain";
    expect(tierRequired("secret-service")).toBe(false);
    expect(() => assertTierAvailable("secret-service", false)).not.toThrow();
  });

  it("parses comma lists with whitespace", () => {
    process.env["HARPOC_REQUIRE_PLATFORM_TESTS"] = " keychain , isolation ";
    expect(tierRequired("keychain")).toBe(true);
    expect(tierRequired("isolation")).toBe(true);
  });
});
