import { afterEach, describe, expect, it } from "vitest";
import { assertTierAvailable, tierRequired } from "./tiers.js";

const VARIABLE = "HARPOC_REQUIRE_PLATFORM_TESTS";

describe("e2e platform tiers", () => {
  const saved = process.env[VARIABLE];
  afterEach(() => {
    if (saved === undefined) Reflect.deleteProperty(process.env, VARIABLE);
    else process.env[VARIABLE] = saved;
  });

  it("reads the comma-separated list, trimming each name", () => {
    process.env[VARIABLE] = "ssh-live, two-uid ,docker";
    expect(tierRequired("two-uid")).toBe(true);
    expect(tierRequired("docker")).toBe(true);
    expect(tierRequired("keyring")).toBe(false);
  });

  it("requires nothing where the variable is unset", () => {
    Reflect.deleteProperty(process.env, VARIABLE);
    expect(tierRequired("two-uid")).toBe(false);
  });

  it("fails a required tier whose probe failed, naming the tier and the cause", () => {
    process.env[VARIABLE] = "docker";
    expect(() => assertTierAvailable("docker", false, new Error("no daemon"))).toThrow(
      /demands the "docker" tier but its probe failed: Error: no daemon/,
    );
  });

  it("lets an unrequired tier skip and passes a required one that is available", () => {
    process.env[VARIABLE] = "two-uid";
    expect(() => assertTierAvailable("docker", false)).not.toThrow();
    expect(() => assertTierAvailable("two-uid", true)).not.toThrow();
  });
});
