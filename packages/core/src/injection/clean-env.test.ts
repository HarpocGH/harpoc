import { describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { buildCleanEnv } from "./clean-env.js";
import { expectVaultError } from "@harpoc/test-utils";

const VALUE = "S3CRET-TOKEN-xyz";

describe("buildCleanEnv refuses an env_var a plain object cannot hold (S11)", () => {
  it("refuses __proto__ INVALID_INJECTION_CONFIG with a value-free message", async () => {
    const err = await expectVaultError(
      () => buildCleanEnv("__proto__", VALUE, []),
      ErrorCode.INVALID_INJECTION_CONFIG,
    );
    expect(err.message).toBe("environment variable name must not be __proto__");
  });

  it.each(["constructor", "prototype", "__PROTO__", "__proto__x", "x__proto__"])(
    "writes %s as an own variable carrying the value (control)",
    (name) => {
      const env = buildCleanEnv(name, VALUE, []);
      expect(Object.keys(env).filter((k) => k !== "PATH")).toEqual([name]);
      expect(env[name]).toBe(VALUE);
    },
  );
});
