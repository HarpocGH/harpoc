import { describe, it, expect } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import {
  parseAlgorithm,
  parseBits,
  parseCurve,
  assertAlgorithmPairing,
  DEFAULT_KEY_ALGORITHM,
} from "./key-algorithm-options.js";
import { expectVaultError } from "@harpoc/test-utils";

it("DEFAULT_KEY_ALGORITHM is ec", () => {
  expect(DEFAULT_KEY_ALGORITHM).toBe("ec");
});

describe("parseAlgorithm", () => {
  it("accepts rsa and ec", () => {
    expect(parseAlgorithm("rsa")).toBe("rsa");
    expect(parseAlgorithm("ec")).toBe("ec");
  });

  it("refuses anything else with the value list", () => {
    expect(() => parseAlgorithm("dsa")).toThrow(
      'Invalid algorithm "dsa". Must be one of: rsa, ec.',
    );
  });
});

describe("parseBits", () => {
  it("passes undefined through", () => {
    expect(parseBits(undefined)).toBeUndefined();
  });

  it("accepts 2048 and 4096", () => {
    expect(parseBits("2048")).toBe(2048);
    expect(parseBits("4096")).toBe(4096);
  });

  it("refuses other sizes", () => {
    expect(() => parseBits("1024")).toThrow('Invalid bits "1024". Must be one of: 2048, 4096.');
  });
});

describe("parseCurve", () => {
  it("passes undefined through", () => {
    expect(parseCurve(undefined)).toBeUndefined();
  });

  it("accepts P-256 and P-384", () => {
    expect(parseCurve("P-256")).toBe("P-256");
    expect(parseCurve("P-384")).toBe("P-384");
  });

  it("refuses other curves", () => {
    expect(() => parseCurve("P-521")).toThrow(
      'Invalid curve "P-521". Must be one of: P-256, P-384.',
    );
  });
});

describe("assertAlgorithmPairing", () => {
  it("accepts matched pairs and bare algorithms", () => {
    expect(() => assertAlgorithmPairing("rsa", 4096, undefined)).not.toThrow();
    expect(() => assertAlgorithmPairing("ec", undefined, "P-384")).not.toThrow();
    expect(() => assertAlgorithmPairing("rsa", undefined, undefined)).not.toThrow();
  });

  it("refuses --bits under ec", () => {
    expect(() => assertAlgorithmPairing("ec", 2048, undefined)).toThrow(
      "--bits only applies with --algorithm rsa.",
    );
  });

  it("refuses --curve under rsa", () => {
    expect(() => assertAlgorithmPairing("rsa", undefined, "P-256")).toThrow(
      "--curve only applies with --algorithm ec.",
    );
  });
});

describe("the refusals are INVALID_INPUT, their messages unchanged (T4)", () => {
  it.each([
    {
      label: "parseAlgorithm",
      call: () => parseAlgorithm("dsa"),
      message: 'Invalid algorithm "dsa". Must be one of: rsa, ec.',
    },
    {
      label: "parseBits",
      call: () => parseBits("1024"),
      message: 'Invalid bits "1024". Must be one of: 2048, 4096.',
    },
    {
      label: "parseCurve",
      call: () => parseCurve("P-521"),
      message: 'Invalid curve "P-521". Must be one of: P-256, P-384.',
    },
    {
      label: "assertAlgorithmPairing with --bits under ec",
      call: () => assertAlgorithmPairing("ec", 2048, undefined),
      message: "--bits only applies with --algorithm rsa.",
    },
    {
      label: "assertAlgorithmPairing with --curve under rsa",
      call: () => assertAlgorithmPairing("rsa", undefined, "P-256"),
      message: "--curve only applies with --algorithm ec.",
    },
  ])("$label", async ({ call, message }) => {
    const err = await expectVaultError(call, ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(message);
  });
});
