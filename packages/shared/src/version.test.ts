import { describe, expect, it } from "vitest";
import {
  compareVaultVersions,
  isVaultVersionSupported,
  meetsVaultVersionFloor,
} from "./version.js";

describe("isVaultVersionSupported", () => {
  it("accepts an equal version", () => {
    expect(isVaultVersionSupported("1.0.0", "1.0.0")).toBe(true);
  });

  it("accepts older stored versions", () => {
    expect(isVaultVersionSupported("1.0.0", "1.2.0")).toBe(true);
    expect(isVaultVersionSupported("0.9.9", "1.0.0")).toBe(true);
    expect(isVaultVersionSupported("1.1.9", "1.2.0")).toBe(true);
  });

  it("refuses newer stored versions", () => {
    expect(isVaultVersionSupported("1.0.1", "1.0.0")).toBe(false);
    expect(isVaultVersionSupported("2.0.0", "1.9.9")).toBe(false);
    expect(isVaultVersionSupported("1.3.0", "1.2.9")).toBe(false);
  });

  it("refuses a newer version across a digit boundary (differential control vs string compare)", () => {
    // Lexicographically "1.10.0" < "1.2.0" — the naive string compare the
    // helper replaces accepts this newer vault. The helper must refuse it.
    expect("1.10.0" < "1.2.0").toBe(true);
    expect(isVaultVersionSupported("1.10.0", "1.2.0")).toBe(false);
  });

  it("accepts an older version across a digit boundary", () => {
    expect(isVaultVersionSupported("1.2.0", "1.10.0")).toBe(true);
  });

  it("treats missing components as zero", () => {
    expect(isVaultVersionSupported("1.2", "1.2.0")).toBe(true);
    expect(isVaultVersionSupported("1.2.0", "1.2")).toBe(true);
    expect(isVaultVersionSupported("1.2.1", "1.2")).toBe(false);
    expect(isVaultVersionSupported("1", "1.0.0")).toBe(true);
  });

  it("fails closed on malformed stored versions", () => {
    expect(isVaultVersionSupported("banana", "1.0.0")).toBe(false);
    expect(isVaultVersionSupported("1.x.0", "1.0.0")).toBe(false);
    expect(isVaultVersionSupported("", "1.0.0")).toBe(false);
    expect(isVaultVersionSupported("1..0", "1.0.0")).toBe(false);
    expect(isVaultVersionSupported("1.0.0-beta", "1.0.0")).toBe(false);
    expect(isVaultVersionSupported(" 1.0.0", "1.0.0")).toBe(false);
    expect(isVaultVersionSupported("1.0.0 ", "1.0.0")).toBe(false);
  });

  it("fails closed on a malformed supported version", () => {
    expect(isVaultVersionSupported("1.0.0", "garbage")).toBe(false);
  });

  it("handles multi-digit components numerically", () => {
    expect(isVaultVersionSupported("1.9.0", "1.10.0")).toBe(true);
    expect(isVaultVersionSupported("1.11.0", "1.10.0")).toBe(false);
    expect(isVaultVersionSupported("10.0.0", "9.99.99")).toBe(false);
  });
});

describe("compareVaultVersions", () => {
  it("orders numerically per component", () => {
    expect(compareVaultVersions("1.0.0", "1.5.0")).toBe(-1);
    expect(compareVaultVersions("1.5.0", "1.5.0")).toBe(0);
    expect(compareVaultVersions("1.10.0", "1.5.0")).toBe(1);
    expect(compareVaultVersions("1.5", "1.5.0")).toBe(0);
  });

  it("returns null for a malformed side", () => {
    expect(compareVaultVersions("banana", "1.5.0")).toBeNull();
    expect(compareVaultVersions("1.5.0", "")).toBeNull();
  });
});

describe("meetsVaultVersionFloor", () => {
  it("accepts the floor itself and anything above it", () => {
    expect(meetsVaultVersionFloor("1.5.0", "1.5.0")).toBe(true);
    expect(meetsVaultVersionFloor("1.5.3", "1.5.0")).toBe(true);
    expect(meetsVaultVersionFloor("2.0.0", "1.5.0")).toBe(true);
  });

  it("refuses anything below the floor and fails closed on garbage", () => {
    expect(meetsVaultVersionFloor("1.0.0", "1.5.0")).toBe(false);
    expect(meetsVaultVersionFloor("0.9.0", "1.5.0")).toBe(false);
    expect(meetsVaultVersionFloor("banana", "1.5.0")).toBe(false);
    expect(meetsVaultVersionFloor("1.5.0", "banana")).toBe(false);
  });
});
