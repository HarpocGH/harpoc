import { describe, expect, it } from "vitest";
import { toBase64 } from "./encoding";

const decode = (b64: string): string =>
  new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));

describe("toBase64", () => {
  it("encodes an ASCII value the way the API decodes it", () => {
    expect(toBase64("v2-bytes")).toBe("djItYnl0ZXM=");
  });

  it("encodes the empty string", () => {
    expect(toBase64("")).toBe("");
  });

  it("encodes a value that bare btoa cannot", () => {
    // The reason this helper exists: btoa is a Latin-1 byte encoder and throws
    // on any code point above U+00FF, so a passphrase with a check mark in it
    // would be the one value the UI could not deliver.
    expect(() => btoa("pässwörd✓")).toThrow();
    expect(toBase64("pässwörd✓")).toBe("cMOkc3N3w7ZyZOKckw==");
  });

  it("round-trips multi-line and non-Latin1 text as UTF-8", () => {
    // The NUL stays an escape rather than a raw byte: one embedded U+0000 makes
    // git treat this whole file as binary, and an undiffable test file is one
    // nobody can review a change to.
    for (const value of [
      "pässwörd✓",
      "-----BEGIN KEY-----\nline2\n-----END KEY-----",
      "a\u0000b",
    ]) {
      expect(decode(toBase64(value))).toBe(value);
    }
  });
});
