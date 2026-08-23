import { describe, expect, it } from "vitest";
import { decodeJwtClaims } from "./jwt-claims";

const b64url = (text: string): string =>
  btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const jwt = (payload: unknown): string =>
  `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url(JSON.stringify(payload))}.signature`;

describe("decodeJwtClaims", () => {
  it("reads jti, sub, exp and principal_type off a three-segment token", () => {
    const claims = decodeJwtClaims(
      jwt({ jti: "jti-1", sub: "ci-bot", exp: 1700000000, principal_type: "user" }),
    );
    expect(claims).toEqual({
      jti: "jti-1",
      sub: "ci-bot",
      exp: 1700000000,
      principal_type: "user",
    });
  });

  it("omits an absent principal_type — the CLI default the caller applies", () => {
    expect(decodeJwtClaims(jwt({ sub: "ci-bot" }))).toEqual({ sub: "ci-bot" });
  });

  it("decodes the base64url alphabet, not plain base64", () => {
    // `{"jti":"a>b?c~d"}` encodes to a segment carrying `_` — a plain `atob`
    // over it either throws or decodes to the wrong bytes.
    const token = jwt({ jti: "a>b?c~d" });
    expect(token.split(".")[1]).toContain("_");
    expect(decodeJwtClaims(token)?.jti).toBe("a>b?c~d");
  });

  it("decodes a UTF-8 payload rather than its latin-1 bytes", () => {
    const payload = "eyJqdGkiOiJqdGktw7wtMSIsInN1YiI6ImNpLWJvdCJ9";
    expect(decodeJwtClaims(`header.${payload}.sig`)?.jti).toBe("jti-ü-1");
  });

  it("tolerates an unpadded segment", () => {
    const token = jwt({ jti: "abc" });
    expect(token).not.toContain("=");
    expect(decodeJwtClaims(token)?.jti).toBe("abc");
  });

  it("returns null for garbage", () => {
    expect(decodeJwtClaims("garbage")).toBeNull();
  });

  it("returns null for the wrong segment count", () => {
    expect(decodeJwtClaims(`${b64url('{"jti":"x"}')}.${b64url('{"jti":"x"}')}`)).toBeNull();
    expect(decodeJwtClaims(`a.${b64url('{"jti":"x"}')}.c.d`)).toBeNull();
  });

  it("returns null for an empty payload segment", () => {
    expect(decodeJwtClaims("header..signature")).toBeNull();
  });

  it("returns null when the payload segment is not base64", () => {
    expect(decodeJwtClaims("header.!!!!.signature")).toBeNull();
  });

  it("returns null when the payload is not JSON", () => {
    expect(decodeJwtClaims(`header.${b64url("not json at all")}.sig`)).toBeNull();
  });

  it("returns null when the payload is a JSON scalar, null or array", () => {
    expect(decodeJwtClaims(`header.${b64url("123")}.sig`)).toBeNull();
    expect(decodeJwtClaims(`header.${b64url('"jti-1"')}.sig`)).toBeNull();
    expect(decodeJwtClaims(`header.${b64url("null")}.sig`)).toBeNull();
    expect(decodeJwtClaims(`header.${b64url('["jti-1"]')}.sig`)).toBeNull();
  });

  it("omits a claim carrying the wrong type rather than reporting it", () => {
    // The jti is compared against a registry row's `jti` string; a number that
    // typechecks as a string is a lie the comparison would silently lose.
    expect(decodeJwtClaims(jwt({ jti: 7, sub: null, exp: "soon", principal_type: 3 }))).toEqual({});
  });

  it("returns the empty claim set for a payload carrying none of the four", () => {
    expect(decodeJwtClaims(jwt({ scope: ["read"] }))).toEqual({});
  });

  it("verifies nothing — an unsigned-looking token still decodes", () => {
    expect(decodeJwtClaims(`header.${b64url('{"jti":"j"}')}.`)).toEqual({ jti: "j" });
  });
});
