import { describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import {
  derBitString,
  derBoolean,
  derContext,
  derGeneralizedTime,
  derIa5String,
  derInteger,
  derIntegerFromBytes,
  derNamedBitString,
  derNull,
  derOctetString,
  derOid,
  derPrintableString,
  derSequence,
  derSet,
  derTime,
  derUtcTime,
  derUtf8String,
} from "./der.js";

const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");
const csrFailed = expect.objectContaining({ code: ErrorCode.CERT_CSR_FAILED });

describe("der primitives", () => {
  it("encodes INTEGER 0 and 127 and 128 (leading-zero rule)", () => {
    expect(hex(derInteger(0))).toBe("020100");
    expect(hex(derInteger(127))).toBe("02017f");
    expect(hex(derInteger(128))).toBe("02020080");
  });
  it("encodes OID 2.5.4.3 (commonName) and 1.2.840.113549.1.1.11 (sha256WithRSA)", () => {
    expect(hex(derOid("2.5.4.3"))).toBe("0603550403");
    expect(hex(derOid("1.2.840.113549.1.1.11"))).toBe("06092a864886f70d01010b");
  });
  it("encodes NULL, UTF8String, PrintableString, OCTET STRING", () => {
    expect(hex(derNull())).toBe("0500");
    expect(hex(derUtf8String("ab"))).toBe("0c026162");
    expect(hex(derPrintableString("ab"))).toBe("13026162");
    expect(hex(derOctetString(new Uint8Array([1, 2])))).toBe("04020102");
  });
  it("encodes BIT STRING with zero unused bits prefix", () => {
    expect(hex(derBitString(new Uint8Array([0xff])))).toBe("030200ff");
  });
  it("uses long-form length above 127 bytes", () => {
    const long = derOctetString(new Uint8Array(200));
    expect(hex(long).startsWith("0481c8")).toBe(true);
  });
  it("encodes SEQUENCE and context tags", () => {
    expect(hex(derSequence([derInteger(1)]))).toBe("3003020101");
    expect(hex(derContext(0, true, derInteger(1)))).toBe("a003020101");
    expect(hex(derContext(2, false, new Uint8Array([0x61])))).toBe("820161");
  });
  it("encodes BOOLEAN, IA5String and SET", () => {
    expect(hex(derBoolean(true))).toBe("0101ff");
    expect(hex(derBoolean(false))).toBe("010100");
    expect(hex(derIa5String("ab"))).toBe("16026162");
    expect(hex(derSet([derInteger(1)]))).toBe("3103020101");
  });
});

describe("der out-of-range inputs", () => {
  it("rejects negative and non-integer INTEGER values", () => {
    expect(() => derInteger(-1)).toThrow(csrFailed);
    expect(() => derInteger(1.5)).toThrow(csrFailed);
  });
  it("rejects malformed OIDs and oversized arcs", () => {
    expect(() => derOid("2")).toThrow(csrFailed);
    expect(() => derOid("1.x.3")).toThrow(csrFailed);
    expect(() => derOid("3.5.4")).toThrow(csrFailed);
    expect(() => derOid("1.40.3")).toThrow(csrFailed);
    expect(() => derOid("1.2.2147483648")).toThrow(csrFailed);
  });
  it("rejects context tag numbers above 30", () => {
    expect(() => derContext(31, false, new Uint8Array(0))).toThrow(csrFailed);
    expect(() => derContext(-1, false, new Uint8Array(0))).toThrow(csrFailed);
  });
  it("rejects characters outside the PrintableString and IA5String sets", () => {
    expect(() => derPrintableString("a_b")).toThrow(csrFailed);
    expect(() => derIa5String("ä")).toThrow(csrFailed);
    expect(() => derUtf8String("ä")).not.toThrow();
  });
});

describe("der X.509 primitives", () => {
  it("encodes a positive INTEGER from a big-endian magnitude, minimal and sign-safe", () => {
    expect(hex(derIntegerFromBytes(Uint8Array.of(0x01, 0x02)))).toBe("02020102");
    expect(hex(derIntegerFromBytes(Uint8Array.of(0x00, 0x00, 0x7f)))).toBe("02017f");
    expect(hex(derIntegerFromBytes(Uint8Array.of(0x80, 0x01)))).toBe("0203008001");
    expect(hex(derIntegerFromBytes(Uint8Array.of(0x00)))).toBe("020100");
  });
  it("encodes a BIT STRING with unused bits", () => {
    expect(hex(derBitString(Uint8Array.of(0x06), 1))).toBe("03020106");
    expect(hex(derBitString(Uint8Array.of(0x80), 7))).toBe("03020780");
    expect(hex(derBitString(new Uint8Array(0)))).toBe("030100");
  });
  it("encodes KeyUsage named bits with the trailing zero bits dropped", () => {
    expect(hex(derNamedBitString([5, 6]))).toBe("03020106");
    expect(hex(derNamedBitString([0]))).toBe("03020780");
    expect(hex(derNamedBitString([0, 8]))).toBe("0303078080");
    expect(hex(derNamedBitString([]))).toBe("030100");
  });
  it("encodes UTCTime and GeneralizedTime in RFC 5280's Z forms", () => {
    const text = (u: Uint8Array) => Buffer.from(u.subarray(2)).toString("ascii");
    const before = new Date("2049-12-31T23:59:59.999Z");
    const after = new Date("2050-01-01T00:00:00Z");
    expect(hex(derUtcTime(before)).slice(0, 4)).toBe("170d");
    expect(text(derUtcTime(before))).toBe("491231235959Z");
    expect(hex(derGeneralizedTime(after)).slice(0, 4)).toBe("180f");
    expect(text(derGeneralizedTime(after))).toBe("20500101000000Z");
    expect(derTime(before)).toEqual(derUtcTime(before));
    expect(derTime(after)).toEqual(derGeneralizedTime(after));
    expect(text(derTime(new Date("1950-01-01T00:00:00Z")))).toBe("500101000000Z");
  });
});

describe("der X.509 out-of-range inputs", () => {
  it("rejects an empty INTEGER magnitude", () => {
    expect(() => derIntegerFromBytes(new Uint8Array(0))).toThrow(csrFailed);
  });
  it("rejects a bad unused-bit count and set padding bits", () => {
    expect(() => derBitString(Uint8Array.of(0x80), 8)).toThrow(csrFailed);
    expect(() => derBitString(Uint8Array.of(0x80), -1)).toThrow(csrFailed);
    expect(() => derBitString(new Uint8Array(0), 1)).toThrow(csrFailed);
    expect(() => derBitString(Uint8Array.of(0x81), 1)).toThrow(csrFailed);
  });
  it("rejects named bits out of range", () => {
    expect(() => derNamedBitString([-1])).toThrow(csrFailed);
    expect(() => derNamedBitString([64])).toThrow(csrFailed);
    expect(() => derNamedBitString([1.5])).toThrow(csrFailed);
  });
  it("rejects UTCTime outside 1950-2049 and unrepresentable dates", () => {
    expect(() => derUtcTime(new Date("2050-01-01T00:00:00Z"))).toThrow(csrFailed);
    expect(() => derUtcTime(new Date("1949-12-31T23:59:59Z"))).toThrow(csrFailed);
    expect(() => derGeneralizedTime(new Date(Number.NaN))).toThrow(csrFailed);
    expect(() => derTime(new Date("+010000-01-01T00:00:00Z"))).toThrow(csrFailed);
  });
});
