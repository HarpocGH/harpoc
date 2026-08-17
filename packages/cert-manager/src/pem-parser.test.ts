import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ErrorCode } from "@harpoc/shared";
import { assertKeyMatchesCert, parseCertificate, splitChain } from "./pem-parser.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__", "certs");
const fx = (n: string): string => readFileSync(join(FIXTURES, n), "utf8");

describe("parseCertificate", () => {
  it("extracts subject, dates and SANs", () => {
    const p = parseCertificate(fx("rsa-cert.pem"));
    expect(p.subject).toContain("fixture.example.com");
    expect(p.sans).toEqual(["fixture.example.com", "alt.example.com"]);
    expect(p.notAfter).toBeGreaterThan(p.notBefore);
  });
  it("throws CERT_INVALID on malformed PEM", () => {
    expect(() => parseCertificate("not a pem")).toThrow(
      expect.objectContaining({ code: ErrorCode.CERT_INVALID }),
    );
  });
  it("parses the first block of a raw, un-split two-cert bundle", () => {
    const bundle = fx("rsa-cert.pem") + fx("ec-cert.pem");
    expect(parseCertificate(bundle).subject).toContain("fixture.example.com");
  });
});

describe("splitChain", () => {
  it("splits a two-cert bundle into leaf + chain", () => {
    const bundle = fx("rsa-cert.pem") + fx("ec-cert.pem");
    const { leaf, chain } = splitChain(bundle);
    expect(leaf).toContain("BEGIN CERTIFICATE");
    expect(chain).toContain("BEGIN CERTIFICATE");
    expect(parseCertificate(leaf).subject).toContain("fixture.example.com");
  });
  it("returns null chain for a single cert", () => {
    expect(splitChain(fx("rsa-cert.pem")).chain).toBeNull();
  });
  it("throws CERT_INVALID when no certificate block is found", () => {
    expect(() => splitChain("no pem here")).toThrow(
      expect.objectContaining({ code: ErrorCode.CERT_INVALID }),
    );
  });
});

describe("assertKeyMatchesCert", () => {
  it("passes on a matching pair and throws on mismatch", () => {
    expect(() => assertKeyMatchesCert(fx("rsa-key.pem"), fx("rsa-cert.pem"))).not.toThrow();
    expect(() => assertKeyMatchesCert(fx("other-key.pem"), fx("rsa-cert.pem"))).toThrow(
      expect.objectContaining({ code: ErrorCode.CERT_PRIVATE_KEY_MISMATCH }),
    );
  });
  it("throws CERT_INVALID on a malformed certificate PEM", () => {
    expect(() => assertKeyMatchesCert(fx("rsa-key.pem"), "not a pem")).toThrow(
      expect.objectContaining({ code: ErrorCode.CERT_INVALID }),
    );
  });
});
