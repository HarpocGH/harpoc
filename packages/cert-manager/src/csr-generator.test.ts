import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicKey, createVerify, generateKeyPairSync } from "node:crypto";
import { ErrorCode } from "@harpoc/shared";
import { buildCsr } from "./csr-generator.js";
import { generateCertKeyPair } from "./key-pair.js";

/*
 * The golden fixtures were produced once with OpenSSL 3.5.3 and are committed:
 *
 *   openssl genrsa -out csr-fixture-key.pem 2048
 *   openssl req -new -key csr-fixture-key.pem -out csr-fixture.pem -utf8 \
 *     -subj "/CN=golden.example.com" \
 *     -addext "subjectAltName=DNS:golden.example.com,DNS:www.golden.example.com,IP:203.0.113.7"
 *
 * (CRLF stripped afterwards so the fixtures match the LF fixtures already in
 * this directory.) `openssl asn1parse -in csr-fixture.pem` shows the subject as
 * UTF8STRING, so the byte-for-byte comparison below holds without any
 * structural fallback. RSA PKCS#1 v1.5 signing is deterministic, which is what
 * makes a whole-CSR byte compare possible.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__", "certs");
const fx = (n: string): string => readFileSync(join(FIXTURES, n), "utf8");
const hex = (u: Uint8Array): string => Buffer.from(u).toString("hex");
const csrFailed = expect.objectContaining({ code: ErrorCode.CERT_CSR_FAILED });

function topLevelChildren(der: Uint8Array): Uint8Array[] {
  const children: Uint8Array[] = [];
  const outerLen = der[1] as number;
  let i = 1 + (outerLen < 0x80 ? 1 : 1 + (outerLen & 0x7f));
  while (i < der.length) {
    const start = i;
    const lb = der[start + 1] as number;
    const hl = lb < 0x80 ? 2 : 2 + (lb & 0x7f);
    const cl =
      lb < 0x80
        ? lb
        : Number(
            Buffer.from(der.slice(start + 2, start + 2 + (lb & 0x7f))).readUIntBE(0, lb & 0x7f),
          );
    children.push(der.slice(start, start + hl + cl));
    i = start + hl + cl;
  }
  return children;
}

function signatureBytes(der: Uint8Array): Uint8Array {
  const bitString = topLevelChildren(der)[2] as Uint8Array;
  const lb = bitString[1] as number;
  const hl = lb < 0x80 ? 2 : 2 + (lb & 0x7f);
  return bitString.slice(hl + 1);
}

describe("buildCsr", () => {
  it("byte-matches the openssl golden CSR for the fixed RSA key (utf8 subject)", () => {
    const { der, pem } = buildCsr({
      privateKeyPem: fx("csr-fixture-key.pem"),
      commonName: "golden.example.com",
      sans: ["golden.example.com", "www.golden.example.com", "203.0.113.7"],
    });
    const goldenB64 = fx("csr-fixture.pem").replace(/-----[^-]+-----|\s/g, "");
    expect(Buffer.from(der).toString("base64")).toBe(goldenB64);
    expect(pem).toContain("BEGIN CERTIFICATE REQUEST");
    expect(pem.replace(/\r\n/g, "\n")).toBe(fx("csr-fixture.pem").replace(/\r\n/g, "\n"));
  });

  it("embeds the key's exact SPKI", () => {
    const { privateKeyPem, publicKeyPem } = generateCertKeyPair({ algorithm: "ec" });
    const { der } = buildCsr({ privateKeyPem, commonName: "spki.example.com" });
    const spki = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
    expect(Buffer.from(der).includes(spki)).toBe(true);
  });

  it("produces a verifiable signature over the TBS (RSA and EC)", () => {
    for (const algorithm of ["rsa", "ec"] as const) {
      const { privateKeyPem, publicKeyPem } = generateCertKeyPair({ algorithm });
      const { der } = buildCsr({ privateKeyPem, commonName: "sig.example.com" });
      const tbs = topLevelChildren(der)[0] as Uint8Array;
      const verified = createVerify("sha256")
        .update(tbs)
        .verify(publicKeyPem, Buffer.from(signatureBytes(der)));
      expect(verified).toBe(true);
    }
  });

  it("uses sha256WithRSAEncryption with NULL params for RSA and bare ecdsa-with-SHA256 for EC", () => {
    const rsa = generateCertKeyPair({ algorithm: "rsa" });
    const ec = generateCertKeyPair({ algorithm: "ec" });
    const rsaAlg = topLevelChildren(
      buildCsr({ privateKeyPem: rsa.privateKeyPem, commonName: "a.example.com" }).der,
    )[1] as Uint8Array;
    const ecAlg = topLevelChildren(
      buildCsr({ privateKeyPem: ec.privateKeyPem, commonName: "a.example.com" }).der,
    )[1] as Uint8Array;
    expect(hex(rsaAlg)).toBe("300d06092a864886f70d01010b0500");
    expect(hex(ecAlg)).toBe("300a06082a8648ce3d040302");
  });

  it("encodes IPv6 SANs as 16-byte iPAddress entries, compressed forms included", () => {
    const { privateKeyPem } = generateCertKeyPair({ algorithm: "ec" });
    const { der } = buildCsr({
      privateKeyPem,
      commonName: "v6.example.com",
      sans: ["::1", "2001:db8::7", "fe80::", "::ffff:192.0.2.1"],
    });
    const body = hex(der);
    expect(body).toContain("871000000000000000000000000000000001");
    expect(body).toContain("871020010db8000000000000000000000007");
    expect(body).toContain("8710fe800000000000000000000000000000");
    expect(body).toContain("871000000000000000000000ffffc0000201");
  });

  it("refuses an IPv6 SAN whose groups are not representable", () => {
    const { privateKeyPem } = generateCertKeyPair({ algorithm: "ec" });
    expect(() =>
      buildCsr({ privateKeyPem, commonName: "v6.example.com", sans: ["fe80::%eth0"] }),
    ).toThrow(csrFailed);
  });

  it("omits the extensionRequest attribute entirely when no SANs are given", () => {
    const { privateKeyPem } = generateCertKeyPair({ algorithm: "ec" });
    const { der } = buildCsr({ privateKeyPem, commonName: "bare.example.com" });
    const tbs = hex(topLevelChildren(der)[0] as Uint8Array);
    expect(tbs).not.toContain("06092a864886f70d01090e");
    expect(tbs.endsWith("a000")).toBe(true);
  });

  it("rejects an unparseable private key, an unsupported key type and a non-ASCII SAN", () => {
    expect(() => buildCsr({ privateKeyPem: "not a pem", commonName: "x.example.com" })).toThrow(
      csrFailed,
    );
    const { privateKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    expect(() => buildCsr({ privateKeyPem: privateKey, commonName: "x.example.com" })).toThrow(
      csrFailed,
    );
    const { privateKeyPem } = generateCertKeyPair({ algorithm: "ec" });
    expect(() =>
      buildCsr({ privateKeyPem, commonName: "x.example.com", sans: ["schön.example.com"] }),
    ).toThrow(csrFailed);
  });
});
