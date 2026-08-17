import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { generateCertKeyPair } from "../key-pair.js";
import { jwkThumbprint, publicJwk, signJws } from "./jws.js";

/*
 * RFC 7638 §3.1 verbatim: the example JWK (alg and kid included, both of which
 * the thumbprint must ignore) and the octet-string thumbprint it produces.
 */
const RFC7638_JWK = {
  kty: "RSA",
  n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  e: "AQAB",
  alg: "RS256",
  kid: "2011-04-29",
};
const RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

const acmeFailed = expect.objectContaining({ code: ErrorCode.CERT_ACME_FAILED });

const signingInput = (jws: { protected: string; payload: string }): Buffer =>
  Buffer.from(`${jws.protected}.${jws.payload}`, "ascii");

const decode = (part: string): unknown => JSON.parse(Buffer.from(part, "base64url").toString());

describe("signJws", () => {
  it("signs ES256 as a raw 64-byte r||s pair, not as a DER SEQUENCE", () => {
    const { privateKeyPem, publicKeyPem } = generateCertKeyPair({ algorithm: "ec" });
    const jws = signJws({
      payload: { termsOfServiceAgreed: true },
      protectedHeader: { alg: "ES256", nonce: "n1", url: "https://acme.example.com/new-acct" },
      privateKeyPem,
    });
    const signature = Buffer.from(jws.signature, "base64url");
    expect(signature.length).toBe(64);
    expect(
      verify(
        "sha256",
        signingInput(jws),
        { key: publicKeyPem, dsaEncoding: "ieee-p1363" },
        signature,
      ),
    ).toBe(true);
    expect(verify("sha256", signingInput(jws), publicKeyPem, signature)).toBe(false);
  });

  it("signs RS256 with plain PKCS#1 v1.5 over the same signing input", () => {
    const { privateKeyPem, publicKeyPem } = generateCertKeyPair({ algorithm: "rsa" });
    const jws = signJws({
      payload: { contact: ["mailto:ops@example.com"] },
      protectedHeader: { alg: "RS256", nonce: "n2" },
      privateKeyPem,
    });
    const signature = Buffer.from(jws.signature, "base64url");
    expect(signature.length).toBe(256);
    expect(verify("sha256", signingInput(jws), publicKeyPem, signature)).toBe(true);
  });

  it("emits flattened base64url members that decode back to the header and payload", () => {
    const { privateKeyPem } = generateCertKeyPair({ algorithm: "ec" });
    const protectedHeader = { alg: "ES256", jwk: { kty: "EC" }, nonce: "n3" };
    const payload = { identifiers: [{ type: "dns", value: "a.example.com" }] };
    const jws = signJws({ payload, protectedHeader, privateKeyPem });
    expect(Object.keys(jws).sort()).toEqual(["payload", "protected", "signature"]);
    expect(decode(jws.protected)).toEqual(protectedHeader);
    expect(decode(jws.payload)).toEqual(payload);
    for (const part of [jws.protected, jws.payload, jws.signature]) {
      expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
    }
  });

  it("leaves the payload empty for POST-as-GET rather than encoding a JSON string", () => {
    const { privateKeyPem, publicKeyPem } = generateCertKeyPair({ algorithm: "ec" });
    const jws = signJws({ payload: "", protectedHeader: { alg: "ES256" }, privateKeyPem });
    expect(jws.payload).toBe("");
    expect(jws.payload).not.toBe(Buffer.from('""').toString("base64url"));
    expect(signingInput(jws).toString()).toBe(`${jws.protected}.`);
    expect(
      verify(
        "sha256",
        signingInput(jws),
        { key: publicKeyPem, dsaEncoding: "ieee-p1363" },
        Buffer.from(jws.signature, "base64url"),
      ),
    ).toBe(true);
  });

  it("rejects an unparseable key and an unsupported key type", () => {
    expect(() =>
      signJws({ payload: "", protectedHeader: { alg: "ES256" }, privateKeyPem: "not a pem" }),
    ).toThrow(acmeFailed);
    const { privateKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    expect(() =>
      signJws({ payload: "", protectedHeader: { alg: "EdDSA" }, privateKeyPem: privateKey }),
    ).toThrow(acmeFailed);
  });

  it("refuses a protected header whose alg disagrees with the signing key", () => {
    const ec = generateCertKeyPair({ algorithm: "ec" }).privateKeyPem;
    const rsa = generateCertKeyPair({ algorithm: "rsa" }).privateKeyPem;
    const p384 = generateCertKeyPair({ algorithm: "ec", namedCurve: "P-384" }).privateKeyPem;
    const mismatches: [string, string][] = [
      [ec, "RS256"],
      [ec, "ES384"],
      [rsa, "ES256"],
      [p384, "ES256"],
    ];
    for (const [privateKeyPem, alg] of mismatches) {
      expect(() => signJws({ payload: "", protectedHeader: { alg }, privateKeyPem })).toThrow(
        acmeFailed,
      );
    }
  });

  it("signs each supported curve under its own alg and hash", () => {
    const cases = [
      { namedCurve: "P-256", alg: "ES256", hash: "sha256", length: 64 },
      { namedCurve: "P-384", alg: "ES384", hash: "sha384", length: 96 },
      { namedCurve: "P-521", alg: "ES512", hash: "sha512", length: 132 },
    ];
    for (const { namedCurve, alg, hash, length } of cases) {
      const { privateKey, publicKey } = generateKeyPairSync("ec", {
        namedCurve,
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      });
      const jws = signJws({ payload: {}, protectedHeader: { alg }, privateKeyPem: privateKey });
      const signature = Buffer.from(jws.signature, "base64url");
      expect(signature.length).toBe(length);
      expect(
        verify(hash, signingInput(jws), { key: publicKey, dsaEncoding: "ieee-p1363" }, signature),
      ).toBe(true);
    }
  });

  it("signs with the key's own algorithm when the header declares no alg", () => {
    const { privateKeyPem, publicKeyPem } = generateCertKeyPair({ algorithm: "ec" });
    const jws = signJws({ payload: "", protectedHeader: { nonce: "n4" }, privateKeyPem });
    expect(
      verify(
        "sha256",
        signingInput(jws),
        { key: publicKeyPem, dsaEncoding: "ieee-p1363" },
        Buffer.from(jws.signature, "base64url"),
      ),
    ).toBe(true);
  });

  it("refuses an EC curve that has no JOSE algorithm", () => {
    const { privateKey } = generateKeyPairSync("ec", {
      namedCurve: "secp256k1",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    expect(() => signJws({ payload: "", protectedHeader: {}, privateKeyPem: privateKey })).toThrow(
      acmeFailed,
    );
  });

  it("refuses a header or payload that will not serialize", () => {
    const { privateKeyPem } = generateCertKeyPair({ algorithm: "ec" });
    const circular: Record<string, unknown> = {};
    circular["self"] = circular;
    expect(() =>
      signJws({ payload: circular, protectedHeader: { alg: "ES256" }, privateKeyPem }),
    ).toThrow(acmeFailed);
    expect(() =>
      signJws({ payload: {}, protectedHeader: { alg: "ES256", bad: 1n }, privateKeyPem }),
    ).toThrow(acmeFailed);
    expect(() =>
      signJws({
        payload: { toJSON: () => undefined },
        protectedHeader: { alg: "ES256" },
        privateKeyPem,
      }),
    ).toThrow(acmeFailed);
  });
});

describe("publicJwk", () => {
  it("orders EC members crv,kty,x,y and RSA members e,kty,n", () => {
    const ec = publicJwk(generateCertKeyPair({ algorithm: "ec" }).privateKeyPem);
    const rsa = publicJwk(generateCertKeyPair({ algorithm: "rsa" }).privateKeyPem);
    expect(Object.keys(ec)).toEqual(["crv", "kty", "x", "y"]);
    expect(Object.keys(rsa)).toEqual(["e", "kty", "n"]);
    expect(JSON.stringify(ec)).toBe(
      `{"crv":"P-256","kty":"EC","x":"${ec["x"] ?? ""}","y":"${ec["y"] ?? ""}"}`,
    );
    expect(JSON.stringify(rsa)).toBe(`{"e":"AQAB","kty":"RSA","n":"${rsa["n"] ?? ""}"}`);
  });

  it("carries the curve of a P-384 key", () => {
    const jwk = publicJwk(
      generateCertKeyPair({ algorithm: "ec", namedCurve: "P-384" }).privateKeyPem,
    );
    expect(jwk["crv"]).toBe("P-384");
  });

  it("rejects an unparseable key and an unsupported key type", () => {
    expect(() => publicJwk("not a pem")).toThrow(acmeFailed);
    const { privateKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    expect(() => publicJwk(privateKey)).toThrow(acmeFailed);
  });
});

describe("jwkThumbprint", () => {
  it("matches the RFC 7638 §3.1 RSA vector", () => {
    expect(jwkThumbprint(RFC7638_JWK)).toBe(RFC7638_THUMBPRINT);
  });

  it("hashes the required members only, whatever else the JWK carries", () => {
    const ec = publicJwk(generateCertKeyPair({ algorithm: "ec" }).privateKeyPem);
    const canonical = JSON.stringify({
      crv: ec["crv"],
      kty: ec["kty"],
      x: ec["x"],
      y: ec["y"],
    });
    expect(jwkThumbprint(ec)).toBe(createHash("sha256").update(canonical).digest("base64url"));
    expect(jwkThumbprint({ ...ec, alg: "ES256", kid: "k1", use: "sig" })).toBe(jwkThumbprint(ec));
  });

  it("is insensitive to the member order of the input JWK", () => {
    const { n, kty, e } = RFC7638_JWK;
    expect(jwkThumbprint({ n, e, kty })).toBe(RFC7638_THUMBPRINT);
  });

  it("rejects an unsupported kty and a JWK missing a required member", () => {
    expect(() => jwkThumbprint({ kty: "OKP", crv: "Ed25519", x: "abc" })).toThrow(acmeFailed);
    expect(() => jwkThumbprint({ x: "abc" })).toThrow(acmeFailed);
    expect(() => jwkThumbprint({ kty: "RSA", e: "AQAB" })).toThrow(acmeFailed);
    expect(() => jwkThumbprint({ kty: "constructor" })).toThrow(acmeFailed);
  });

  it("reads own members only, never through the prototype chain", () => {
    const inherited = Object.create({
      kty: "RSA",
      e: "AQAB",
      n: RFC7638_JWK.n,
    }) as Record<string, string>;
    expect(() => jwkThumbprint(inherited)).toThrow(acmeFailed);
    const partial = Object.create({ n: RFC7638_JWK.n }) as Record<string, string>;
    partial["kty"] = "RSA";
    partial["e"] = "AQAB";
    expect(() => jwkThumbprint(partial)).toThrow(acmeFailed);
  });
});
