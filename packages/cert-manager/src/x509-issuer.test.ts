import { createHash, createPrivateKey, X509Certificate } from "node:crypto";
import { once } from "node:events";
import { connect, createServer } from "node:tls";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import {
  caSigner,
  createCa,
  hostPermitted,
  issueLeaf,
  MAX_UNCONSTRAINED_CA_DAYS,
  normalizeHost,
} from "./x509-issuer.js";
import type { CaMaterial, LeafCertificate } from "./x509-issuer.js";
import { expectVaultError } from "@harpoc/test-utils";

const DAY_MS = 86_400_000;
const NOW = new Date("2026-11-09T12:00:00Z");
const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");
const derHex = (pem: string) => hex(new X509Certificate(pem).raw);
const zeros = (n: number) => "00".repeat(n);
const validFrom = (cert: X509Certificate) => new Date(cert.validFrom).getTime();
const validTo = (cert: X509Certificate) => new Date(cert.validTo).getTime();
const LOCALHOST_HEX = Buffer.from("localhost").toString("hex");

/** SHA-1 of a P-256 SPKI's uncompressed point -- RFC 5280 4.2.1.2 method 1. */
function keyIdentifierHex(pem: string): string {
  const spki = new X509Certificate(pem).publicKey.export({ type: "spki", format: "der" });
  return createHash("sha1").update(spki.subarray(-65)).digest("hex");
}

/**
 * A TLS handshake against `leaf` (served with the intermediate unless told
 * otherwise) from a client trusting the root (or the intermediate alone):
 * "OK" or the error's code and message.
 */
async function handshake(
  ca: CaMaterial,
  leaf: LeafCertificate,
  servername: string | undefined,
  options: { anchor?: "root" | "intermediate"; serveIntermediate?: boolean } = {},
): Promise<string> {
  const cert = options.serveIntermediate === false ? leaf.certPem : leaf.certPem + ca.certPem;
  const anchor = options.anchor === "intermediate" ? ca.certPem : ca.rootPem;
  const server = createServer({ key: leaf.keyPem, cert }, (socket) => socket.end());
  server.on("tlsClientError", () => undefined);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;
  try {
    return await new Promise<string>((resolve) => {
      const socket = connect({ host: "127.0.0.1", port, servername, ca: [anchor] }, () => {
        socket.destroy();
        resolve("OK");
      });
      socket.setTimeout(5_000, () => socket.destroy(new Error("handshake timed out")));
      socket.on("error", (err: NodeJS.ErrnoException) =>
        resolve(`${String(err.code)}: ${err.message}`),
      );
    });
  } finally {
    server.close();
    await once(server, "close");
  }
}

describe("createCa", () => {
  const material = createCa({ permittedHosts: ["localhost"], validityDays: 3650, now: NOW });
  const ca = new X509Certificate(material.certPem);
  const root = new X509Certificate(material.rootPem);

  it("returns the intermediate, its key and the root, and no root key", () => {
    expect(Object.keys(material).sort()).toEqual(["certPem", "keyPem", "rootPem"]);
    expect(ca.checkPrivateKey(createPrivateKey(material.keyPem))).toBe(true);
    expect(root.checkPrivateKey(createPrivateKey(material.keyPem))).toBe(false);
    expect(material.keyPem.startsWith("-----BEGIN PRIVATE KEY-----")).toBe(true);
  });

  it("is a self-signed root over an intermediate CA it issued", () => {
    expect(root.ca).toBe(true);
    expect(root.subject).toBe(root.issuer);
    expect(root.subject).toMatch(/^CN=Harpoc Egress Proxy Root [0-9a-f]{8}$/);
    expect(root.subject.slice(-8)).toBe(keyIdentifierHex(material.rootPem).slice(0, 8));
    expect(root.verify(root.publicKey)).toBe(true);
    expect(root.checkIssued(root)).toBe(true);
    expect(ca.ca).toBe(true);
    expect(ca.issuer).toBe(root.subject);
    expect(ca.subject).toMatch(/^CN=Harpoc Egress Proxy CA [0-9a-f]{8}$/);
    expect(ca.subject.slice(-8)).toBe(keyIdentifierHex(material.certPem).slice(0, 8));
    expect(ca.checkIssued(root)).toBe(true);
    expect(ca.verify(root.publicKey)).toBe(true);
    expect(ca.verify(ca.publicKey)).toBe(false);
  });

  it("is valid from five minutes before now for validityDays", () => {
    for (const cert of [root, ca]) {
      expect(validFrom(cert)).toBe(NOW.getTime() - 5 * 60_000);
      expect(validTo(cert)).toBe(NOW.getTime() + 3650 * DAY_MS);
    }
  });

  it("draws a 16-octet positive serial", () => {
    expect(ca.serialNumber).toMatch(/^[4-7][0-9A-F]{31}$/);
    expect(root.serialNumber).toMatch(/^[4-7][0-9A-F]{31}$/);
  });

  it("gives the root pathLen 1 and the intermediate the root's key id as its AKI", () => {
    const rootDer = derHex(material.rootPem);
    expect(rootDer).toContain("30120603551d130101ff040830060101ff020101");
    expect(rootDer).toContain("300e0603551d0f0101ff040403020106");
    expect(rootDer).toContain(`301d0603551d0e04160414${keyIdentifierHex(material.rootPem)}`);
    expect(rootDer).not.toContain("0603551d23");
    expect(derHex(material.certPem)).toContain(
      `301f0603551d23041830168014${keyIdentifierHex(material.rootPem)}`,
    );
  });

  it("carries critical basicConstraints (CA, pathLen 0) and keyUsage (keyCertSign, cRLSign)", () => {
    const der = derHex(material.certPem);
    expect(der).toContain("30120603551d130101ff040830060101ff020100");
    expect(der).toContain("300e0603551d0f0101ff040403020106");
    expect(der).toContain(`301d0603551d0e04160414${keyIdentifierHex(material.certPem)}`);
  });

  it("carries critical nameConstraints permitting the host and excluding every IP address", () => {
    const permitted = `a00d300b8209${LOCALHOST_HEX}`;
    const excluded = `a130300a8708${zeros(8)}30228720${zeros(32)}`;
    for (const pem of [material.certPem, material.rootPem]) {
      expect(derHex(pem)).toContain(`304d0603551d1e0101ff04433041${permitted}${excluded}`);
    }
  });

  it("excludes every DNS name when only IP literals are permitted", () => {
    const ipOnly = createCa({ permittedHosts: ["127.0.0.1"], validityDays: 30, now: NOW });
    for (const pem of [ipOnly.certPem, ipOnly.rootPem]) {
      expect(derHex(pem)).toContain(
        "0603551d1e0101ff04163014a00c300a87087f000001ffffffffa10430028200",
      );
    }
  });

  it("encodes an IPv6 entry as address plus a 128-bit mask and a DNS entry beside it", () => {
    const both = createCa({ permittedHosts: ["LocalHost", "::1"], validityDays: 30, now: NOW });
    expect(derHex(both.certPem)).toContain(
      `a031300b8209${LOCALHOST_HEX}30228720${zeros(15)}01${"ff".repeat(16)}`,
    );
    expect(derHex(both.certPem)).not.toContain("a130");
  });

  it("writes GeneralizedTime for a notAfter from 2050 on (RFC 5280 4.1.2.5)", () => {
    const late = createCa({
      permittedHosts: ["localhost"],
      validityDays: 3650,
      now: new Date("2045-06-01T00:00:00Z"),
    });
    const cert = new X509Certificate(late.certPem);
    expect(new Date(validTo(cert)).toISOString()).toBe("2055-05-30T00:00:00.000Z");
    expect(derHex(late.certPem)).toContain(`180f${Buffer.from("20550530000000Z").toString("hex")}`);
    expect(derHex(late.certPem)).toContain(`170d${Buffer.from("450531235500Z").toString("hex")}`);
  });

  it("takes a commonName when given", () => {
    const named = createCa({
      permittedHosts: ["localhost"],
      validityDays: 1,
      commonName: "Test CA",
    });
    expect(new X509Certificate(named.certPem).subject).toBe("CN=Test CA");
  });

  it("builds the unconstrained fallback without the nameConstraints extension", () => {
    const fallback = createCa({ permittedHosts: [], unconstrained: true, validityDays: 7 });
    const cert = new X509Certificate(fallback.certPem);
    expect(cert.ca).toBe(true);
    expect(cert.checkIssued(new X509Certificate(fallback.rootPem))).toBe(true);
    expect(derHex(fallback.certPem)).not.toContain("0603551d1e");
    expect(derHex(fallback.rootPem)).not.toContain("0603551d1e");
  });

  it("refuses inputs that cannot make a CA", async () => {
    const base = { permittedHosts: ["localhost"], validityDays: 1 };
    await expectVaultError(
      () => createCa({ ...base, permittedHosts: [] }),
      ErrorCode.INVALID_INPUT,
    );
    await expectVaultError(() => createCa({ ...base, validityDays: 0 }), ErrorCode.INVALID_INPUT);
    await expectVaultError(() => createCa({ ...base, validityDays: 1.5 }), ErrorCode.INVALID_INPUT);
    await expectVaultError(() => createCa({ ...base, commonName: "" }), ErrorCode.INVALID_INPUT);
    await expectVaultError(
      () => createCa({ ...base, unconstrained: true }),
      ErrorCode.INVALID_INPUT,
    );
    await expectVaultError(
      () =>
        createCa({
          permittedHosts: [],
          unconstrained: true,
          validityDays: MAX_UNCONSTRAINED_CA_DAYS + 1,
        }),
      ErrorCode.INVALID_INPUT,
    );
    for (const host of [
      "",
      "exa mple.com",
      "-a.example",
      "a..example",
      "example.",
      "ä.example",
      "\u212Aocalhost",
    ]) {
      await expectVaultError(
        () => createCa({ ...base, permittedHosts: [host] }),
        ErrorCode.INVALID_INPUT,
      );
    }
    for (const host of ["fe80::1%eth0", "[::1]", "localhost:443", "*.example"]) {
      await expectVaultError(
        () => createCa({ ...base, permittedHosts: [host] }),
        ErrorCode.INVALID_INPUT,
      );
    }
  });
});

describe("issueLeaf", () => {
  const material = createCa({ permittedHosts: ["localhost", "127.0.0.1"], validityDays: 3650 });
  const signer = caSigner(material);
  const ca = new X509Certificate(material.certPem);

  it("issues a DNS leaf that parses, chains to the CA and matches its host", () => {
    const leaf = issueLeaf(signer, { host: "localhost", validityMs: 7 * DAY_MS, now: NOW });
    const cert = new X509Certificate(leaf.certPem);
    expect(cert.subject).toBe("CN=localhost");
    expect(cert.issuer).toBe(ca.subject);
    expect(cert.subjectAltName).toBe("DNS:localhost");
    expect(cert.ca).toBe(false);
    expect(cert.keyUsage).toEqual(["1.3.6.1.5.5.7.3.1"]);
    expect(cert.checkIssued(ca)).toBe(true);
    expect(cert.verify(ca.publicKey)).toBe(true);
    expect(cert.checkIssued(new X509Certificate(material.rootPem))).toBe(false);
    expect(cert.checkHost("localhost")).toBe("localhost");
    expect(cert.checkHost("other.localhost")).toBeUndefined();
    expect(cert.checkPrivateKey(createPrivateKey(leaf.keyPem))).toBe(true);
    expect(validFrom(cert)).toBe(NOW.getTime() - 5 * 60_000);
    expect(leaf.notAfter.getTime()).toBe(NOW.getTime() + 7 * DAY_MS);
    expect(validTo(cert)).toBe(leaf.notAfter.getTime());
  });

  it("carries the leaf extensions: CA:FALSE and digitalSignature critical, the CA's key id", () => {
    const leaf = issueLeaf(signer, { host: "localhost", validityMs: DAY_MS });
    const der = derHex(leaf.certPem);
    expect(der).toContain("300c0603551d130101ff04023000");
    expect(der).toContain("300e0603551d0f0101ff040403020780");
    expect(der).toContain("30130603551d25040c300a06082b06010505070301");
    expect(der).toContain(`301f0603551d23041830168014${keyIdentifierHex(material.certPem)}`);
  });

  it("issues an IP leaf with an iPAddress SAN and no commonName", () => {
    const leaf = issueLeaf(signer, { host: "127.0.0.1", validityMs: DAY_MS });
    const cert = new X509Certificate(leaf.certPem);
    expect(cert.subject).toBe("O=Harpoc Egress Proxy");
    expect(cert.subjectAltName).toBe("IP Address:127.0.0.1");
    expect(cert.checkIP("127.0.0.1")).toBe("127.0.0.1");
    const v6 = new X509Certificate(issueLeaf(signer, { host: "::1", validityMs: DAY_MS }).certPem);
    expect(v6.checkIP("::1")).toBe("::1");
    expect(v6.subjectAltName).toBe("IP Address:0:0:0:0:0:0:0:1");
  });

  it("signs a leaf for a host outside the constraints -- the constraint is a chain rule, not a signature rule", () => {
    const cert = new X509Certificate(
      issueLeaf(signer, { host: "evil.example", validityMs: DAY_MS }).certPem,
    );
    expect(cert.verify(ca.publicKey)).toBe(true);
    expect(cert.checkIssued(ca)).toBe(true);
  });

  it("caps a leaf's notAfter at the CA's", () => {
    const leaf = issueLeaf(signer, { host: "localhost", validityMs: 4000 * DAY_MS });
    expect(leaf.notAfter.getTime()).toBe(signer.notAfter.getTime());
  });

  it("refuses a bad host, a non-positive validity and an expired CA", async () => {
    for (const host of ["", "a b", "fe80::1%1", "[::1]", "ä.example", "\u212Aocalhost"]) {
      await expectVaultError(
        () => issueLeaf(signer, { host, validityMs: DAY_MS }),
        ErrorCode.INVALID_INPUT,
      );
    }
    await expectVaultError(
      () => issueLeaf(signer, { host: "localhost", validityMs: 0 }),
      ErrorCode.INVALID_INPUT,
    );
    await expectVaultError(
      () =>
        issueLeaf(signer, {
          host: "localhost",
          validityMs: DAY_MS,
          now: new Date(signer.notAfter.getTime()),
        }),
      ErrorCode.CERT_EXPIRED,
    );
  });
});

describe("caSigner", () => {
  const material = createCa({ permittedHosts: ["localhost"], validityDays: 30 });

  it("takes the CA key as bytes and keeps signing after the caller wipes them", () => {
    const keyBytes = Buffer.from(material.keyPem);
    const signer = caSigner({ certPem: material.certPem, keyPem: keyBytes });
    keyBytes.fill(0);
    const leaf = new X509Certificate(
      issueLeaf(signer, { host: "localhost", validityMs: DAY_MS }).certPem,
    );
    expect(leaf.checkIssued(new X509Certificate(material.certPem))).toBe(true);
  });

  it("refuses a certificate that is not a CA, a mismatched key and unparseable PEMs", async () => {
    const leaf = issueLeaf(caSigner(material), { host: "localhost", validityMs: DAY_MS });
    const other = createCa({ permittedHosts: ["localhost"], validityDays: 30 });
    await expectVaultError(
      () => caSigner({ certPem: leaf.certPem, keyPem: leaf.keyPem }),
      ErrorCode.CERT_INVALID,
    );
    await expectVaultError(
      () => caSigner({ certPem: material.certPem, keyPem: other.keyPem }),
      ErrorCode.CERT_PRIVATE_KEY_MISMATCH,
    );
    await expectVaultError(
      () => caSigner({ certPem: "not a pem", keyPem: material.keyPem }),
      ErrorCode.CERT_INVALID,
    );
    await expectVaultError(
      () => caSigner({ certPem: material.certPem, keyPem: "not a pem" }),
      ErrorCode.CERT_INVALID,
    );
  });
});

describe("the constraints as Node's TLS client enforces them", () => {
  const dnsCa = createCa({ permittedHosts: ["localhost"], validityDays: 3650 });
  const dnsSigner = caSigner(dnsCa);
  const ipCa = createCa({ permittedHosts: ["127.0.0.1"], validityDays: 3650 });
  const ipSigner = caSigner(ipCa);
  const week = 7 * DAY_MS;

  it("accepts a leaf for a permitted host", async () => {
    const leaf = issueLeaf(dnsSigner, { host: "localhost", validityMs: week });
    expect(await handshake(dnsCa, leaf, "localhost")).toBe("OK");
  });

  it("refuses a leaf for a host outside the permitted subtrees", async () => {
    const leaf = issueLeaf(dnsSigner, { host: "evil.example", validityMs: week });
    expect(await handshake(dnsCa, leaf, "evil.example")).toBe(
      "UNSPECIFIED: permitted subtree violation",
    );
  });

  it("refuses an IP leaf under a CA that permits DNS names only", async () => {
    const leaf = issueLeaf(dnsSigner, { host: "127.0.0.1", validityMs: week });
    expect(await handshake(dnsCa, leaf, undefined)).toBe("UNSPECIFIED: excluded subtree violation");
  });

  it("accepts a permitted IP leaf and refuses another address and any DNS leaf", async () => {
    const permitted = issueLeaf(ipSigner, { host: "127.0.0.1", validityMs: week });
    expect(await handshake(ipCa, permitted, undefined)).toBe("OK");
    const dns = issueLeaf(ipSigner, { host: "localhost", validityMs: week });
    expect(await handshake(ipCa, dns, "localhost")).toBe("UNSPECIFIED: excluded subtree violation");
  });

  it("needs the intermediate served after the leaf", async () => {
    const leaf = issueLeaf(dnsSigner, { host: "localhost", validityMs: week });
    expect(await handshake(dnsCa, leaf, "localhost", { serveIntermediate: false })).toMatch(
      /^UNABLE_TO_VERIFY_LEAF_SIGNATURE: /,
    );
  });

  it("does not take the intermediate alone as a trust anchor", async () => {
    const leaf = issueLeaf(dnsSigner, { host: "localhost", validityMs: week });
    expect(await handshake(dnsCa, leaf, "localhost", { anchor: "intermediate" })).toMatch(
      /^UNABLE_TO_GET_ISSUER_CERT: unable to get issuer certificate/,
    );
  });

  it("accepts any host under the unconstrained fallback", async () => {
    const fallback = createCa({ permittedHosts: [], unconstrained: true, validityDays: 7 });
    const leaf = issueLeaf(caSigner(fallback), { host: "evil.example", validityMs: week });
    expect(await handshake(fallback, leaf, "evil.example")).toBe("OK");
  });
});

describe("hostPermitted", () => {
  it("permits the host itself and its subdomains, case-insensitively", () => {
    expect(hostPermitted(["example.com"], "example.com")).toBe(true);
    expect(hostPermitted(["example.com"], "API.Example.com")).toBe(true);
    expect(hostPermitted(["Example.COM"], "a.b.example.com")).toBe(true);
    expect(hostPermitted(["example.com"], "evilexample.com")).toBe(false);
    expect(hostPermitted(["api.example.com"], "example.com")).toBe(false);
  });

  it("permits an IP only when it equals an entry, in either IPv6 spelling", () => {
    expect(hostPermitted(["127.0.0.1"], "127.0.0.1")).toBe(true);
    expect(hostPermitted(["127.0.0.1"], "127.0.0.2")).toBe(false);
    expect(hostPermitted(["::1"], "0:0:0:0:0:0:0:1")).toBe(true);
    expect(hostPermitted(["localhost"], "127.0.0.1")).toBe(false);
    expect(hostPermitted(["127.0.0.1"], "localhost")).toBe(false);
  });

  it("permits nothing unparseable", () => {
    expect(hostPermitted(["localhost"], "")).toBe(false);
    expect(hostPermitted(["localhost"], "local host")).toBe(false);
    expect(hostPermitted(["bad entry"], "localhost")).toBe(false);
  });

  it("normalizes a host the way the issuer encodes it", () => {
    expect(normalizeHost("LocalHost")).toBe("localhost");
    expect(normalizeHost("0:0:0:0:0:0:0:1")).toBe("::1");
    expect(normalizeHost("::ffff:127.0.0.1")).toBe("::ffff:7f00:1");
  });
});
