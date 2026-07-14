import { generateKeyPairSync, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ErrorCode } from "@harpoc/shared";
import { describe, expect, it } from "vitest";
import { loadPrivateKey } from "./key-loader.js";
import { SshReader } from "./ssh-wire.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "__fixtures__", "ssh");
const readFixture = (name: string): string => readFileSync(join(FIXTURES, name), "utf8");
const pubBlob = (name: string): Buffer =>
  Buffer.from(readFixture(`${name}.pub`).trim().split(/\s+/)[1] as string, "base64");

/** Decode an SSH signature blob into its format id and inner bytes. */
function splitSig(sig: Buffer): { format: string; inner: Buffer } {
  const r = new SshReader(sig);
  return { format: r.readCString(), inner: r.readString() };
}

/** Rebuild a fixed-width ieee-p1363 r‖s buffer from the SSH ecdsa inner blob. */
function ecInnerToP1363(inner: Buffer, size: number): Buffer {
  const reader = new SshReader(inner);
  const pad = (b: Buffer): Buffer => Buffer.concat([Buffer.alloc(size - b.length), b]);
  return Buffer.concat([pad(reader.readMpint()), pad(reader.readMpint())]);
}

const CHALLENGE = Buffer.from("harpoc agent challenge bytes");

describe("loadPrivateKey — OpenSSH container format", () => {
  it("loads ed25519, derives the public blob, and signs verifiably", () => {
    const key = loadPrivateKey(readFixture("ed25519_openssh"));
    expect(key.publicKeyBlob).toEqual(pubBlob("ed25519_openssh"));

    const sig = key.sign(CHALLENGE, 0);
    const { format, inner } = splitSig(sig);
    expect(format).toBe("ssh-ed25519");
    const pubPem = pubKeyObjectFromBlob(pubBlob("ed25519_openssh"));
    expect(cryptoVerify(null, CHALLENGE, pubPem, inner)).toBe(true);
  });

  it("loads rsa, honors the SHA-2 sign flags, and signs verifiably", () => {
    const key = loadPrivateKey(readFixture("rsa_openssh"));
    expect(key.publicKeyBlob).toEqual(pubBlob("rsa_openssh"));
    const pub = pubKeyObjectFromBlob(pubBlob("rsa_openssh"));

    const sig256 = splitSig(key.sign(CHALLENGE, 2));
    expect(sig256.format).toBe("rsa-sha2-256");
    expect(cryptoVerify("sha256", CHALLENGE, pub, sig256.inner)).toBe(true);

    const sig512 = splitSig(key.sign(CHALLENGE, 4));
    expect(sig512.format).toBe("rsa-sha2-512");
    expect(cryptoVerify("sha512", CHALLENGE, pub, sig512.inner)).toBe(true);

    // No flag → defaults to sha256, never legacy SHA-1.
    expect(splitSig(key.sign(CHALLENGE, 0)).format).toBe("rsa-sha2-256");
  });

  it.each([
    ["ecdsa256_openssh", "ecdsa-sha2-nistp256", "sha256", 32],
    ["ecdsa384_openssh", "ecdsa-sha2-nistp384", "sha384", 48],
    ["ecdsa521_openssh", "ecdsa-sha2-nistp521", "sha512", 66],
  ])("loads %s, derives the blob, and signs verifiably", (name, format, hash, size) => {
    const key = loadPrivateKey(readFixture(name));
    expect(key.publicKeyBlob).toEqual(pubBlob(name));

    const sig = splitSig(key.sign(CHALLENGE, 0));
    expect(sig.format).toBe(format);
    const p1363 = ecInnerToP1363(sig.inner, size as number);
    const pub = { key: pubKeyObjectFromBlob(pubBlob(name)), dsaEncoding: "ieee-p1363" as const };
    expect(cryptoVerify(hash, CHALLENGE, pub, p1363)).toBe(true);
  });
});

describe("loadPrivateKey — traditional PEM format", () => {
  it("loads a PKCS#1 RSA PEM and matches its .pub blob", () => {
    const key = loadPrivateKey(readFixture("rsa_pem"));
    expect(key.publicKeyBlob).toEqual(pubBlob("rsa_pem"));
    const sig = splitSig(key.sign(CHALLENGE, 2));
    expect(cryptoVerify("sha256", CHALLENGE, pubKeyObjectFromBlob(pubBlob("rsa_pem")), sig.inner)).toBe(
      true,
    );
  });

  it("loads a SEC1 EC PEM and matches its .pub blob", () => {
    const key = loadPrivateKey(readFixture("ecdsa256_pem"));
    expect(key.publicKeyBlob).toEqual(pubBlob("ecdsa256_pem"));
  });

  it("loads a PKCS#8 ed25519 PEM generated at runtime", () => {
    const { privateKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const key = loadPrivateKey(privateKey as string);
    const sig = splitSig(key.sign(CHALLENGE, 0));
    expect(sig.format).toBe("ssh-ed25519");
  });
});

describe("loadPrivateKey — rejections (no secret material in messages)", () => {
  it("rejects an encrypted OpenSSH key pointing at the PKCS#8 conversion", () => {
    try {
      loadPrivateKey(readFixture("ed25519_enc"));
      expect.fail("should throw");
    } catch (e) {
      expect((e as { code: string }).code).toBe(ErrorCode.SSH_AGENT_FAILED);
      expect((e as Error).message).toContain("encrypted private keys are not supported");
      expect((e as Error).message).toContain("ssh-keygen -p -f <keyfile> -m PKCS8");
      expect((e as Error).message).toContain("secret set --from-file");
    }
  });

  it("rejects a stored encrypted PKCS#8 key pointing at re-import", () => {
    const { privateKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
        cipher: "aes-256-cbc",
        passphrase: "some-passphrase",
      },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    try {
      loadPrivateKey(privateKey as string);
      expect.fail("should throw");
    } catch (e) {
      expect((e as { code: string }).code).toBe(ErrorCode.SSH_AGENT_FAILED);
      expect((e as Error).message).toContain("stored key is encrypted");
      expect((e as Error).message).toContain("secret set --from-file");
      expect((e as Error).message).not.toContain("some-passphrase");
    }
  });

  it("rejects garbage input", () => {
    expect(() => loadPrivateKey("not a key")).toThrow();
  });

  it("rejects a truncated OpenSSH container", () => {
    const truncated = `-----BEGIN OPENSSH PRIVATE KEY-----\n${Buffer.from("openssh-key-v1\0").toString("base64")}\n-----END OPENSSH PRIVATE KEY-----`;
    expect(() => loadPrivateKey(truncated)).toThrow();
  });
});

// --- test-only helpers: build a node public KeyObject from an SSH blob -------

import { createPublicKey } from "node:crypto";

function pubKeyObjectFromBlob(blob: Buffer) {
  const r = new SshReader(blob);
  const type = r.readCString();
  if (type === "ssh-ed25519") {
    const a = r.readString();
    return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: a.toString("base64url") }, format: "jwk" });
  }
  if (type === "ssh-rsa") {
    const e = r.readMpint();
    const n = r.readMpint();
    return createPublicKey({
      key: { kty: "RSA", e: e.toString("base64url"), n: n.toString("base64url") },
      format: "jwk",
    });
  }
  // ecdsa: type already read; blob is <type> <curveId> <point>
  const curveId = r.readCString();
  const point = r.readString();
  const sizes: Record<string, [string, number]> = {
    "nistp256": ["P-256", 32],
    "nistp384": ["P-384", 48],
    "nistp521": ["P-521", 66],
  };
  const [crv, size] = sizes[curveId] as [string, number];
  const x = point.subarray(1, 1 + size).toString("base64url");
  const y = point.subarray(1 + size, 1 + 2 * size).toString("base64url");
  return createPublicKey({ key: { kty: "EC", crv, x, y }, format: "jwk" });
}
