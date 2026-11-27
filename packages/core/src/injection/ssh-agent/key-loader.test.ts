import { generateKeyPairSync, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ErrorCode, recordOf } from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { describe, expect, it } from "vitest";
import { loadPrivateKey } from "./key-loader.js";
import { SshReader, writeMpint, writeString, writeUint32 } from "./ssh-wire.js";

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
const STORED_PASSPHRASE = "some-passphrase";

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
    expect(
      cryptoVerify("sha256", CHALLENGE, pubKeyObjectFromBlob(pubBlob("rsa_pem")), sig.inner),
    ).toBe(true);
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
  it("rejects an encrypted OpenSSH key pointing at the PKCS#8 conversion", async () => {
    const err = await expectVaultError(
      () => loadPrivateKey(readFixture("ed25519_enc")),
      ErrorCode.SSH_AGENT_FAILED,
    );
    expect(err.message).toContain("encrypted private keys are not supported");
    expect(err.message).toContain("ssh-keygen -p -f <keyfile> -m PKCS8");
    expect(err.message).toContain("secret set --from-file");
  });

  it("rejects a stored encrypted PKCS#8 key pointing at re-import", async () => {
    const { privateKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
        cipher: "aes-256-cbc",
        passphrase: "some-passphrase",
      },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const err = await expectVaultError(
      () => loadPrivateKey(privateKey as string),
      ErrorCode.SSH_AGENT_FAILED,
    );
    expectAbsent(err.message, STORED_PASSPHRASE);
    expect(err.message).toContain("stored key is encrypted");
    expect(err.message).toContain("secret set --from-file");
  });

  it("rejects garbage input", async () => {
    await expectVaultError(() => loadPrivateKey("not a key"), ErrorCode.SSH_AGENT_FAILED);
  });

  it("a key node cannot read names no reader's error", async () => {
    const err = await expectVaultError(
      () => loadPrivateKey("not a key"),
      ErrorCode.SSH_AGENT_FAILED,
    );

    expect(err.message).toBe("Ephemeral ssh-agent failed: unsupported or malformed private key");
    expect(recordOf(err)).toBeDefined();
  });

  it("a truncated container is a malformed key", async () => {
    const truncated = armor(Buffer.from("openssh-key-v1\0", "binary"));

    const err = await expectVaultError(() => loadPrivateKey(truncated), ErrorCode.SSH_AGENT_FAILED);

    expect(err.message).toBe("Ephemeral ssh-agent failed: malformed OpenSSH private key");
    expect(recordOf(err)).toBeDefined();
  });

  it("the reader's message is not passed through", async () => {
    const one = Buffer.from([1]);
    const pem = container(
      writeString("ssh-rsa"),
      writeMpint(Buffer.from("c3a1", "hex")),
      writeMpint(Buffer.from("010001", "hex")),
      writeMpint(Buffer.from("5b", "hex")),
      writeMpint(one),
      writeMpint(one),
      writeMpint(Buffer.from("0b", "hex")),
    );

    const err = await expectVaultError(() => loadPrivateKey(pem), ErrorCode.SSH_AGENT_FAILED);

    expect(err.message).not.toContain("Division");
    expect(err.message).toBe("Ephemeral ssh-agent failed: malformed OpenSSH private key");
    expect(recordOf(err)).toBeDefined();
  });
});

const KEY_FIELD_FIXTURE = "harpoc-key-field-c41d";
const CERT_BLOB_FIXTURE = "harpoc-cert-blob-9e27";
const NISTP256_POINT = Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 7)]);

function armor(body: Buffer): string {
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${body.toString("base64")}\n-----END OPENSSH PRIVATE KEY-----`;
}

/** An unencrypted one-key `openssh-key-v1` container whose private section holds `fields` after its check pair. */
function container(...fields: Buffer[]): string {
  const priv = Buffer.concat([writeUint32(7), writeUint32(7), ...fields, writeString("comment")]);
  return armor(
    Buffer.concat([
      Buffer.from("openssh-key-v1\0", "binary"),
      writeString("none"),
      writeString("none"),
      writeString(""),
      writeUint32(1),
      writeString(Buffer.alloc(0)),
      writeString(priv),
    ]),
  );
}

const PEM_ENCODING = {
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
} as const;

describe("loadPrivateKey — a type or a curve it does not take is named only from its lists", () => {
  it("a known type the loader does not take is named", async () => {
    const pem = container(
      writeString("ssh-dss"),
      writeMpint(Buffer.from("d1", "hex")),
      writeMpint(Buffer.from("b3", "hex")),
    );

    const err = await expectVaultError(() => loadPrivateKey(pem), ErrorCode.SSH_AGENT_FAILED);

    expect(err.message).toBe("Ephemeral ssh-agent failed: unsupported key type: ssh-dss");
    expect(recordOf(err)).toBeDefined();
  });

  it("an unknown type is not named", async () => {
    const pem = container(writeString(KEY_FIELD_FIXTURE));

    const err = await expectVaultError(() => loadPrivateKey(pem), ErrorCode.SSH_AGENT_FAILED);

    expectAbsent(err.message, KEY_FIELD_FIXTURE);
    expect(err.message).toBe("Ephemeral ssh-agent failed: unsupported key type");
    expect(recordOf(err)).toBeDefined();
  });

  it("a known curve the loader does not take is named (secp256k1, through node)", async () => {
    const pem = generateKeyPairSync("ec", { namedCurve: "secp256k1", ...PEM_ENCODING }).privateKey;

    const err = await expectVaultError(() => loadPrivateKey(pem), ErrorCode.SSH_AGENT_FAILED);

    expect(err.message).toBe("Ephemeral ssh-agent failed: unsupported ECDSA curve: secp256k1");
    expect(recordOf(err)).toBeDefined();
  });

  it("an unknown curve is not named", async () => {
    const pem = container(
      writeString("ecdsa-sha2-nistp256"),
      writeString(KEY_FIELD_FIXTURE),
      writeString(NISTP256_POINT),
      writeMpint(Buffer.from("2a", "hex")),
    );

    const err = await expectVaultError(() => loadPrivateKey(pem), ErrorCode.SSH_AGENT_FAILED);

    expectAbsent(err.message, KEY_FIELD_FIXTURE);
    expect(err.message).toBe("Ephemeral ssh-agent failed: unsupported ECDSA curve");
    expect(recordOf(err)).toBeDefined();
  });

  it("a certificate's ECDSA key ends without its blob", async () => {
    const certificate = Buffer.concat([
      writeString("ecdsa-sha2-nistp256-cert-v01@openssh.com"),
      writeString(CERT_BLOB_FIXTURE),
      writeString(NISTP256_POINT),
    ]);
    const pem = container(
      writeString("ecdsa-sha2-nistp256-cert-v01@openssh.com"),
      writeString(certificate),
      writeMpint(Buffer.from("2a", "hex")),
    );

    const err = await expectVaultError(() => loadPrivateKey(pem), ErrorCode.SSH_AGENT_FAILED);

    expectAbsent(err.message, CERT_BLOB_FIXTURE);
    expect(err.message).toBe("Ephemeral ssh-agent failed: unsupported ECDSA curve");
    expect(recordOf(err)).toBeDefined();
  });

  it.each([
    {
      what: "a type node names that is on the list (ed448)",
      pem: () => generateKeyPairSync("ed448", PEM_ENCODING).privateKey,
      text: "Ephemeral ssh-agent failed: unsupported key type: ed448",
    },
    {
      what: "a type node reads and cannot export, off the list (dsa)",
      pem: () =>
        generateKeyPairSync("dsa", { modulusLength: 1024, divisorLength: 160, ...PEM_ENCODING })
          .privateKey,
      text: "Ephemeral ssh-agent failed: unsupported key type",
    },
    {
      what: "a curve node reads and cannot export, off the list (brainpoolP256r1)",
      pem: () =>
        generateKeyPairSync("ec", { namedCurve: "brainpoolP256r1", ...PEM_ENCODING }).privateKey,
      text: "Ephemeral ssh-agent failed: unsupported ECDSA curve",
    },
  ])("$what: a fixed text, no raw error", async ({ pem, text }) => {
    const key = pem();

    const err = await expectVaultError(() => loadPrivateKey(key), ErrorCode.SSH_AGENT_FAILED);

    expect(err.message).toBe(text);
    expect(recordOf(err)).toBeDefined();
  });
});

// --- test-only helpers: build a node public KeyObject from an SSH blob -------

import { createPublicKey } from "node:crypto";

function pubKeyObjectFromBlob(blob: Buffer) {
  const r = new SshReader(blob);
  const type = r.readCString();
  if (type === "ssh-ed25519") {
    const a = r.readString();
    return createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: a.toString("base64url") },
      format: "jwk",
    });
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
    nistp256: ["P-256", 32],
    nistp384: ["P-384", 48],
    nistp521: ["P-521", 66],
  };
  const [crv, size] = sizes[curveId] as [string, number];
  const x = point.subarray(1, 1 + size).toString("base64url");
  const y = point.subarray(1 + size, 1 + 2 * size).toString("base64url");
  return createPublicKey({ key: { kty: "EC", crv, x, y }, format: "jwk" });
}
