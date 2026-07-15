import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { describe, expect, it } from "vitest";
import { analyzeKeyMaterial, decryptKeyForImport } from "./key-import.js";
import { loadPrivateKey } from "./key-loader.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "__fixtures__", "ssh");
const readFixture = (name: string): string => readFileSync(join(FIXTURES, name), "utf8");

const PASSPHRASE = "correct horse battery";
const CHALLENGE = Buffer.from("harpoc key-import challenge");

function encryptedPkcs8(type: "rsa" | "ed25519" | "ec"): { privateKey: string; publicKey: string } {
  const encoding = {
    privateKeyEncoding: {
      type: "pkcs8" as const,
      format: "pem" as const,
      cipher: "aes-256-cbc",
      passphrase: PASSPHRASE,
    },
    publicKeyEncoding: { type: "spki" as const, format: "pem" as const },
  };
  if (type === "rsa") return generateKeyPairSync("rsa", { modulusLength: 2048, ...encoding });
  if (type === "ec") return generateKeyPairSync("ec", { namedCurve: "prime256v1", ...encoding });
  return generateKeyPairSync("ed25519", encoding);
}

function encryptedLegacyPem(): { privateKey: string; publicKey: string } {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: {
      type: "pkcs1",
      format: "pem",
      cipher: "aes-128-cbc",
      passphrase: PASSPHRASE,
    },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
}

describe("analyzeKeyMaterial — classification", () => {
  it("classifies encrypted PKCS#8 (rsa, ed25519, ec)", () => {
    for (const type of ["rsa", "ed25519", "ec"] as const) {
      expect(analyzeKeyMaterial(encryptedPkcs8(type).privateKey)).toBe("encrypted-pkcs8");
    }
  });

  it("classifies encrypted legacy PEM (Proc-Type: 4,ENCRYPTED)", () => {
    const { privateKey } = encryptedLegacyPem();
    expect(privateKey).toContain("Proc-Type: 4,ENCRYPTED");
    expect(analyzeKeyMaterial(privateKey)).toBe("encrypted-legacy-pem");
  });

  it("classifies an encrypted OpenSSH container", () => {
    expect(analyzeKeyMaterial(readFixture("ed25519_enc"))).toBe("encrypted-openssh");
  });

  it("classifies unencrypted keys of every supported shape", () => {
    const pkcs8 = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    }).privateKey;
    expect(analyzeKeyMaterial(pkcs8)).toBe("unencrypted-key");
    expect(analyzeKeyMaterial(readFixture("rsa_pem"))).toBe("unencrypted-key");
    expect(analyzeKeyMaterial(readFixture("ecdsa256_pem"))).toBe("unencrypted-key");
    expect(analyzeKeyMaterial(readFixture("ed25519_openssh"))).toBe("unencrypted-key");
    expect(analyzeKeyMaterial(readFixture("rsa_openssh"))).toBe("unencrypted-key");
  });

  it("classifies non-key values as not-a-key", () => {
    expect(analyzeKeyMaterial("sk-abc123def456")).toBe("not-a-key");
    expect(analyzeKeyMaterial('{"token":"xyz"}')).toBe("not-a-key");
    expect(analyzeKeyMaterial("")).toBe("not-a-key");
    expect(analyzeKeyMaterial("QUJDREVGRw==")).toBe("not-a-key");
    expect(analyzeKeyMaterial("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----")).toBe(
      "not-a-key",
    );
  });

  it("classifies an OpenSSH armor around garbage as not-a-key", () => {
    const garbage = `-----BEGIN OPENSSH PRIVATE KEY-----\n${Buffer.from("not a container").toString("base64")}\n-----END OPENSSH PRIVATE KEY-----`;
    expect(analyzeKeyMaterial(garbage)).toBe("not-a-key");
  });

  it("classifies a truncated OpenSSH container (magic only) as not-a-key", () => {
    const truncated = `-----BEGIN OPENSSH PRIVATE KEY-----\n${Buffer.from("openssh-key-v1\0").toString("base64")}\n-----END OPENSSH PRIVATE KEY-----`;
    expect(analyzeKeyMaterial(truncated)).toBe("not-a-key");
  });
});

const FAKE_CERT = "-----BEGIN CERTIFICATE-----\nMIIBfakecertbody\n-----END CERTIFICATE-----\n";

describe("analyzeKeyMaterial — bundles (review fix F3)", () => {
  it("classifies cert + encrypted PKCS#8 as encrypted-key-bundle (either order)", () => {
    const { privateKey } = encryptedPkcs8("rsa");
    expect(analyzeKeyMaterial(`${FAKE_CERT}${privateKey}`)).toBe("encrypted-key-bundle");
    expect(analyzeKeyMaterial(`${privateKey}${FAKE_CERT}`)).toBe("encrypted-key-bundle");
  });

  it("classifies cert + encrypted legacy PEM as encrypted-key-bundle", () => {
    const { privateKey } = encryptedLegacyPem();
    expect(analyzeKeyMaterial(`${FAKE_CERT}${privateKey}`)).toBe("encrypted-key-bundle");
  });

  it("two encrypted keys in one file are a bundle too", () => {
    const a = encryptedPkcs8("rsa").privateKey;
    const b = encryptedPkcs8("ed25519").privateKey;
    expect(analyzeKeyMaterial(`${a}${b}`)).toBe("encrypted-key-bundle");
  });

  it("control: a lone encrypted key is NOT a bundle", () => {
    expect(analyzeKeyMaterial(encryptedPkcs8("rsa").privateKey)).toBe("encrypted-pkcs8");
    expect(analyzeKeyMaterial(encryptedLegacyPem().privateKey)).toBe("encrypted-legacy-pem");
  });

  it("control: cert + unencrypted key stays unencrypted-key (imports verbatim)", () => {
    const plain = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    }).privateKey;
    expect(analyzeKeyMaterial(`${FAKE_CERT}${plain}`)).toBe("unencrypted-key");
  });
});

describe("import classifier and use-time loader guard agree (review fix F10)", () => {
  it("every encrypted-classified PEM specimen is refused by loadPrivateKey with the re-import recovery", () => {
    const specimens = [
      encryptedPkcs8("rsa").privateKey,
      encryptedPkcs8("ed25519").privateKey,
      encryptedPkcs8("ec").privateKey,
      encryptedLegacyPem().privateKey,
    ];
    for (const pem of specimens) {
      expect(analyzeKeyMaterial(pem)).toMatch(/^encrypted-/);
      expect(() => loadPrivateKey(pem)).toThrowError(/re-import/);
    }
  });

  it("every unencrypted specimen loads (no drift on the accept side)", () => {
    for (const name of ["rsa_pem", "ecdsa256_pem", "ed25519_openssh", "rsa_openssh"]) {
      const pem = readFixture(name);
      expect(analyzeKeyMaterial(pem)).toBe("unencrypted-key");
      expect(() => loadPrivateKey(pem)).not.toThrow();
    }
  });
});

describe("decryptKeyForImport — roundtrip", () => {
  it.each(["rsa", "ed25519", "ec"] as const)(
    "decrypts an encrypted PKCS#8 %s key to a use-time-loadable PEM",
    (type) => {
      const { privateKey, publicKey } = encryptedPkcs8(type);
      const pem = decryptKeyForImport(privateKey, PASSPHRASE);
      const pemText = pem.toString("utf8");

      expect(pemText.startsWith("-----BEGIN PRIVATE KEY-----")).toBe(true);
      expect(pemText).not.toContain("ENCRYPTED");
      expect(analyzeKeyMaterial(pemText)).toBe("unencrypted-key");

      // Parses without a passphrase and still matches the original public key.
      const decrypted = createPrivateKey(pemText);
      expect(createPublicKey(decrypted).export({ format: "pem", type: "spki" })).toBe(publicKey);

      // The use-time loader accepts the output and the key signs verifiably.
      const loaded = loadPrivateKey(pemText);
      expect(loaded.publicKeyBlob.length).toBeGreaterThan(0);
      const digest = type === "ed25519" ? null : "sha256";
      const sig = cryptoSign(digest, CHALLENGE, decrypted);
      expect(cryptoVerify(digest, CHALLENGE, createPublicKey(publicKey), sig)).toBe(true);
    },
  );

  it("decrypts an encrypted legacy PEM through the same call", () => {
    const { privateKey, publicKey } = encryptedLegacyPem();
    const pem = decryptKeyForImport(privateKey, PASSPHRASE);
    const decrypted = createPrivateKey(pem.toString("utf8"));
    expect(createPublicKey(decrypted).export({ format: "pem", type: "spki" })).toBe(publicKey);
    expect(() => loadPrivateKey(pem.toString("utf8"))).not.toThrow();
  });

  it("decrypts CRLF-normalized input (Windows-edited key file)", () => {
    const { privateKey } = encryptedPkcs8("ed25519");
    const crlf = privateKey.replace(/\n/g, "\r\n");
    expect(() => decryptKeyForImport(crlf, PASSPHRASE)).not.toThrow();
  });
});

describe("decryptKeyForImport — rejection", () => {
  it("throws KEY_PASSPHRASE_INVALID on a wrong passphrase, leaking nothing", () => {
    const { privateKey } = encryptedPkcs8("ed25519");
    try {
      decryptKeyForImport(privateKey, "wrong-passphrase");
      expect.fail("should throw");
    } catch (err) {
      expect(err).toBeInstanceOf(VaultError);
      expect((err as VaultError).code).toBe(ErrorCode.KEY_PASSPHRASE_INVALID);
      expect((err as Error).message).not.toContain("wrong-passphrase");
      expect((err as Error).message).not.toContain("BEGIN");
    }
  });

  it("throws KEY_PASSPHRASE_INVALID on material that is not a decryptable key", () => {
    expect(() => decryptKeyForImport("not a key at all", PASSPHRASE)).toThrow(VaultError);
  });
});
