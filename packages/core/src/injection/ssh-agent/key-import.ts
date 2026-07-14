import { createPrivateKey } from "node:crypto";
import { VaultError } from "@harpoc/shared";
import { wipeBuffer } from "../../crypto/random.js";
import { opensshKeyCipher } from "./key-loader.js";

/**
 * Import-side classification of incoming secret material (thesis §4.5.7,
 * decrypt-at-import). Purely armor/header-based — content behind valid armor
 * is not validated here; an unparseable OpenSSH container classifies as
 * "not-a-key" and passes through the generic import path untouched.
 */
export type KeyMaterialKind =
  | "encrypted-pkcs8"
  | "encrypted-legacy-pem"
  | "encrypted-openssh"
  | "unencrypted-key"
  | "not-a-key";

const PKCS8_ENCRYPTED_ARMOR = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const OPENSSH_ARMOR = "-----BEGIN OPENSSH PRIVATE KEY-----";
const LEGACY_ARMOR = /-----BEGIN (?:RSA|EC|DSA) PRIVATE KEY-----/;
const ANY_KEY_ARMOR = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const LEGACY_ENCRYPTED_HEADER = /Proc-Type:\s*4\s*,\s*ENCRYPTED/i;

export function analyzeKeyMaterial(material: string): KeyMaterialKind {
  const trimmed = material.trim();

  if (trimmed.includes(PKCS8_ENCRYPTED_ARMOR)) {
    return "encrypted-pkcs8";
  }

  if (trimmed.includes(OPENSSH_ARMOR)) {
    try {
      return opensshKeyCipher(trimmed) === "none" ? "unencrypted-key" : "encrypted-openssh";
    } catch {
      return "not-a-key";
    }
  }

  if (LEGACY_ARMOR.test(trimmed)) {
    return LEGACY_ENCRYPTED_HEADER.test(trimmed) ? "encrypted-legacy-pem" : "unencrypted-key";
  }

  if (ANY_KEY_ARMOR.test(trimmed)) {
    return "unencrypted-key";
  }

  return "not-a-key";
}

/**
 * Decrypt an encrypted PKCS#8 or legacy-PEM private key in memory and return
 * it as an unencrypted PKCS#8 PEM buffer — exactly what `loadPrivateKey`
 * accepts at use time. node:crypto only; the OpenSSH container format
 * (bcrypt-pbkdf) is deliberately outside this function's reach.
 *
 * The returned buffer is the caller's to wipe after the engine handoff.
 * Residuals: the passphrase string and the KeyObject's native handle are not
 * wipeable (same class as the master-password prompt and use-time loader).
 */
export function decryptKeyForImport(material: string, passphrase: string): Buffer {
  let keyObject;
  try {
    keyObject = createPrivateKey({ key: material, passphrase });
  } catch {
    throw VaultError.keyPassphraseInvalid();
  }

  const der = keyObject.export({ type: "pkcs8", format: "der" });
  try {
    return derToPkcs8Pem(der);
  } finally {
    wipeBuffer(der);
  }
}

function derToPkcs8Pem(der: Buffer): Buffer {
  const b64 = der.toString("base64");
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return Buffer.from(
    `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----\n`,
    "utf8",
  );
}
