import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import {
  AES_IV_LENGTH,
  AES_KEY_LENGTH,
  AES_TAG_LENGTH,
  ErrorCode,
  VaultError,
} from "@harpoc/shared";

export interface EncryptResult {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

/**
 * Encrypt plaintext with AES-256-GCM. Always generates a fresh random IV.
 */
export function encrypt(key: Uint8Array, plaintext: Uint8Array, aad: string): EncryptResult {
  if (key.length !== AES_KEY_LENGTH) {
    throw new VaultError(
      ErrorCode.ENCRYPTION_ERROR,
      `AES key must be ${AES_KEY_LENGTH} bytes, got ${key.length}`,
    );
  }

  const iv = randomBytes(AES_IV_LENGTH);
  const aadBuffer = Buffer.from(aad, "utf8");

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aadBuffer);

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: new Uint8Array(encrypted),
    iv: new Uint8Array(iv),
    tag: new Uint8Array(tag),
  };
}

/**
 * Decrypt ciphertext with AES-256-GCM. Validates auth tag and AAD.
 */
export function decrypt(
  key: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad: string,
): Uint8Array {
  if (key.length !== AES_KEY_LENGTH) {
    throw new VaultError(
      ErrorCode.ENCRYPTION_ERROR,
      `AES key must be ${AES_KEY_LENGTH} bytes, got ${key.length}`,
    );
  }
  if (iv.length !== AES_IV_LENGTH) {
    throw new VaultError(
      ErrorCode.ENCRYPTION_ERROR,
      `IV must be ${AES_IV_LENGTH} bytes, got ${iv.length}`,
    );
  }
  if (tag.length !== AES_TAG_LENGTH) {
    throw new VaultError(
      ErrorCode.ENCRYPTION_ERROR,
      `Auth tag must be ${AES_TAG_LENGTH} bytes, got ${tag.length}`,
    );
  }

  const aadBuffer = Buffer.from(aad, "utf8");

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  decipher.setAAD(aadBuffer);

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return new Uint8Array(decrypted);
  } catch {
    throw VaultError.encryptionError("AES-GCM decryption failed (auth tag mismatch or corrupted)");
  }
}
