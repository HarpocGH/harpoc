import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import {
  AES_IV_LENGTH,
  AES_KEY_LENGTH,
  AES_TAG_LENGTH,
  ErrorCode,
  VaultError,
  num,
  vaultText,
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
      vaultText`AES key must be ${num(AES_KEY_LENGTH)} bytes, got ${num(key.length)}`,
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
      vaultText`AES key must be ${num(AES_KEY_LENGTH)} bytes, got ${num(key.length)}`,
    );
  }
  if (iv.length !== AES_IV_LENGTH) {
    throw new VaultError(
      ErrorCode.ENCRYPTION_ERROR,
      vaultText`IV must be ${num(AES_IV_LENGTH)} bytes, got ${num(iv.length)}`,
    );
  }
  if (tag.length !== AES_TAG_LENGTH) {
    throw new VaultError(
      ErrorCode.ENCRYPTION_ERROR,
      vaultText`Auth tag must be ${num(AES_TAG_LENGTH)} bytes, got ${num(tag.length)}`,
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
    throw VaultError.encryptionError(
      vaultText`AES-GCM decryption failed (auth tag mismatch or corrupted)`,
    );
  }
}
