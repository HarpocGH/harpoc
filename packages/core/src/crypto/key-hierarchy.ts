import { createHmac } from "node:crypto";
import {
  AAD_DEK_WRAP,
  AAD_NAME_ENCRYPTION,
  AAD_SECRET_PAYLOAD,
  AAD_VAULT_KEK,
  AAD_WRAPPED_AUDIT_KEY,
  AAD_WRAPPED_JWT_KEY,
  AES_KEY_LENGTH,
  HKDF_INFO_AUDIT,
  HKDF_INFO_JWT_SIGNING,
  HKDF_INFO_NAME_INDEX,
} from "@harpoc/shared";
import { decrypt, encrypt } from "./aes-gcm.js";
import { deriveKey, generateSalt } from "./argon2.js";
import { deriveSubkey } from "./hkdf.js";
import { generateRandomBytes, generateUUIDv7, wipeBuffer } from "./random.js";

/** A key wrapped with AES-256-GCM. */
export interface WrappedKey {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

/** Result of creating a new vault. */
export interface VaultKeys {
  salt: Uint8Array;
  wrappedKek: Uint8Array;
  wrappedKekIv: Uint8Array;
  wrappedKekTag: Uint8Array;
  kek: Uint8Array;
  jwtKey: Uint8Array;
  auditKey: Uint8Array;
  vaultId: string;
  wrappedJwtKey: WrappedKey;
  wrappedAuditKey: WrappedKey;
}

/** Result of unlocking a vault. */
export interface UnlockedKeys {
  kek: Uint8Array;
  jwtKey: Uint8Array;
  auditKey: Uint8Array;
}

/** Wrapped DEK result. */
export interface WrappedDek {
  wrappedDek: Uint8Array;
  dekIv: Uint8Array;
  dekTag: Uint8Array;
}

/** Encrypted value result. */
export interface EncryptedValue {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

/**
 * Create a new vault: generate KEK, wrap it with master key, derive JWT/audit keys.
 */
export async function createVaultKeys(password: string): Promise<VaultKeys> {
  const salt = generateSalt();
  const masterKey = await deriveKey(password, salt);

  try {
    // Generate random KEK
    const kek = generateRandomBytes(AES_KEY_LENGTH);

    // Wrap KEK with master key
    const { ciphertext: wrappedKek, iv: wrappedKekIv, tag: wrappedKekTag } =
      encrypt(masterKey, kek, AAD_VAULT_KEK);

    // Generate vault ID
    const vaultId = generateUUIDv7();

    // Generate RANDOM JWT and audit keys (not HKDF-derived)
    const jwtKey = generateRandomBytes(AES_KEY_LENGTH);
    const auditKey = generateRandomBytes(AES_KEY_LENGTH);

    // Wrap JWT and audit keys with KEK for persistent storage
    const wrappedJwtKey = wrapKeyWithKek(kek, jwtKey, AAD_WRAPPED_JWT_KEY);
    const wrappedAuditKey = wrapKeyWithKek(kek, auditKey, AAD_WRAPPED_AUDIT_KEY);

    return {
      salt, wrappedKek, wrappedKekIv, wrappedKekTag,
      kek, jwtKey, auditKey, vaultId,
      wrappedJwtKey, wrappedAuditKey,
    };
  } finally {
    wipeBuffer(masterKey);
  }
}

/**
 * Unlock vault: derive master key from password, unwrap KEK, recover JWT/audit keys.
 *
 * If wrappedJwtKey/wrappedAuditKey are provided, unwraps them from KEK.
 * Otherwise falls back to HKDF derivation from master key (legacy vault support).
 */
export async function unlockVault(
  password: string,
  salt: Uint8Array,
  wrappedKek: Uint8Array,
  wrappedKekIv: Uint8Array,
  wrappedKekTag: Uint8Array,
  vaultId: string,
  wrappedJwtKey?: WrappedKey,
  wrappedAuditKey?: WrappedKey,
): Promise<UnlockedKeys> {
  const masterKey = await deriveKey(password, salt);

  try {
    const kek = decrypt(masterKey, wrappedKek, wrappedKekIv, wrappedKekTag, AAD_VAULT_KEK);

    let jwtKey: Uint8Array;
    let auditKey: Uint8Array;

    if (wrappedJwtKey && wrappedAuditKey) {
      // New path: unwrap from KEK
      jwtKey = decrypt(kek, wrappedJwtKey.ciphertext, wrappedJwtKey.iv, wrappedJwtKey.tag, AAD_WRAPPED_JWT_KEY);
      auditKey = decrypt(kek, wrappedAuditKey.ciphertext, wrappedAuditKey.iv, wrappedAuditKey.tag, AAD_WRAPPED_AUDIT_KEY);
    } else {
      // Legacy path: derive from master key via HKDF
      jwtKey = await deriveSubkey(masterKey, vaultId, HKDF_INFO_JWT_SIGNING);
      auditKey = await deriveSubkey(masterKey, vaultId, HKDF_INFO_AUDIT);
    }

    return { kek, jwtKey, auditKey };
  } finally {
    wipeBuffer(masterKey);
  }
}

/**
 * Wrap a per-secret DEK with the vault KEK.
 */
export function wrapDek(kek: Uint8Array, dek: Uint8Array, secretId: string): WrappedDek {
  const { ciphertext: wrappedDek, iv: dekIv, tag: dekTag } =
    encrypt(kek, dek, AAD_DEK_WRAP(secretId));
  return { wrappedDek, dekIv, dekTag };
}

/**
 * Unwrap a per-secret DEK with the vault KEK.
 */
export function unwrapDek(
  kek: Uint8Array,
  wrappedDek: Uint8Array,
  dekIv: Uint8Array,
  dekTag: Uint8Array,
  secretId: string,
): Uint8Array {
  return decrypt(kek, wrappedDek, dekIv, dekTag, AAD_DEK_WRAP(secretId));
}

/**
 * Encrypt a secret value with its DEK.
 */
export function encryptSecretValue(
  dek: Uint8Array,
  plaintext: Uint8Array,
  secretId: string,
  version: number,
): EncryptedValue {
  const { ciphertext, iv, tag } =
    encrypt(dek, plaintext, AAD_SECRET_PAYLOAD(secretId, version));
  return { ciphertext, iv, tag };
}

/**
 * Decrypt a secret value with its DEK.
 */
export function decryptSecretValue(
  dek: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  secretId: string,
  version: number,
): Uint8Array {
  return decrypt(dek, ciphertext, iv, tag, AAD_SECRET_PAYLOAD(secretId, version));
}

/**
 * Encrypt a secret name with the vault KEK (not per-secret DEK).
 */
export function encryptName(
  kek: Uint8Array,
  name: string,
  secretId: string,
): EncryptedValue {
  const plaintext = new Uint8Array(Buffer.from(name, "utf8"));
  const { ciphertext, iv, tag } = encrypt(kek, plaintext, AAD_NAME_ENCRYPTION(secretId));
  return { ciphertext, iv, tag };
}

/**
 * Decrypt a secret name with the vault KEK.
 */
export function decryptName(
  kek: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  secretId: string,
): string {
  const plaintext = decrypt(kek, ciphertext, iv, tag, AAD_NAME_ENCRYPTION(secretId));
  return Buffer.from(plaintext).toString("utf8");
}

/**
 * Change vault password: re-wraps KEK with new master key. O(1) — no DEKs/ciphertexts touched.
 * JWT and audit keys are unchanged (wrapped with KEK, not derived from master key).
 */
export async function changePassword(
  oldPassword: string,
  newPassword: string,
  salt: Uint8Array,
  wrappedKek: Uint8Array,
  wrappedKekIv: Uint8Array,
  wrappedKekTag: Uint8Array,
): Promise<{
  newSalt: Uint8Array;
  newWrappedKek: Uint8Array;
  newWrappedKekIv: Uint8Array;
  newWrappedKekTag: Uint8Array;
}> {
  // Unwrap KEK with old password
  const oldMasterKey = await deriveKey(oldPassword, salt);
  let kek: Uint8Array;

  try {
    kek = decrypt(oldMasterKey, wrappedKek, wrappedKekIv, wrappedKekTag, AAD_VAULT_KEK);
  } finally {
    wipeBuffer(oldMasterKey);
  }

  // Re-wrap KEK with new password
  const newSalt = generateSalt();
  const newMasterKey = await deriveKey(newPassword, newSalt);

  try {
    const {
      ciphertext: newWrappedKek,
      iv: newWrappedKekIv,
      tag: newWrappedKekTag,
    } = encrypt(newMasterKey, kek, AAD_VAULT_KEK);

    return { newSalt, newWrappedKek, newWrappedKekIv, newWrappedKekTag };
  } finally {
    wipeBuffer(newMasterKey);
    wipeBuffer(kek);
  }
}

/**
 * Wrap a key with the vault KEK using a specific AAD string.
 */
export function wrapKeyWithKek(kek: Uint8Array, key: Uint8Array, aad: string): WrappedKey {
  const { ciphertext, iv, tag } = encrypt(kek, key, aad);
  return { ciphertext, iv, tag };
}

/**
 * Unwrap a key from the vault KEK using a specific AAD string.
 */
export function unwrapKeyFromKek(
  kek: Uint8Array,
  wrapped: WrappedKey,
  aad: string,
): Uint8Array {
  return decrypt(kek, wrapped.ciphertext, wrapped.iv, wrapped.tag, aad);
}

/**
 * Compute an HMAC for secret name lookup. Enables O(1) resolution without
 * decrypting all secret names.
 *
 * HMAC(HKDF(kek, "name-index-v1"), name + ":" + project)
 */
export async function computeNameHmac(
  kek: Uint8Array,
  name: string,
  project: string | null,
): Promise<string> {
  const hmacKey = await deriveSubkey(kek, HKDF_INFO_NAME_INDEX, HKDF_INFO_NAME_INDEX);
  try {
    const data = project ? `${name}:${project}` : name;
    return createHmac("sha256", hmacKey).update(data).digest("hex");
  } finally {
    wipeBuffer(hmacKey);
  }
}
