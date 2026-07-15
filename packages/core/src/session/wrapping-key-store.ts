import type { SessionKeyProtectionScheme } from "@harpoc/shared";
import { AES_IV_LENGTH, AES_TAG_LENGTH, ErrorCode, VaultError } from "@harpoc/shared";
import { decrypt, encrypt } from "../crypto/aes-gcm.js";
import { generateRandomBytes, wipeBuffer } from "../crypto/random.js";
// Type-only: erased at compile time, so no runtime cycle with the factory module.
import type { SessionKeyProtector } from "./session-key-protector.js";

/** Wrapping keys are AES-256 keys. */
export const WRAPPING_KEY_LENGTH = 32;

/**
 * Blob layout version. Unknown versions are rejected — fail closed, a fresh
 * unlock is the recovery path.
 */
const WRAP_BLOB_VERSION = 0x01;

/**
 * AAD binds the blob to this wrap format AND the producing scheme —
 * defense-in-depth atop the session file's `key_protection` tag.
 */
const WRAP_AAD_PREFIX = "harpoc.session-key.wrap.v1:";

const MIN_BLOB_LENGTH = 1 + AES_IV_LENGTH + AES_TAG_LENGTH + 1;

/**
 * A platform keystore holding the per-user session wrapping key (thesis §4.6).
 * `loadWrappingKey` returns null on a clean miss (no item yet) and throws on
 * operational failure (keystore locked/unreachable); `storeWrappingKey`
 * creates or replaces the item. Implementations must never place key material
 * in error messages, logs, or process arguments.
 */
export interface WrappingKeyStore {
  readonly scheme: SessionKeyProtectionScheme;
  loadWrappingKey(): Promise<Uint8Array | null>;
  storeWrappingKey(key: Uint8Array): Promise<void>;
}

/**
 * Generic keystore-backed protector: a random 32-byte wrapping key lives in
 * the platform keystore (get-or-create, never rotated or deleted by the
 * vault), and the session key is wrapped AES-256-GCM under it into
 * `[version 0x01 | iv 12 | tag 16 | ciphertext]`. A session file copied off
 * the host is inert without the keystore item; tampering dies at the GCM tag.
 */
export class KeystoreWrappedSessionKeyProtector implements SessionKeyProtector {
  constructor(private readonly store: WrappingKeyStore) {}

  get scheme(): SessionKeyProtectionScheme {
    return this.store.scheme;
  }

  async protect(key: Uint8Array): Promise<Uint8Array> {
    if (key.length === 0) {
      throw VaultError.sessionFileError(`${this.scheme} protect requires non-empty input`);
    }

    const wrappingKey = await this.getOrCreateWrappingKey();
    try {
      const { ciphertext, iv, tag } = encrypt(wrappingKey, key, WRAP_AAD_PREFIX + this.scheme);
      const blob = new Uint8Array(1 + iv.length + tag.length + ciphertext.length);
      blob[0] = WRAP_BLOB_VERSION;
      blob.set(iv, 1);
      blob.set(tag, 1 + iv.length);
      blob.set(ciphertext, 1 + iv.length + tag.length);
      return blob;
    } finally {
      wipeBuffer(wrappingKey);
    }
  }

  async unprotect(blob: Uint8Array): Promise<Uint8Array> {
    if (blob.length === 0) {
      throw VaultError.sessionFileError(`${this.scheme} unprotect requires non-empty input`);
    }
    if (blob.length < MIN_BLOB_LENGTH) {
      throw VaultError.sessionFileError(`${this.scheme} blob is truncated`);
    }
    if (blob[0] !== WRAP_BLOB_VERSION) {
      throw VaultError.sessionFileError(`${this.scheme} blob has unknown version`);
    }

    const iv = blob.subarray(1, 1 + AES_IV_LENGTH);
    const tag = blob.subarray(1 + AES_IV_LENGTH, 1 + AES_IV_LENGTH + AES_TAG_LENGTH);
    const ciphertext = blob.subarray(1 + AES_IV_LENGTH + AES_TAG_LENGTH);

    const wrappingKey = await this.store.loadWrappingKey();
    if (wrappingKey === null) {
      throw VaultError.sessionFileError(
        `${this.scheme} wrapping key not found in the platform keystore`,
      );
    }
    try {
      this.assertKeyLength(wrappingKey);
      return decrypt(wrappingKey, ciphertext, iv, tag, WRAP_AAD_PREFIX + this.scheme);
    } catch (err) {
      if (err instanceof VaultError && err.code === ErrorCode.SESSION_FILE_ERROR) throw err;
      throw VaultError.sessionFileError(
        `${this.scheme} session key unwrap failed (tampered blob or foreign keystore item)`,
      );
    } finally {
      wipeBuffer(wrappingKey);
    }
  }

  private async getOrCreateWrappingKey(): Promise<Uint8Array> {
    const existing = await this.store.loadWrappingKey();
    if (existing !== null) {
      this.assertKeyLength(existing);
      return existing;
    }
    const fresh = generateRandomBytes(WRAPPING_KEY_LENGTH);
    try {
      await this.store.storeWrappingKey(fresh);
    } finally {
      wipeBuffer(fresh);
    }
    // Read back what actually won: a silently-failed write must not produce an
    // unwrappable blob, and a concurrent first-creation race resolves toward
    // the stored item rather than a displaced local copy.
    const stored = await this.store.loadWrappingKey();
    if (stored === null) {
      throw VaultError.sessionFileError(`${this.scheme} keystore did not persist the wrapping key`);
    }
    this.assertKeyLength(stored);
    return stored;
  }

  private assertKeyLength(key: Uint8Array): void {
    if (key.length !== WRAPPING_KEY_LENGTH) {
      wipeBuffer(key);
      throw VaultError.sessionFileError(
        `${this.scheme} keystore item has unexpected length ${key.length}`,
      );
    }
  }
}
