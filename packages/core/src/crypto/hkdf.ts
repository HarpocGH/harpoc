import { hkdf } from "node:crypto";
import { AES_KEY_LENGTH, ErrorCode, VaultError } from "@harpoc/shared";

/**
 * Derive a subkey using HKDF-SHA256.
 *
 * @param ikm - Input key material
 * @param salt - Salt (typically vaultId)
 * @param info - Context string from HKDF_INFO_* constants
 * @param length - Output length in bytes (default: 32)
 */
export function deriveSubkey(
  ikm: Uint8Array,
  salt: string,
  info: string,
  length: number = AES_KEY_LENGTH,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    hkdf("sha256", ikm, salt, info, length, (err, derivedKey) => {
      if (err) {
        reject(
          new VaultError(ErrorCode.KEY_DERIVATION_ERROR, `HKDF derivation failed: ${err.message}`),
        );
        return;
      }
      resolve(new Uint8Array(derivedKey));
    });
  });
}
