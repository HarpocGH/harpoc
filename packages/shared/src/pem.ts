/**
 * Passphrase-protected private-key PEM detection: PKCS#8 "ENCRYPTED PRIVATE KEY"
 * and legacy PEM "Proc-Type: 4,ENCRYPTED". OpenSSH-format encryption is not
 * header-detectable here and is refused downstream by the key parser (D3).
 * This file also carries the shared import-refusal text
 * (`ENCRYPTED_KEY_IMPORT_REFUSAL`), so the REST and SDK surfaces cannot drift apart.
 */
export function isEncryptedPrivateKeyPem(pem: string): boolean {
  return (
    pem.includes("-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
    /Proc-Type:\s*4\s*,\s*ENCRYPTED/i.test(pem)
  );
}

/**
 * Refusal text for passphrase-protected private keys on the REST/SDK import
 * paths (D3, Phase 10). One constant so the surfaces cannot drift apart.
 */
export const ENCRYPTED_KEY_IMPORT_REFUSAL =
  "private_key_pem is passphrase-protected — decrypt it first or import via 'harpoc cert import', which prompts for the passphrase (D3)";
