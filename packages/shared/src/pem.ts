/**
 * Passphrase-protected private-key PEM detection: PKCS#8 "ENCRYPTED PRIVATE KEY"
 * and legacy PEM "Proc-Type: 4,ENCRYPTED". OpenSSH-format encryption is not
 * header-detectable here and is refused downstream by the key parser (D3).
 */
export function isEncryptedPrivateKeyPem(pem: string): boolean {
  return (
    pem.includes("-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
    /Proc-Type:\s*4\s*,\s*ENCRYPTED/i.test(pem)
  );
}
