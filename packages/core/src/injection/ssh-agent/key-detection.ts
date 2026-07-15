/**
 * Armor/header detection shared by the import-time classifier
 * (key-import.ts) and the use-time loader guard (key-loader.ts) — a single
 * source of truth so the two cannot drift: a format one detector matches and
 * the other misses would be accepted at import yet fail at use with the
 * wrong recovery message, or vice versa.
 */
export const PKCS8_ENCRYPTED_ARMOR = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
export const OPENSSH_ARMOR = "-----BEGIN OPENSSH PRIVATE KEY-----";
export const LEGACY_KEY_ARMOR = /-----BEGIN (?:RSA|EC|DSA) PRIVATE KEY-----/;
export const ANY_KEY_ARMOR = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
export const LEGACY_ENCRYPTED_HEADER = /Proc-Type:\s*4\s*,\s*ENCRYPTED/i;

/** True when the PEM text carries an encrypted PKCS#8 armor or a legacy encryption header. */
export function hasEncryptedPemMarker(pem: string): boolean {
  return pem.includes(PKCS8_ENCRYPTED_ARMOR) || LEGACY_ENCRYPTED_HEADER.test(pem);
}

const PEM_BLOCK_LABELS = /-----BEGIN ([A-Z0-9 ]+?)-----/g;

/**
 * True when the material carries PEM blocks beyond a single private key —
 * the combined cert-chain + key layout (nginx/haproxy). Decrypting only the
 * key block would silently drop the companion blocks from the stored value.
 */
export function hasCompanionPemBlocks(material: string): boolean {
  const labels = [...material.matchAll(PEM_BLOCK_LABELS)].map((m) => (m[1] as string).trim());
  const keyBlocks = labels.filter((label) => label.endsWith("PRIVATE KEY"));
  return labels.length > keyBlocks.length || keyBlocks.length > 1;
}
