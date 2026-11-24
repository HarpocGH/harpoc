/** The key types a bootstrap block admits for a host key: the default HostKey types the 8.4 floor and the current release share. */
export const SSH_HOST_KEY_TYPES = [
  "ssh-ed25519",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "ssh-rsa",
] as const;

/** The key types a bootstrap may install: what sshd accepts by default at 8.4 and at the current release, no certificate. */
export const SSH_INSTALL_KEY_TYPES = [
  ...SSH_HOST_KEY_TYPES,
  "sk-ssh-ed25519@openssh.com",
  "sk-ecdsa-sha2-nistp256@openssh.com",
] as const;

export const MAX_SSH_KEY_LINE_CHARS = 4096;

const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * The type of `<type> <base64>`, a public key line with nothing else, when `type` is
 * listed, the base64 is canonical (padded, no stray bits) and the blob's first
 * length-prefixed string is that type; otherwise `null`.
 */
export function sshKeyLineType(line: string, types: readonly string[]): string | null {
  if (line.length > MAX_SSH_KEY_LINE_CHARS) return null;
  const space = line.indexOf(" ");
  if (space < 1) return null;
  const type = line.slice(0, space);
  const base64 = line.slice(space + 1);
  if (!types.includes(type) || !CANONICAL_BASE64.test(base64)) return null;
  const bytes = atob(base64);
  if (btoa(bytes) !== base64 || bytes.length < 4) return null;
  const length =
    bytes.charCodeAt(0) * 0x1000000 +
    (bytes.charCodeAt(1) << 16) +
    (bytes.charCodeAt(2) << 8) +
    bytes.charCodeAt(3);
  if (length !== type.length || bytes.length <= 4 + length) return null;
  return bytes.slice(4, 4 + length) === type ? type : null;
}
