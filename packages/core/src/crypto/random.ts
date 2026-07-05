import { randomBytes } from "node:crypto";

/**
 * Generate cryptographically secure random bytes.
 */
export function generateRandomBytes(length: number): Uint8Array {
  return new Uint8Array(randomBytes(length));
}

/**
 * Generate a UUIDv7 per RFC 9562: 48-bit ms timestamp + version 7 + random.
 */
export function generateUUIDv7(): string {
  const now = Date.now();

  // 48-bit millisecond timestamp
  const timeBits = new Uint8Array(6);
  timeBits[0] = (now / 2 ** 40) & 0xff;
  timeBits[1] = (now / 2 ** 32) & 0xff;
  timeBits[2] = (now / 2 ** 24) & 0xff;
  timeBits[3] = (now / 2 ** 16) & 0xff;
  timeBits[4] = (now / 2 ** 8) & 0xff;
  timeBits[5] = now & 0xff;

  // 10 random bytes
  const rand = randomBytes(10);

  // Build 16-byte UUID
  const uuid = new Uint8Array(16);
  uuid.set(timeBits, 0);
  uuid.set(rand, 6);

  // Set version 7: bits 48-51 = 0111
  uuid[6] = ((uuid[6] ?? 0) & 0x0f) | 0x70;
  // Set variant 10: bits 64-65 = 10
  uuid[8] = ((uuid[8] ?? 0) & 0x3f) | 0x80;

  // Format as string
  const hex = Buffer.from(uuid).toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}

/**
 * Securely wipe a buffer by overwriting it with zeros (thesis §4.6 memory
 * hygiene). The session-file secure erase intentionally uses random bytes
 * instead — that is a file-erasure mechanism, not this one.
 */
export function wipeBuffer(buf: Uint8Array): void {
  buf.fill(0);
}
