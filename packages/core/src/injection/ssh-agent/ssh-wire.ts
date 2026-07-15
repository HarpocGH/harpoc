/**
 * SSH wire-format primitives (RFC 4251 §5) and the public-key / signature blob
 * codecs the ephemeral agent needs. All integers are big-endian. Types:
 *   byte    a single octet
 *   uint32  4-byte unsigned
 *   string  uint32 length followed by that many bytes (arbitrary binary)
 *   mpint   a string holding a two's-complement big-endian integer; a leading
 *           0x00 is present when the high bit would otherwise be set. Only
 *           non-negative values occur here.
 *
 * This module contains no cryptography — it is pure framing, so the vault owns
 * the agent protocol without a third-party dependency.
 */

const MAX_STRING = 512 * 1024; // frames carrying a private-key signature are small; cap defensively

/** Sequential big-endian reader over a Buffer with bounds checking. */
export class SshReader {
  private offset = 0;

  constructor(private readonly buf: Buffer) {}

  get remaining(): number {
    return this.buf.length - this.offset;
  }

  readByte(): number {
    if (this.remaining < 1) throw new Error("ssh-wire: truncated byte");
    const v = this.buf.readUInt8(this.offset);
    this.offset += 1;
    return v;
  }

  readUint32(): number {
    if (this.remaining < 4) throw new Error("ssh-wire: truncated uint32");
    const v = this.buf.readUInt32BE(this.offset);
    this.offset += 4;
    return v;
  }

  readString(): Buffer {
    const len = this.readUint32();
    if (len > MAX_STRING) throw new Error("ssh-wire: string length exceeds cap");
    if (this.remaining < len) throw new Error("ssh-wire: truncated string");
    const v = this.buf.subarray(this.offset, this.offset + len);
    this.offset += len;
    return v;
  }

  readCString(): string {
    return this.readString().toString("utf8");
  }

  /** Read an mpint and return its magnitude as a big-endian byte buffer (no sign byte). */
  readMpint(): Buffer {
    const raw = this.readString();
    let i = 0;
    while (i < raw.length - 1 && raw[i] === 0) i++; // strip sign/leading zero bytes
    return raw.subarray(i);
  }
}

/** Serialize an SSH `string` (uint32 length prefix + bytes). */
export function writeString(data: Buffer | string): Buffer {
  const body = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  const len = Buffer.allocUnsafe(4);
  len.writeUInt32BE(body.length, 0);
  return Buffer.concat([len, body]);
}

export function writeUint32(value: number): Buffer {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(value >>> 0, 0);
  return b;
}

export function writeByte(value: number): Buffer {
  return Buffer.from([value & 0xff]);
}

/**
 * Serialize a non-negative big-endian integer as an SSH `mpint`: strip leading
 * zero bytes, then prepend one 0x00 if the top bit is set so the value reads as
 * positive. Zero encodes as an empty string.
 */
export function writeMpint(magnitude: Buffer): Buffer {
  let i = 0;
  while (i < magnitude.length && magnitude[i] === 0) i++;
  const trimmed = magnitude.subarray(i);
  if (trimmed.length === 0) return writeString(Buffer.alloc(0));
  const first = trimmed[0] as number;
  const body = first & 0x80 ? Buffer.concat([Buffer.from([0x00]), trimmed]) : trimmed;
  return writeString(body);
}

// --- Public-key blobs -------------------------------------------------------

export function ed25519PublicKeyBlob(a: Buffer): Buffer {
  return Buffer.concat([writeString("ssh-ed25519"), writeString(a)]);
}

export function rsaPublicKeyBlob(e: Buffer, n: Buffer): Buffer {
  return Buffer.concat([writeString("ssh-rsa"), writeMpint(e), writeMpint(n)]);
}

/** `curve` is the SSH id ("nistp256"/"nistp384"/"nistp521"); `q` is the uncompressed point (0x04‖x‖y). */
export function ecdsaPublicKeyBlob(curve: string, q: Buffer): Buffer {
  return Buffer.concat([writeString(`ecdsa-sha2-${curve}`), writeString(curve), writeString(q)]);
}

// --- Signature blobs --------------------------------------------------------

/** SSH signature = string(format id) ‖ string(raw signature bytes). */
export function encodeSignature(formatId: string, rawSignature: Buffer): Buffer {
  return Buffer.concat([writeString(formatId), writeString(rawSignature)]);
}

/**
 * ECDSA signature: node:crypto with dsaEncoding "ieee-p1363" yields fixed-width
 * r‖s; re-encode as the SSH inner blob mpint(r) ‖ mpint(s), then wrap.
 */
export function encodeEcdsaSignature(formatId: string, rs: Buffer): Buffer {
  const half = rs.length / 2;
  const r = rs.subarray(0, half);
  const s = rs.subarray(half);
  const inner = Buffer.concat([writeMpint(r), writeMpint(s)]);
  return encodeSignature(formatId, inner);
}
