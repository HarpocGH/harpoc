import { VaultError } from "@harpoc/shared";

/*
 * Minimal DER writer covering the subset PKCS#10 needs: definite lengths only,
 * the universal tags BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL, OID,
 * UTF8String, PrintableString, IA5String, SEQUENCE and SET, plus
 * context-specific tags 0-30. Indefinite lengths, the high-tag-number form and
 * negative INTEGERs are out of scope and are rejected rather than approximated.
 * SET children are emitted in the order given -- a multi-element SET OF must be
 * sorted by the caller.
 */

const TAG_BOOLEAN = 0x01;
const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_NULL = 0x05;
const TAG_OID = 0x06;
const TAG_UTF8_STRING = 0x0c;
const TAG_PRINTABLE_STRING = 0x13;
const TAG_IA5_STRING = 0x16;
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;

const MAX_ARC = 0x7fffffff;
const MAX_CONTEXT_TAG = 30;
const PRINTABLE_RE = /^[A-Za-z0-9 '()+,./:=?-]*$/;
const TEXT_ENCODER = new TextEncoder();

function derLength(n: number): Uint8Array {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes: number[] = [];
  let rest = n;
  while (rest > 0) {
    bytes.unshift(rest % 256);
    rest = Math.floor(rest / 256);
  }
  return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  const length = derLength(content.length);
  const out = new Uint8Array(1 + length.length + content.length);
  out[0] = tag;
  out.set(length, 1);
  out.set(content, 1 + length.length);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function base128(value: number): number[] {
  if (value === 0) return [0];
  const out: number[] = [];
  let rest = value;
  while (rest > 0) {
    out.unshift((rest % 128) | (out.length > 0 ? 0x80 : 0));
    rest = Math.floor(rest / 128);
  }
  return out;
}

export function derSequence(children: Uint8Array[]): Uint8Array {
  return tlv(TAG_SEQUENCE, concat(children));
}

export function derSet(children: Uint8Array[]): Uint8Array {
  return tlv(TAG_SET, concat(children));
}

export function derOid(dotted: string): Uint8Array {
  const parts = dotted.split(".");
  if (parts.length < 2) throw VaultError.certCsrFailed("OID needs at least two arcs");
  const arcs = parts.map((part) => {
    if (!/^\d+$/.test(part)) throw VaultError.certCsrFailed("OID arc is not a decimal number");
    const arc = Number(part);
    if (arc > MAX_ARC) throw VaultError.certCsrFailed("OID arc exceeds the supported range");
    return arc;
  });
  const [first = 0, second = 0] = arcs;
  if (first > 2) throw VaultError.certCsrFailed("OID first arc must be 0, 1 or 2");
  if (first < 2 && second > 39) throw VaultError.certCsrFailed("OID second arc must be below 40");
  const content = [
    ...base128(first * 40 + second),
    ...arcs.slice(2).flatMap((arc) => base128(arc)),
  ];
  return tlv(TAG_OID, Uint8Array.from(content));
}

export function derInteger(value: number): Uint8Array {
  if (!Number.isSafeInteger(value))
    throw VaultError.certCsrFailed("INTEGER must be a safe integer");
  if (value < 0) throw VaultError.certCsrFailed("INTEGER must be non-negative");
  const bytes: number[] = [];
  let rest = value;
  while (rest > 0) {
    bytes.unshift(rest % 256);
    rest = Math.floor(rest / 256);
  }
  if (bytes.length === 0) bytes.push(0);
  if (((bytes[0] ?? 0) & 0x80) !== 0) bytes.unshift(0);
  return tlv(TAG_INTEGER, Uint8Array.from(bytes));
}

export function derBoolean(v: boolean): Uint8Array {
  return tlv(TAG_BOOLEAN, Uint8Array.of(v ? 0xff : 0x00));
}

export function derNull(): Uint8Array {
  return tlv(TAG_NULL, new Uint8Array(0));
}

export function derUtf8String(s: string): Uint8Array {
  return tlv(TAG_UTF8_STRING, TEXT_ENCODER.encode(s));
}

export function derPrintableString(s: string): Uint8Array {
  if (!PRINTABLE_RE.test(s)) {
    throw VaultError.certCsrFailed("PrintableString contains an unsupported character");
  }
  return tlv(TAG_PRINTABLE_STRING, TEXT_ENCODER.encode(s));
}

export function derIa5String(s: string): Uint8Array {
  for (let i = 0; i < s.length; i += 1) {
    if (s.charCodeAt(i) > 0x7f) {
      throw VaultError.certCsrFailed("IA5String contains a non-ASCII character");
    }
  }
  return tlv(TAG_IA5_STRING, TEXT_ENCODER.encode(s));
}

export function derBitString(bytes: Uint8Array): Uint8Array {
  const content = new Uint8Array(bytes.length + 1);
  content.set(bytes, 1);
  return tlv(TAG_BIT_STRING, content);
}

export function derOctetString(bytes: Uint8Array): Uint8Array {
  return tlv(TAG_OCTET_STRING, bytes);
}

export function derContext(
  tagNumber: number,
  constructed: boolean,
  content: Uint8Array,
): Uint8Array {
  if (!Number.isInteger(tagNumber) || tagNumber < 0 || tagNumber > MAX_CONTEXT_TAG) {
    throw VaultError.certCsrFailed("context tag number out of range");
  }
  return tlv(0x80 | (constructed ? 0x20 : 0) | tagNumber, content);
}
