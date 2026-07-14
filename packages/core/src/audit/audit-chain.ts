import { createHmac, timingSafeEqual } from "node:crypto";
import { AUDIT_CHAIN_GENESIS, AUDIT_CHAIN_KEY_LABEL } from "@harpoc/shared";

/** Fields covered by a row's chain HMAC (everything but the autoincrement id). */
export interface AuditChainFields {
  timestamp: number;
  event_type: string;
  secret_id: string | null;
  principal_type: string | null;
  principal_id: string | null;
  detail_encrypted: Uint8Array | null;
  detail_iv: Uint8Array | null;
  detail_tag: Uint8Array | null;
  ip_address: string | null;
  session_id: string | null;
  success: boolean;
}

/** Genesis link seeding the first row's chain. */
export const AUDIT_CHAIN_GENESIS_BYTES: Uint8Array = new Uint8Array(
  Buffer.from(AUDIT_CHAIN_GENESIS, "utf8"),
);

/** Derive the chain HMAC key from the audit key (domain-separated from AES-GCM use). */
export function deriveAuditChainKey(auditKey: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac("sha256", auditKey).update(AUDIT_CHAIN_KEY_LABEL).digest());
}

/** Length-prefixed, presence-flagged field encoding — unambiguous and deterministic. */
function encodeField(buf: Uint8Array | null): Buffer {
  if (buf === null) return Buffer.from([0]);
  const header = Buffer.alloc(5);
  header.writeUInt8(1, 0);
  header.writeUInt32BE(buf.length, 1);
  return Buffer.concat([header, Buffer.from(buf)]);
}

function strBytes(s: string | null): Uint8Array | null {
  return s === null ? null : new Uint8Array(Buffer.from(s, "utf8"));
}

/**
 * Compute the chain HMAC over a row's fields plus the previous row's link. The
 * autoincrement id is deliberately excluded (unknown before insert; ordering
 * integrity comes from the links themselves).
 */
export function computeAuditRowHmac(
  chainKey: Uint8Array,
  fields: AuditChainFields,
  prev: Uint8Array,
): Uint8Array {
  const ts = Buffer.alloc(8);
  ts.writeBigUInt64BE(BigInt(fields.timestamp));
  const parts = [
    encodeField(new Uint8Array(ts)),
    encodeField(strBytes(fields.event_type)),
    encodeField(strBytes(fields.secret_id)),
    encodeField(strBytes(fields.principal_type)),
    encodeField(strBytes(fields.principal_id)),
    encodeField(fields.detail_encrypted),
    encodeField(fields.detail_iv),
    encodeField(fields.detail_tag),
    encodeField(strBytes(fields.ip_address)),
    encodeField(strBytes(fields.session_id)),
    encodeField(new Uint8Array([fields.success ? 1 : 0])),
    encodeField(prev),
  ];
  return new Uint8Array(createHmac("sha256", chainKey).update(Buffer.concat(parts)).digest());
}

/** Constant-time link comparison; unequal lengths are a mismatch, not a throw. */
export function auditHmacEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
