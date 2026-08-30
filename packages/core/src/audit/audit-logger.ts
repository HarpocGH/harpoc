import type { AuditEventType, PrincipalType } from "@harpoc/shared";
import { AAD_AUDIT_DETAIL_V2 } from "@harpoc/shared";
import { encrypt } from "../crypto/aes-gcm.js";
import type { SqliteStore } from "../storage/sqlite-store.js";
import {
  AUDIT_CHAIN_GENESIS_BYTES,
  computeAuditRowHmac,
  deriveAuditChainKey,
} from "./audit-chain.js";

export interface AuditLogOptions {
  eventType: AuditEventType;
  secretId?: string;
  principalType?: PrincipalType;
  principalId?: string;
  detail?: Record<string, unknown>;
  ipAddress?: string;
  sessionId?: string;
  success?: boolean;
}

/**
 * Writes encrypted audit log entries to the database.
 *
 * Detail ciphertext is bound to the row via a row-specific AAD (v2), and each
 * row carries an HMAC chain link over its fields plus the previous link, so a
 * holder of DB write access (but not the audit key) cannot swap detail blobs
 * between rows, tamper with the plaintext columns, or delete a row undetected.
 */
export class AuditLogger {
  private readonly chainKey: Uint8Array;

  constructor(
    private readonly store: SqliteStore,
    private readonly auditKey: Uint8Array,
  ) {
    this.chainKey = deriveAuditChainKey(auditKey);
  }

  log(options: AuditLogOptions): number {
    const {
      eventType,
      secretId,
      principalType,
      principalId,
      detail,
      ipAddress,
      sessionId,
      success = true,
    } = options;

    const timestamp = Date.now();

    let detailEncrypted: Uint8Array | null = null;
    let detailIv: Uint8Array | null = null;
    let detailTag: Uint8Array | null = null;

    if (detail) {
      const plaintext = new Uint8Array(Buffer.from(JSON.stringify(detail), "utf8"));
      const encrypted = encrypt(
        this.auditKey,
        plaintext,
        AAD_AUDIT_DETAIL_V2(eventType, timestamp, secretId ?? null),
      );
      detailEncrypted = encrypted.ciphertext;
      detailIv = encrypted.iv;
      detailTag = encrypted.tag;
    }

    const eventRow = {
      timestamp,
      event_type: eventType,
      secret_id: secretId ?? null,
      principal_type: principalType ?? null,
      principal_id: principalId ?? null,
      detail_encrypted: detailEncrypted,
      detail_iv: detailIv,
      detail_tag: detailTag,
      ip_address: ipAddress ?? null,
      session_id: sessionId ?? null,
      success,
    };

    // SELECT-last + compute + INSERT in one transaction so concurrent writers
    // serialize on SQLite's lock and the chain stays linear.
    return this.store.transaction(() => {
      const prev = this.store.getLastAuditRow()?.row_hmac ?? AUDIT_CHAIN_GENESIS_BYTES;
      const rowHmac = computeAuditRowHmac(this.chainKey, eventRow, prev);
      return this.store.insertAuditEvent(eventRow, rowHmac);
    });
  }
}
