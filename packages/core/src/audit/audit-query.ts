import type { AuditEvent, AuditEventType } from "@harpoc/shared";
import { AAD_AUDIT_DETAIL_V2 } from "@harpoc/shared";
import { decrypt } from "../crypto/aes-gcm.js";
import type { AuditFilter, SqliteStore } from "../storage/sqlite-store.js";
import {
  AUDIT_CHAIN_GENESIS_BYTES,
  auditHmacEqual,
  computeAuditRowHmac,
  deriveAuditChainKey,
} from "./audit-chain.js";

/** Audit event with decrypted detail. */
export interface DecryptedAuditEvent extends Omit<
  AuditEvent,
  "detail_encrypted" | "detail_iv" | "detail_tag"
> {
  detail: Record<string, unknown> | null;
  /** True when a stored detail blob could not be decrypted (legacy pre-v2 AAD, or tampered). */
  detail_unreadable?: boolean;
}

/** Result of verifying the audit HMAC chain. */
export interface AuditChainVerification {
  /** All chained rows link correctly. */
  valid: boolean;
  /** Number of chained (post-migration) rows checked. */
  checked: number;
  /** Number of legacy (pre-migration, unchained) rows skipped. */
  legacy: number;
  /** Id of the first row whose link failed, if any. */
  firstBrokenId: number | null;
}

export interface AuditQueryOptions {
  secretId?: string;
  eventType?: AuditEventType;
  since?: number;
  until?: number;
  limit?: number;
}

/**
 * Queries audit log entries and decrypts their detail fields.
 */
export class AuditQuery {
  constructor(
    private readonly store: SqliteStore,
    private readonly auditKey: Uint8Array | null,
  ) {}

  query(options?: AuditQueryOptions): DecryptedAuditEvent[] {
    const filter: AuditFilter = {
      secretId: options?.secretId,
      eventType: options?.eventType,
      since: options?.since,
      until: options?.until,
      limit: options?.limit,
    };

    const events = this.store.queryAuditLog(filter);
    return events.map((event) => this.decryptEvent(event));
  }

  /**
   * Verify the audit HMAC chain. Legacy (pre-migration) rows carry no link and
   * are counted but not checked; the chain's genesis is the first chained row.
   */
  verifyChain(): AuditChainVerification {
    const rows = this.store.getAuditChainRows();
    const chainKey = this.auditKey ? deriveAuditChainKey(this.auditKey) : null;

    let prev: Uint8Array = AUDIT_CHAIN_GENESIS_BYTES;
    let checked = 0;
    let legacy = 0;
    let firstBrokenId: number | null = null;
    let valid = true;

    for (const row of rows) {
      if (row.row_hmac === null) {
        // Legacy row — reset prev to genesis, mirroring insert-time behavior.
        legacy++;
        prev = AUDIT_CHAIN_GENESIS_BYTES;
        continue;
      }
      if (!chainKey) {
        // Chained rows exist but no audit key is available to verify them.
        valid = false;
        if (firstBrokenId === null) firstBrokenId = row.id;
        break;
      }
      const expected = computeAuditRowHmac(chainKey, row, prev);
      if (!auditHmacEqual(expected, row.row_hmac)) {
        valid = false;
        if (firstBrokenId === null) firstBrokenId = row.id;
      }
      prev = row.row_hmac;
      checked++;
    }

    return { valid, checked, legacy, firstBrokenId };
  }

  private decryptEvent(event: AuditEvent): DecryptedAuditEvent {
    let detail: Record<string, unknown> | null = null;
    let detailUnreadable = false;

    if (event.detail_encrypted && event.detail_iv && event.detail_tag && this.auditKey) {
      try {
        const plaintext = decrypt(
          this.auditKey,
          event.detail_encrypted,
          event.detail_iv,
          event.detail_tag,
          AAD_AUDIT_DETAIL_V2(event.event_type, event.timestamp, event.secret_id),
        );
        detail = JSON.parse(Buffer.from(plaintext).toString("utf8")) as Record<string, unknown>;
      } catch {
        // No legacy fallback: a pre-v2 (constant-AAD) or tampered blob is
        // unreadable. Degrade per row — never throw — so one bad row cannot
        // break the whole listing; the plaintext columns stay intact.
        detail = null;
        detailUnreadable = true;
      }
    }

    return {
      id: event.id,
      timestamp: event.timestamp,
      event_type: event.event_type,
      secret_id: event.secret_id,
      principal_type: event.principal_type,
      principal_id: event.principal_id,
      detail,
      detail_unreadable: detailUnreadable,
      ip_address: event.ip_address,
      session_id: event.session_id,
      success: event.success,
    };
  }
}
