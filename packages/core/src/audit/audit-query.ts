import type { AuditEvent, AuditEventType, PrincipalType } from "@harpoc/shared";
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
  /** True when a stored detail blob could not be decrypted (tampered, or mis-bound to another row). */
  detail_unreadable?: boolean;
}

/** Outcome of checking a supplied anchor against the live chain. */
export type AuditAnchorStatus = "ok" | "row_missing" | "hmac_mismatch";

/** Anchor supplied to verifyChain: the tail link an operator exported earlier. */
export interface AuditChainAnchorInput {
  lastId: number;
  rowHmac: Uint8Array;
}

/** The newest chained row's link — what an anchor is taken from. */
export interface AuditChainTailLink {
  lastId: number;
  timestamp: number;
  rowHmac: Uint8Array;
}

/** Result of verifying the audit HMAC chain. */
export interface AuditChainVerification {
  /** Every row carries a link that verifies AND (when an anchor was supplied) the anchored row is intact. */
  valid: boolean;
  /** Rows whose link was verified (an unlinked row is a break and is not counted). */
  checked: number;
  /** Id of the first row whose link is missing or does not verify, else null. */
  firstBrokenId: number | null;
  /** Present only when an anchor was supplied. */
  anchor?: { lastId: number; status: AuditAnchorStatus };
}

export interface AuditQueryOptions {
  secretId?: string;
  eventType?: AuditEventType;
  since?: number;
  until?: number;
  limit?: number;
  success?: boolean;
  principalType?: PrincipalType;
  principalId?: string;
  /** Secret ids a scoped caller may see (L10) — applied inside the query, ahead of `limit`. */
  visibleSecretIds?: string[];
}

/**
 * Queries audit log entries and decrypts their detail fields.
 */
export class AuditQuery {
  constructor(
    private readonly store: SqliteStore,
    private readonly auditKey: Uint8Array,
  ) {}

  query(options?: AuditQueryOptions): DecryptedAuditEvent[] {
    const filter: AuditFilter = {
      secretId: options?.secretId,
      eventType: options?.eventType,
      since: options?.since,
      until: options?.until,
      limit: options?.limit,
      success: options?.success,
      principalType: options?.principalType,
      principalId: options?.principalId,
      visibleSecretIds: options?.visibleSecretIds,
    };

    const events = this.store.queryAuditLog(filter);
    return events.map((event) => this.decryptEvent(event));
  }

  /** The newest row's link — the anchorable tail — or null when the log is empty or its last row carries no link. */
  chainTail(): AuditChainTailLink | null {
    const row = this.store.getLastAuditRow();
    if (!row || row.row_hmac === null) return null;
    return { lastId: row.id, timestamp: row.timestamp, rowHmac: row.row_hmac };
  }

  /**
   * Verify the audit HMAC chain. Every row carries a link — the column has
   * been written by every logger since migration 010 and no vault created
   * before it can open under v1.5 (audit C30) — so a NULL link is an erased
   * link and breaks the chain at that row. The row after a missing link is
   * verified against genesis — what the writer chains from over an unlinked
   * tail — so rows appended after the break still verify, while a mid-chain
   * erasure also breaks the row that was chained onto the erased link.
   *
   * With an anchor, additionally assert the anchored row still exists with
   * exactly that link — a valid-but-shorter chain (tail truncation, database
   * rollback) is invisible to the link HMACs alone. Rows appended after the
   * anchor do not affect the anchor check.
   */
  verifyChain(anchor?: AuditChainAnchorInput): AuditChainVerification {
    const rows = this.store.getAuditChainRows();
    const chainKey = deriveAuditChainKey(this.auditKey);

    let prev: Uint8Array = AUDIT_CHAIN_GENESIS_BYTES;
    let checked = 0;
    let firstBrokenId: number | null = null;
    let valid = true;
    let anchorStatus: AuditAnchorStatus = "row_missing";

    for (const row of rows) {
      if (anchor && row.id === anchor.lastId) {
        anchorStatus =
          row.row_hmac !== null && auditHmacEqual(row.row_hmac, anchor.rowHmac)
            ? "ok"
            : "hmac_mismatch";
      }
      if (row.row_hmac === null) {
        valid = false;
        if (firstBrokenId === null) firstBrokenId = row.id;
        prev = AUDIT_CHAIN_GENESIS_BYTES;
        continue;
      }
      const expected = computeAuditRowHmac(chainKey, row, prev);
      if (!auditHmacEqual(expected, row.row_hmac)) {
        valid = false;
        if (firstBrokenId === null) firstBrokenId = row.id;
      }
      prev = row.row_hmac;
      checked++;
    }

    if (!anchor) {
      return { valid, checked, firstBrokenId };
    }
    return {
      valid: valid && anchorStatus === "ok",
      checked,
      firstBrokenId,
      anchor: { lastId: anchor.lastId, status: anchorStatus },
    };
  }

  private decryptEvent(event: AuditEvent): DecryptedAuditEvent {
    let detail: Record<string, unknown> | null = null;
    let detailUnreadable = false;

    if (event.detail_encrypted && event.detail_iv && event.detail_tag) {
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
        // No fallback: a blob that fails the row-bound AAD is tampered or
        // mis-bound. Degrade per row — never throw — so one bad row cannot
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
