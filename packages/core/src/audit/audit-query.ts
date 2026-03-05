import type { AuditEvent, AuditEventType } from "@harpoc/shared";
import { AAD_AUDIT_DETAIL } from "@harpoc/shared";
import { decrypt } from "../crypto/aes-gcm.js";
import type { AuditFilter, SqliteStore } from "../storage/sqlite-store.js";

/** Audit event with decrypted detail. */
export interface DecryptedAuditEvent extends Omit<
  AuditEvent,
  "detail_encrypted" | "detail_iv" | "detail_tag"
> {
  detail: Record<string, unknown> | null;
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

  private decryptEvent(event: AuditEvent): DecryptedAuditEvent {
    let detail: Record<string, unknown> | null = null;

    if (event.detail_encrypted && event.detail_iv && event.detail_tag && this.auditKey) {
      try {
        const plaintext = decrypt(
          this.auditKey,
          event.detail_encrypted,
          event.detail_iv,
          event.detail_tag,
          AAD_AUDIT_DETAIL,
        );
        detail = JSON.parse(Buffer.from(plaintext).toString("utf8")) as Record<string, unknown>;
      } catch {
        // If decryption or parse fails, return null detail
        detail = null;
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
      ip_address: event.ip_address,
      session_id: event.session_id,
      success: event.success,
    };
  }
}
