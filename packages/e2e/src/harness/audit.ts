import type { HarnessVault } from "./vault.js";

/** The two audit-row fields the arms inspect. */
export interface AuditRow {
  success: boolean;
  detail: Record<string, unknown> | null;
}

export function detailString(row: AuditRow, key: string): string | undefined {
  const value = (row.detail ?? {})[key];
  return typeof value === "string" ? value : undefined;
}

/**
 * The V2 attribution pin every context arm asserts: a successful `secret.use`
 * row for `context` exists, its detail names the mcp-http interface, and the
 * HMAC chain still verifies. One implementation — previously pasted verbatim
 * into each arm file, where a shape change had to be fixed in three places.
 * Throws (the opacity-helper convention) so it works outside vitest too.
 */
export function expectAttributedSuccess(vault: HarnessVault, context: string): void {
  const rows = vault.engine.queryAudit({ eventType: "secret.use" }) as unknown as AuditRow[];
  const success = rows.find((r) => r.success === true && detailString(r, "context") === context);
  if (!success) {
    throw new Error(`no successful secret.use audit row with detail.context === "${context}"`);
  }
  const iface = detailString(success, "interface");
  if (iface !== "mcp-http") {
    throw new Error(
      `successful ${context} audit row is attributed to ${JSON.stringify(iface)}, not "mcp-http"`,
    );
  }
  if (!vault.engine.verifyAuditChain().valid) {
    throw new Error("audit chain does not verify after the arm ran");
  }
}
