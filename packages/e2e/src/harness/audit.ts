import type { HarnessVault } from "./vault.js";

/** The audit-row fields the arms inspect. */
export interface AuditRow {
  success: boolean;
  detail: Record<string, unknown> | null;
  principal_id?: string | null;
  principal_type?: string | null;
}

export function detailString(row: AuditRow, key: string): string | undefined {
  const value = (row.detail ?? {})[key];
  return typeof value === "string" ? value : undefined;
}

/**
 * Which rows an assertion is about. Every field narrows: `context` picks the
 * execution context, `principal` the surface that issued the call (the
 * demonstration loop runs five surfaces against one vault, and `rest` and `sdk`
 * share an interface, so the principal is what tells their rows apart), and
 * `server` the downstream MCP server when one context has two variants.
 */
export interface AttributionExpectation {
  context: string;
  /** Expected `detail.interface`; omit for the trusted local path (see `trustedLocal`). */
  interface?: string;
  principal?: string;
  server?: string;
  /**
   * The trusted-local posture: the row must carry NO principal columns and no
   * interface tag. Asserted, not ignored — it is the thesis §4.7 split, and a
   * silently attributed row would mean the opposite of what the cell claims.
   */
  trustedLocal?: boolean;
}

function matches(row: AuditRow, want: AttributionExpectation): boolean {
  if (row.success !== true) return false;
  if (detailString(row, "context") !== want.context) return false;
  if (want.server !== undefined && detailString(row, "server") !== want.server) return false;
  if (want.trustedLocal === true) {
    return (row.principal_id ?? null) === null && detailString(row, "interface") === undefined;
  }
  if (want.principal !== undefined && row.principal_id !== want.principal) return false;
  if (want.interface !== undefined && detailString(row, "interface") !== want.interface) {
    return false;
  }
  return true;
}

/**
 * The V2 attribution pin every context arm asserts: a successful `secret.use`
 * row exists for the expectation, and the HMAC chain still verifies. Throws
 * (the opacity-helper convention) so it works outside vitest too.
 */
export function expectAttributedSuccess(
  vault: HarnessVault,
  expectation: string | AttributionExpectation,
): void {
  const want: AttributionExpectation =
    typeof expectation === "string" ? { context: expectation, interface: "mcp-http" } : expectation;

  const rows = vault.engine.queryAudit({ eventType: "secret.use" }) as unknown as AuditRow[];
  const hit = rows.find((row) => matches(row, want));
  if (!hit) {
    const seen = rows
      .filter((row) => row.success === true)
      .map(
        (row) =>
          `${detailString(row, "context") ?? "?"}/${detailString(row, "interface") ?? "-"}` +
          `/${row.principal_id ?? "-"}`,
      );
    throw new Error(
      `no successful secret.use row matching ${JSON.stringify(want)}; saw: ${seen.join(", ") || "none"}`,
    );
  }
  if (!vault.engine.verifyAuditChain().valid) {
    throw new Error("audit chain does not verify after the arm ran");
  }
}
