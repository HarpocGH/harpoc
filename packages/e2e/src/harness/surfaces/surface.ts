/**
 * The access surfaces the demonstration matrix drives. Five drivers over four
 * access interfaces: MCP is one interface with two transports (design §3.5), so
 * `mcp-http` represents it in the 6 × 4 = 24-cell matrix and `mcp-stdio` is
 * reported beside it as transport coverage.
 *
 * `interfaceId` is what the matrix counts; `name` is what the evidence record
 * carries, so the two never have to be re-derived from each other downstream.
 */
export type SurfaceName = "mcp-http" | "mcp-stdio" | "rest" | "sdk" | "cli";
export type InterfaceId = "mcp" | "rest" | "sdk" | "cli";

export interface CallOutcome {
  ok: boolean;
  result?: unknown;
  /**
   * The joined text of the surface's response — on ok results the
   * JSON-serialized use_secret response, so arms parse it instead of
   * re-implementing the per-surface unwrapping locally.
   */
  text: string;
  errorText?: string;
  /**
   * Raw child output, for the surfaces that spawn one (`cli`). The credential
   * has to be absent from a real process's own streams, not merely from the
   * structured result the harness parsed out of them.
   */
  stdout?: string;
  stderr?: string;
}

export interface Surface {
  name: SurfaceName;
  interfaceId: InterfaceId;
  /**
   * The audit `detail.interface` value the vault stamps for calls arriving
   * through this surface, or undefined when the surface is the trusted local
   * path and writes principal-less rows.
   */
  auditInterface?: string;
  /** The token subject the vault attributes this surface's calls to. */
  principal?: string;
  callUseSecret(handle: string, action: unknown): Promise<CallOutcome>;
  close(): Promise<void>;
}
