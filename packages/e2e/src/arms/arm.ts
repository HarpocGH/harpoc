import type { CallOutcome } from "../harness/surfaces/surface.js";

export type { CallOutcome } from "../harness/surfaces/surface.js";

/**
 * The C-3 two-arm split: every attack scenario runs its payload twice, once
 * against the §2.3 status quo and once against Harpoc, and *only the
 * credential-handling layer varies*.
 *
 * Both arms are reached by an MCP client over the same Streamable HTTP
 * transport, and both are handed the same `action` object. What differs is the
 * server answering: the vault, which mediates the injection, versus a naive
 * server holding the credential in its launch environment (Listing 2.1). That
 * is what lets a paired row attribute the difference to the vault rather than
 * to the payload, the transport or the backend.
 *
 * `invoke` takes the handle for signature symmetry only — the baseline has no
 * concept of one, since its credential is an environment variable, and it
 * ignores the argument.
 */
export interface Arm {
  name: "baseline" | "harpoc";
  invoke(handle: string, action: unknown): Promise<CallOutcome>;
  /**
   * Everything an agent can learn about stored credentials *without* invoking
   * one: the listing, the per-secret metadata, the resources and a deliberately
   * failing call's error text. §6.2.1's claim is about this surface as a whole,
   * so it is probed as a whole rather than one tool at a time.
   */
  probeMetadata(handle?: string): Promise<CallOutcome>;
  close(): Promise<void>;
}
