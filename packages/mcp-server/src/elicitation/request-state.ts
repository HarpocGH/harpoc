import { randomBytes } from "node:crypto";
import { createRequestStateCodec } from "@modelcontextprotocol/server";

/**
 * What a value-collection round carries across the retry: the collector, the
 * caller, the operation, the namespaced target.
 */
export interface ValueRequestState {
  collector: string;
  principal: string;
  operation: "create" | "rotate";
  target: string;
}

/**
 * One codec per process: the modern leg builds a vault server per request, so
 * the key that seals a round's state must outlive any one server (the SDK's
 * own note on `createRequestStateCodec`). Five minutes, the collector's own
 * budget; a state past it names a collector that has already closed.
 */
export const VALUE_REQUEST_STATE_TTL_SECONDS = 5 * 60;

export const valueRequestState = createRequestStateCodec<ValueRequestState>({
  key: randomBytes(32),
  ttlSeconds: VALUE_REQUEST_STATE_TTL_SECONDS,
});
