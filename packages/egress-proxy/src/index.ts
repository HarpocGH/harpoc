// Proxy
export { createEgressProxy } from "./proxy.js";
export type { EgressProxy, EgressProxyOptions, ProxyEngine } from "./proxy.js";

// CONNECT mode (B8)
export { DEFAULT_LEAF_CACHE_SIZE, DEFAULT_LEAF_TTL_MS, createLeafCache } from "./ca.js";
export type { LeafCache, LeafCacheOptions, LeafIssuer, ProxyCaOptions } from "./ca.js";
export { CONNECT_ESTABLISHED, parseConnectTarget } from "./connect.js";
export type { ConnectTargetParse } from "./connect.js";

// Placeholders
export { findPlaceholder, parsePlaceholder } from "./placeholder.js";
export type { Placeholder, PlaceholderMatch, PlaceholderScan, Placement } from "./placeholder.js";

// Credential swap
export { swapCredential } from "./swap.js";
export type { SwapRequest, SwapResult } from "./swap.js";

// Response redaction
export { REDACTION_MARKER, createRedactingTransform, redactBytes } from "./redact.js";
export type { RedactingTransform } from "./redact.js";
