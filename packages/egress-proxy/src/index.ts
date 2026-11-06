// Proxy
export { createEgressProxy } from "./proxy.js";
export type { EgressProxy, EgressProxyOptions, ProxyEngine } from "./proxy.js";

// Placeholders
export { findPlaceholder, parsePlaceholder } from "./placeholder.js";
export type { Placeholder, PlaceholderMatch, PlaceholderScan, Placement } from "./placeholder.js";

// Credential swap
export { swapCredential } from "./swap.js";
export type { SwapRequest, SwapResult } from "./swap.js";

// Response redaction
export { REDACTION_MARKER, createRedactingTransform, redactBytes } from "./redact.js";
export type { RedactingTransform } from "./redact.js";
