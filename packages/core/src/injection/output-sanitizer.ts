const REDACTION = "[REDACTED]";

/**
 * Redact a secret value and its common encodings from captured process output.
 *
 * This is the best-effort output-sanitization layer for process-mediated
 * injection (thesis §4.5.2). It removes the raw value and its base64 / base64url
 * / hex / percent-encoded forms — raising naive exfiltration (echo the env var)
 * from prompt-injection-only (L1) to at least L3, where the attacker must shape
 * an encoding transform the filter does not cover. It does NOT defeat arbitrary
 * transforms or character-by-character chunking; those residual bypasses are
 * characterized in the evaluation, not claimed to be blocked.
 */
/**
 * Recursively apply `fn` to every string leaf of a JSON-shaped value, returning
 * a new structure. Used to sanitize structured MCP tool results (content blocks
 * and structuredContent) without corrupting their shape.
 */
export function mapStringLeaves(value: unknown, fn: (s: string) => string): unknown {
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) return value.map((item) => mapStringLeaves(item, fn));
  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      result[key] = mapStringLeaves(val, fn);
    }
    return result;
  }
  return value;
}

export function redactSecretEncodings(text: string, secret: string): string {
  if (text.length === 0 || secret.length === 0) return text;

  const secretBytes = Buffer.from(secret, "utf8");
  const needles = new Set<string>([
    secret,
    secretBytes.toString("base64"),
    secretBytes.toString("base64url"),
    secretBytes.toString("hex"),
    encodeURIComponent(secret),
  ]);

  let result = text;
  for (const needle of needles) {
    if (needle.length === 0) continue;
    if (result.includes(needle)) {
      result = result.split(needle).join(REDACTION);
    }
    // hex is case-insensitive on the wire; also strip an uppercase rendering
    const upper = needle.toUpperCase();
    if (upper !== needle && /^[0-9a-fA-F]+$/.test(needle) && result.includes(upper)) {
      result = result.split(upper).join(REDACTION);
    }
  }
  return result;
}
