/**
 * SMTP recipient allowlist patterns (thesis-aligned §5.2 v1.3 SMTP guardrail).
 *
 * A pattern is either an exact address (`local@domain`) or a domain-wide
 * wildcard (`*@domain`, where `*` covers the whole local part only — never a
 * partial local part or a wildcard domain). Domain comparison is
 * case-insensitive (DNS names are case-folded); local-part comparison is
 * case-sensitive unless the pattern's local part is the literal `*`.
 */

/** Valid pattern syntax: `local@domain` or `*@domain`, single `@`, no whitespace. */
const RECIPIENT_PATTERN_REGEX = /^(\*|[^@\s*]+)@[A-Za-z0-9.-]+$/;

/** True if `pattern` is a syntactically valid recipient allowlist pattern. */
export function isValidRecipientPattern(pattern: string): boolean {
  return RECIPIENT_PATTERN_REGEX.test(pattern);
}

/** Splits an address on its last `@` into local part and domain. */
function splitAddress(address: string): { local: string; domain: string } {
  const at = address.lastIndexOf("@");
  return { local: address.slice(0, at), domain: address.slice(at + 1) };
}

/**
 * True if `recipient` matches at least one of `patterns`. An empty pattern
 * list matches nothing — callers that treat "no patterns configured" as
 * unrestricted must check `patterns.length === 0` themselves before calling
 * (the SMTP policy coupling rule in design §5.2 distinguishes "absent" from
 * "configured but non-matching").
 */
export function matchesRecipientPattern(recipient: string, patterns: readonly string[]): boolean {
  if (patterns.length === 0) return false;

  const target = splitAddress(recipient);
  return patterns.some((pattern) => {
    const candidate = splitAddress(pattern);
    if (target.domain.toLowerCase() !== candidate.domain.toLowerCase()) return false;
    if (candidate.local === "*") return true;
    return target.local === candidate.local;
  });
}
