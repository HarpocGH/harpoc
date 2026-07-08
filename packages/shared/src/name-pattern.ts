import { MAX_NAME_LENGTH } from "./constants.js";

/**
 * Secret-name scope patterns for token scoping (thesis §4.7).
 *
 * A token's `secrets` claim lists secret-name patterns: literal names, or
 * patterns in which `*` matches any run of characters (`db-*`, `*-prod`,
 * `api-*-key`). Matching is full-anchored and case-sensitive. The wildcard is
 * the only meta-character — every other character is literal. Matching is a
 * linear segment walk, never a compiled regex: a `*`-to-`.*` translation would
 * backtrack exponentially on adversarial patterns (`*a*a*a…`), and patterns
 * originate from token claims, so the matcher must stay attacker-neutral.
 */

/** Valid pattern syntax: the secret-name charset plus the `*` wildcard. */
const PATTERN_REGEX = /^[a-zA-Z0-9_*-]+$/;

/** True if `pattern` is a syntactically valid secret-name pattern. */
export function isValidSecretNamePattern(pattern: string): boolean {
  return pattern.length <= MAX_NAME_LENGTH && PATTERN_REGEX.test(pattern);
}

/**
 * True if `name` matches `pattern`. A pattern without `*` must equal the name
 * exactly; `*` matches any run of characters (including none). All other
 * characters are matched literally.
 *
 * Greedy leftmost placement of the literal segments between wildcards is
 * complete for `*`-only globs, so the walk is linear and cannot backtrack.
 */
export function matchesSecretNamePattern(name: string, pattern: string): boolean {
  if (!pattern.includes("*")) return name === pattern;

  const segments = pattern.split("*");
  const first = segments[0] as string;
  const last = segments[segments.length - 1] as string;

  if (first.length + last.length > name.length) return false;
  if (!name.startsWith(first) || !name.endsWith(last)) return false;

  let pos = first.length;
  const end = name.length - last.length;
  for (let i = 1; i < segments.length - 1; i++) {
    const segment = segments[i] as string;
    if (segment === "") continue;
    const idx = name.indexOf(segment, pos);
    if (idx === -1 || idx + segment.length > end) return false;
    pos = idx + segment.length;
  }
  return true;
}

/**
 * True if the token's secret-name scope admits `name`. An absent or empty
 * pattern list is unrestricted (the token carries no name dimension);
 * otherwise the name must match at least one pattern.
 */
export function matchesSecretNameScope(
  name: string,
  patterns: readonly string[] | undefined,
): boolean {
  if (!patterns || patterns.length === 0) return true;
  return patterns.some((pattern) => matchesSecretNamePattern(name, pattern));
}
