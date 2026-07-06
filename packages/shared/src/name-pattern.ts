import { MAX_NAME_LENGTH } from "./constants.js";

/**
 * Secret-name scope patterns for token scoping (thesis §4.7).
 *
 * A token's `secrets` claim lists secret-name patterns: literal names, or
 * patterns in which `*` matches any run of characters (`db-*`, `*-prod`,
 * `api-*-key`). Matching is full-anchored and case-sensitive. The wildcard is
 * the only meta-character — every other character is literal, so there is no
 * regex surface: a pattern can never be crafted to behave as anything other
 * than name characters plus `*`.
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
 */
export function matchesSecretNamePattern(name: string, pattern: string): boolean {
  if (!pattern.includes("*")) return name === pattern;
  const escaped = pattern
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .split("*")
    .join(".*");
  return new RegExp(`^${escaped}$`).test(name);
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
