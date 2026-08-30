/**
 * Numeric vault-version comparison.
 *
 * The vault stores its format version as a dotted decimal string ("1.0.0").
 * Support checks must compare components numerically — a lexicographic string
 * compare orders "1.10.0" before "1.2.0", silently accepting a newer vault
 * across a digit boundary and defeating the fail-closed guard.
 */

/**
 * Numeric comparison of two dotted decimal versions: -1 when `a` is older, 0
 * when equal, 1 when newer. Components compare left to right; a missing
 * component counts as 0 ("1.2" is "1.2.0"). A malformed side (empty,
 * non-numeric component) yields null — callers fail closed on it.
 */
export function compareVaultVersions(a: string, b: string): -1 | 0 | 1 | null {
  const aParts = parseVersion(a);
  const bParts = parseVersion(b);
  if (aParts === null || bParts === null) {
    return null;
  }

  const length = Math.max(aParts.length, bParts.length);
  for (let i = 0; i < length; i++) {
    const aPart = aParts[i] ?? 0;
    const bPart = bParts[i] ?? 0;
    if (aPart > bPart) return 1;
    if (aPart < bPart) return -1;
  }
  return 0;
}

/**
 * Whether a vault stamped `stored` may be opened by an engine that supports
 * formats up to `supported`. Fail-closed: a malformed version on either side
 * is treated as unsupported — a garbage version string means corruption, and
 * refusing is safer than guessing.
 */
export function isVaultVersionSupported(stored: string, supported: string): boolean {
  const order = compareVaultVersions(stored, supported);
  return order !== null && order <= 0;
}

/**
 * Whether a vault stamped `stored` is at or above `floor` — the oldest format
 * this binary can open. Fail-closed on a malformed side like the ceiling check.
 */
export function meetsVaultVersionFloor(stored: string, floor: string): boolean {
  const order = compareVaultVersions(stored, floor);
  return order !== null && order >= 0;
}

function parseVersion(version: string): number[] | null {
  if (version.length === 0) {
    return null;
  }
  const parts = version.split(".");
  const numbers: number[] = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return null;
    }
    numbers.push(parseInt(part, 10));
  }
  return numbers;
}
