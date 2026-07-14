/**
 * Numeric vault-version comparison.
 *
 * The vault stores its format version as a dotted decimal string ("1.0.0").
 * Support checks must compare components numerically — a lexicographic string
 * compare orders "1.10.0" before "1.2.0", silently accepting a newer vault
 * across a digit boundary and defeating the fail-closed guard.
 */

/**
 * Whether a vault stamped `stored` may be opened by an engine that supports
 * formats up to `supported`. Components are compared numerically, left to
 * right; missing components count as 0 ("1.2" is "1.2.0"). Fail-closed: a
 * malformed version on either side (empty, non-numeric component) is treated
 * as unsupported — a garbage version string means corruption, and refusing is
 * safer than guessing.
 */
export function isVaultVersionSupported(stored: string, supported: string): boolean {
  const storedParts = parseVersion(stored);
  const supportedParts = parseVersion(supported);
  if (storedParts === null || supportedParts === null) {
    return false;
  }

  const length = Math.max(storedParts.length, supportedParts.length);
  for (let i = 0; i < length; i++) {
    const storedPart = storedParts[i] ?? 0;
    const supportedPart = supportedParts[i] ?? 0;
    if (storedPart > supportedPart) {
      return false;
    }
    if (storedPart < supportedPart) {
      return true;
    }
  }
  return true;
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
