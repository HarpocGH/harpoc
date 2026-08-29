/**
 * The `--algorithm` / `--bits` / `--curve` option triple, shared by `cert csr`
 * and `cert issue` — one default (`DEFAULT_KEY_ALGORITHM`, EC P-256), one
 * value table, one pairing rule, so the two commands cannot drift.
 */

const ALGORITHMS = ["rsa", "ec"] as const;
export type KeyAlgorithm = (typeof ALGORITHMS)[number];

export const DEFAULT_KEY_ALGORITHM: KeyAlgorithm = "ec";

const RSA_KEY_SIZES = [2048, 4096] as const;
export type RsaKeySize = (typeof RSA_KEY_SIZES)[number];

const EC_CURVES = ["P-256", "P-384"] as const;
export type EcCurve = (typeof EC_CURVES)[number];

function isAlgorithm(value: string): value is KeyAlgorithm {
  return (ALGORITHMS as readonly string[]).includes(value);
}

function isRsaKeySize(value: number): value is RsaKeySize {
  return (RSA_KEY_SIZES as readonly number[]).includes(value);
}

function isEcCurve(value: string): value is EcCurve {
  return (EC_CURVES as readonly string[]).includes(value);
}

/**
 * Range-checked at parse time; the callers run these before the vault opens
 * (the `secret set` F4 lesson, also applied to `cert import`'s
 * --renew-before-days) so an operator typo spends no key-pair generation and
 * never reaches the engine.
 */
export function parseAlgorithm(value: string): KeyAlgorithm {
  if (!isAlgorithm(value)) {
    throw new Error(`Invalid algorithm "${value}". Must be one of: ${ALGORITHMS.join(", ")}.`);
  }
  return value;
}

export function parseBits(value: string | undefined): RsaKeySize | undefined {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || !isRsaKeySize(parsed)) {
    throw new Error(`Invalid bits "${value}". Must be one of: ${RSA_KEY_SIZES.join(", ")}.`);
  }
  return parsed;
}

export function parseCurve(value: string | undefined): EcCurve | undefined {
  if (value === undefined) return undefined;
  if (!isEcCurve(value)) {
    throw new Error(`Invalid curve "${value}". Must be one of: ${EC_CURVES.join(", ")}.`);
  }
  return value;
}

/**
 * Callers refuse a mismatched flag rather than silently drop it: an operator's
 * explicit strength request (--bits/--curve) must not be ignored just because
 * it doesn't pair with the resolved algorithm — including a defaulted one, so
 * a bare `--bits` on either command is refused rather than quietly producing
 * a P-256 key.
 */
export function assertAlgorithmPairing(
  algorithm: KeyAlgorithm,
  modulusLength: RsaKeySize | undefined,
  namedCurve: EcCurve | undefined,
): void {
  if (algorithm === "ec" && modulusLength !== undefined) {
    throw new Error("--bits only applies with --algorithm rsa.");
  }
  if (algorithm === "rsa" && namedCurve !== undefined) {
    throw new Error("--curve only applies with --algorithm ec.");
  }
}
