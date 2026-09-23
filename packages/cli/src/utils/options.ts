import { isDecimalInteger, VaultError } from "@harpoc/shared";

/**
 * Parse and range-check a numeric command-line option.
 *
 * Shared by every command that takes one (`oauth connect --callback-port` /
 * `--timeout`, `cert import` / `cert issue --renew-before-days`, `cert issue` /
 * `cert renew --http-port`, the three ports of `server start`): an out-of-range
 * value is an operator mistake, refused as `INVALID_INPUT` naming the option
 * and its range so `--json` renders the envelope (CM-6, 2026-09-23). Callers
 * invoke it inside the command's `try` and before opening the vault, so a typo
 * never reaches a passphrase prompt.
 */
export function parseIntOption(value: string, label: string, min: number, max: number): number {
  const parsed = Number(value);
  if (!isDecimalInteger(value) || parsed < min || parsed > max) {
    throw VaultError.invalidInput(`Invalid ${label} "${value}". Must be ${min}-${max}.`);
  }
  return parsed;
}

/**
 * Parse a positive decimal integer option (`1*DIGIT`, at least 1), refusing
 * through the command's error path with the caller's own message so `--json`
 * renders the envelope (P1bF-2, 2026-09-23). The sites that took `parseInt`
 * accepted `5abc`, `1.5` and `1e3` as 5, 1 and 1.
 */
export function parsePositiveInteger(value: string, message: string): number {
  if (!isDecimalInteger(value) || Number(value) < 1) {
    throw VaultError.invalidInput(message);
  }
  return Number(value);
}
