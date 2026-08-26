import { isDecimalInteger } from "@harpoc/shared";

/**
 * Parse and range-check a numeric command-line option.
 *
 * Shared by every command that takes one (`oauth connect --callback-port` /
 * `--timeout`, `cert import --renew-before-days`): an out-of-range value is an
 * operator mistake, so it ends the process with a message naming the option and
 * its range rather than travelling into the vault as a nonsense argument.
 * Callers invoke it before opening the vault, so a typo never reaches a
 * passphrase prompt.
 */
export function parseIntOption(value: string, label: string, min: number, max: number): number {
  const parsed = Number(value);
  if (!isDecimalInteger(value) || parsed < min || parsed > max) {
    console.error(`Error: Invalid ${label} "${value}". Must be ${min}-${max}.`);
    process.exit(1);
  }
  return parsed;
}
