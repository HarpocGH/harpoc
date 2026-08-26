/**
 * Whether a command-line value is a plain decimal integer literal.
 *
 * `Number()` also accepts forms an operator never means as a port or a minute
 * count — `0x10`, `1e2`, `5.0`, `+5`, ` 5 ` and the empty string all pass
 * `Number.isInteger` after coercion. A numeric flag is operator input, so the
 * surface form is the contract: anything but digits is a typo, not a value.
 *
 * Shared by every numeric CLI flag (`packages/cli`) and `harpoc-mcp --http
 * --port` so the two entry points cannot disagree on what a port literal is.
 */
export function isDecimalInteger(value: string): boolean {
  return /^\d+$/.test(value);
}
