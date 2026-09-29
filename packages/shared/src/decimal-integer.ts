/**
 * Whether a value is a plain decimal integer literal.
 *
 * `Number()` also accepts forms an operator never means as a port or a minute
 * count — `0x10`, `1e2`, `5.0`, `+5`, ` 5 ` and the empty string all pass
 * `Number.isInteger` after coercion. The surface form is the contract: anything
 * but digits is a typo or a malformed field, not a value.
 *
 * Shared by every numeric CLI flag (`packages/cli`) and `harpoc-mcp --http
 * --port`, so the two entry points cannot disagree on what a port literal is;
 * by the redis `database` index, on the wire (`refineDatabaseAction`,
 * `schemas.ts`) and again in core's `RedisAdapter`; and by
 * `contentLengthExceeds` (`http-body.ts`), where a declared Content-Length
 * that is not `1*DIGIT` fails closed.
 */
export function isDecimalInteger(value: string): boolean {
  return /^\d+$/.test(value);
}
