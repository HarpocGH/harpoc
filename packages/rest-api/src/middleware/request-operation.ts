import type { Context } from "hono";

const CONTROL_CHARACTER = /[\p{Cc}\u2028\u2029]/gu;

/** A segment holding `eyJ` with two dots anywhere after its first `eyJ` (linear: three `indexOf`). */
function isTokenShaped(segment: string): boolean {
  const start = segment.indexOf("eyJ");
  const firstDot = start < 0 ? -1 : segment.indexOf(".", start);
  return firstDot >= 0 && segment.indexOf(".", firstDot + 1) >= 0;
}

/**
 * The request's path as Hono decodes it (no query), a segment holding a
 * token-shaped text written as `<token>` and every control character as its
 * percent-escape (C-10).
 */
export function requestPath(c: Context): string {
  return c.req.path
    .split("/")
    .map((segment) =>
      isTokenShaped(segment)
        ? "<token>"
        : segment.replace(CONTROL_CHARACTER, (character) => encodeURIComponent(character)),
    )
    .join("/");
}

/** The request's `<METHOD> <path>`, the path as `requestPath` writes it. */
export function requestOperation(c: Context): string {
  return `${c.req.method} ${requestPath(c)}`;
}
