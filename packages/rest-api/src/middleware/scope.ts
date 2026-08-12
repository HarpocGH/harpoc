import { parseHandle } from "@harpoc/shared";

/**
 * The 3-dimensional token scope predicate lives in shared (`checkTokenScope`)
 * so the CLI token path enforces identical semantics; re-exported here to keep
 * this middleware the import point for every route.
 */
export { checkTokenScope } from "@harpoc/shared";

/**
 * Build a full secret handle URI from a route parameter.
 */
export function buildHandle(handle: string): string {
  return `secret://${handle}`;
}

/**
 * Extract project and name from a handle route parameter for scope checking.
 */
export function parseHandleParam(handle: string): { project?: string; name: string } {
  const parsed = parseHandle(`secret://${handle}`);
  return { project: parsed.project, name: parsed.name };
}
