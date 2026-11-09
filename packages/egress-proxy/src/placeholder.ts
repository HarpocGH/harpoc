import type { IncomingHttpHeaders } from "node:http";
import { injectionConfigSchema, isValidHandle, parseHandle } from "@harpoc/shared";

/** A credential placeholder the agent's client sends where the credential would go (B2-U1). */
export interface Placeholder {
  /** The `<project>` of `harpoc://<project>/<name>`; absent for the bare `harpoc:<name>`. */
  project?: string;
  name: string;
  /** The vault handle it names: `secret://<name>` or `secret://<project>/<name>`. */
  handle: string;
  /** The placeholder exactly as the client sent it. */
  raw: string;
}

/**
 * Where a placeholder stood — `InjectionConfig`'s four placements, the
 * basic-auth one carrying the user the client sent beside the placeholder,
 * the bearer one the `token` scheme when the client sent that one (the GitHub
 * CLI's `Authorization: token <p>`), spelled as sent.
 */
export type Placement =
  | { type: "bearer"; scheme?: string }
  | { type: "basic_auth"; user: string }
  | { type: "header"; header_name: string }
  | { type: "query"; query_param: string };

export interface PlaceholderMatch {
  placeholder: Placeholder;
  placement: Placement;
}

/** One request's scan: no placeholder (pass-through), exactly one, or more than one (refused, R-P1). */
export type PlaceholderScan =
  { outcome: "none" } | { outcome: "found"; match: PlaceholderMatch } | { outcome: "multiple" };

const BARE_PREFIX = "harpoc:";
const PROJECT_PREFIX = "harpoc://";

/**
 * Request headers the forwarder never sends as received — the caller's own
 * token, the target's `Host`, the body framing and the hop-by-hop set of
 * RFC 9110 § 7.6.1 — so none of them is a credential position.
 */
const NOT_A_POSITION = new Set([
  "host",
  "proxy-authorization",
  "connection",
  "keep-alive",
  "proxy-connection",
  "te",
  "transfer-encoding",
  "upgrade",
  "content-length",
]);

/**
 * Parse `harpoc:<name>` or `harpoc://<project>/<name>`. The segments are
 * exactly those `isValidHandle` accepts: the placeholder is read as the
 * handle `secret://<rest>`, so there is no second grammar; the bare form
 * names a project-less secret as `secret://<name>` does. Anything else —
 * another case, surrounding text, a missing or extra segment — is `null`.
 */
export function parsePlaceholder(text: string): Placeholder | null {
  const projectForm = text.startsWith(PROJECT_PREFIX);
  if (!projectForm && !text.startsWith(BARE_PREFIX)) return null;
  const handle = `secret://${text.slice(projectForm ? PROJECT_PREFIX.length : BARE_PREFIX.length)}`;
  if (!isValidHandle(handle)) return null;
  const { project, name } = parseHandle(handle);
  if ((project !== undefined) !== projectForm) return null;
  return project === undefined ? { name, handle, raw: text } : { project, name, handle, raw: text };
}

/**
 * Find the placeholder of one request in the four positions the placement is
 * derived from — `Authorization: Bearer <ph>` (or `token <ph>`), `Authorization: Basic
 * base64(<user>:<ph>)`, any other header whose whole value is `<ph>` and a
 * query parameter whose whole value is `<ph>`. A placeholder-shaped token
 * anywhere else is not a placeholder. `headers` is node's `req.headers`
 * (names lowercased, duplicates joined, `__proto__` dropped); never
 * `req.headersDistinct`, which throws on a `__proto__` header in Node 24.
 */
export function findPlaceholder(headers: IncomingHttpHeaders, url: URL): PlaceholderScan {
  const matches: PlaceholderMatch[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (typeof value !== "string" || NOT_A_POSITION.has(name)) continue;
    const match = name === "authorization" ? authorizationMatch(value) : headerMatch(name, value);
    if (match) matches.push(match);
  }
  for (const [name, value] of url.searchParams) {
    const placeholder = parsePlaceholder(value);
    const placement: Placement = { type: "query", query_param: name };
    if (placeholder && injectionConfigSchema.safeParse(placement).success) {
      matches.push({ placeholder, placement });
    }
  }
  if (matches.length === 0) return { outcome: "none" };
  if (matches.length > 1) return { outcome: "multiple" };
  return { outcome: "found", match: matches[0] as PlaceholderMatch };
}

function authorizationMatch(value: string): PlaceholderMatch | null {
  const bearer = /^(bearer|token) +(.+)$/i.exec(value);
  if (bearer) {
    const scheme = bearer[1] as string;
    const placeholder = parsePlaceholder(bearer[2] as string);
    if (!placeholder) return null;
    const placement: Placement =
      scheme.toLowerCase() === "token" ? { type: "bearer", scheme } : { type: "bearer" };
    return { placeholder, placement };
  }
  const basic = /^basic +([A-Za-z0-9+/]+={0,2})$/i.exec(value);
  if (basic) return basicMatch(basic[1] as string);
  return headerMatch("authorization", value);
}

function basicMatch(token: string): PlaceholderMatch | null {
  const decoded = Buffer.from(token, "base64");
  if (decoded.toString("base64") !== token) return null;
  const credentials = decoded.toString("utf8");
  if (!Buffer.from(credentials, "utf8").equals(decoded)) return null;
  const colon = credentials.indexOf(":");
  if (colon === -1) return null;
  const placeholder = parsePlaceholder(credentials.slice(colon + 1));
  if (!placeholder) return null;
  return { placeholder, placement: { type: "basic_auth", user: credentials.slice(0, colon) } };
}

function headerMatch(name: string, value: string): PlaceholderMatch | null {
  const placeholder = parsePlaceholder(value);
  const placement: Placement = { type: "header", header_name: name };
  if (!placeholder || !injectionConfigSchema.safeParse(placement).success) return null;
  return { placeholder, placement };
}
