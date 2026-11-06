import type { Readable } from "node:stream";
import { createPinnedLookup } from "@harpoc/core";
import type { ProxyUpstreamFailureReason } from "@harpoc/shared";
import { Agent, request } from "undici";
import { redactBytes } from "./redact.js";

/** Header values as the proxy forwards them: lower-case names, duplicates as arrays. */
export type ProxyHeaders = Record<string, string | string[]>;

/**
 * How the client addressed the proxy. The upstream leg is TLS in every form
 * (design M4 (i): "the proxy opens the real TLS connection"); the form decides
 * only how a `Location` is mapped back for the client (`mapLocation`).
 */
export type RequestForm = "path" | "absolute-http" | "absolute-https";

export interface ParsedTarget {
  /** Always `https:`; the default port elided as `URL` spells it. */
  url: URL;
  form: RequestForm;
}

export type TargetParse = { ok: true; target: ParsedTarget } | { ok: false; message: string };

const TARGET_REFUSAL =
  "Not a proxy request target: send http://<proxy>/<host>[:<port>]/<path> or an absolute http:// or https:// URI";

/** `<host>` or `<host>:<port>` — a DNS name or IPv4 literal, or a bracketed IPv6 literal. */
const HOST_SEGMENT = /^(?:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$/;

/**
 * The upstream target of a request line. The path-prefixed form
 * (`/api.github.com/user?x=1`) names the host in its first segment; the
 * absolute form (`http://api.github.com/user`, as `HTTP_PROXY` clients send it,
 * or `https://…`) names it in the authority. The `Host` header is never read.
 * An `http://` target is upgraded: port 80 or none becomes 443, any other port
 * is kept — the credential never travels a plaintext upstream.
 */
export function parseTarget(requestUrl: string): TargetParse {
  const refused: TargetParse = { ok: false, message: TARGET_REFUSAL };
  if (requestUrl.startsWith("/")) {
    const rest = requestUrl.slice(1);
    const end = rest.search(/[/?]/);
    const segment = end === -1 ? rest : rest.slice(0, end);
    const remainder = end === -1 ? "/" : rest.slice(end);
    if (!HOST_SEGMENT.test(segment)) return refused;
    // The remainder starts with "/" or "?", so it cannot reach the authority:
    // never resolved as a reference against the host (a "//x" would become x).
    let url: URL;
    try {
      url = new URL(`https://${segment}${remainder.startsWith("?") ? "/" : ""}${remainder}`);
    } catch {
      return refused;
    }
    url.hash = "";
    return { ok: true, target: { url, form: "path" } };
  }
  if (!/^https?:\/\//i.test(requestUrl)) return refused;
  let given: URL;
  try {
    given = new URL(requestUrl);
  } catch {
    return refused;
  }
  if (given.username !== "" || given.password !== "") return refused;
  const url = new URL(`https://${given.host}${given.pathname}${given.search}`);
  return {
    ok: true,
    target: { url, form: given.protocol === "http:" ? "absolute-http" : "absolute-https" },
  };
}

/**
 * Hop-by-hop request fields (RFC 9110 § 7.6.1 and its list, and RFC 2616 § 13.5.1's
 * `Trailer` — the body is re-framed, so no client trailer follows), the proxy's
 * own credential (`Proxy-Authorization`, consumed here — § 11.7.2), `Host` (undici
 * sets it from the target; a forwarded `Host` would also become the TLS
 * servername) and `Expect` (node answers `100-continue` itself; undici refuses
 * the field).
 */
const REQUEST_STRIPPED = new Set([
  "connection",
  "expect",
  "host",
  "keep-alive",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

/** Hop-by-hop response fields; `Proxy-Authenticate` applies only to the next outbound client (§ 11.7.1). */
const RESPONSE_STRIPPED = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-connection",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function connectionOptions(value: string | string[] | undefined): Set<string> {
  const listed = new Set<string>();
  for (const entry of [value ?? []].flat()) {
    for (const option of entry.split(",")) {
      const name = option.trim().toLowerCase();
      if (name !== "") listed.add(name);
    }
  }
  return listed;
}

/** The client's request fields as they go upstream: every hop-by-hop field and every `Connection` option removed. */
export function upstreamRequestHeaders(
  incoming: Record<string, string | string[] | undefined>,
): ProxyHeaders {
  const listed = connectionOptions(incoming.connection);
  const out: ProxyHeaders = {};
  for (const [name, value] of Object.entries(incoming)) {
    if (value === undefined || REQUEST_STRIPPED.has(name) || listed.has(name)) continue;
    out[name] = value;
  }
  return out;
}

/**
 * Every occurrence of a needle's bytes in `text` replaced by the project's
 * marker (lane P's `redactBytes`) — header values in `latin1` (node's header
 * decoding), messages in `utf8`.
 */
export function redactText(
  text: string,
  needles: readonly Uint8Array[],
  encoding: "latin1" | "utf8",
): { text: string; changed: boolean } {
  const { output, changed } = redactBytes(Buffer.from(text, encoding), needles);
  return changed ? { text: output.toString(encoding), changed } : { text, changed };
}

/**
 * A `Location` on a path-prefixed (base-URL) request, rewritten into the
 * proxy's own form `/<host>[:<port>]/<path>?<query>` (RT-1): resolved against
 * the target first, so a relative one keeps its host, and an `http:` one too —
 * otherwise the client would follow it straight to that origin carrying its
 * `Proxy-Authorization` token. The follow-up comes back through the proxy and
 * is judged on its own origin; the proxy never follows a redirect itself. On an
 * absolute-form request, another scheme or an unparsable value: as received.
 */
export function mapLocation(value: string, target: ParsedTarget): string {
  if (target.form !== "path") return value;
  let resolved: URL;
  try {
    resolved = new URL(value, target.url);
  } catch {
    return value;
  }
  if (resolved.protocol !== "https:" && resolved.protocol !== "http:") return value;
  return `/${resolved.host}${resolved.pathname}${resolved.search}`;
}

/**
 * The upstream response fields as the client gets them: hop-by-hop fields
 * removed, every value redacted by exact needle match when `needles` is set
 * (a brokered request — DB-8), `Content-Length` dropped then (the redaction may
 * change the body's length, so node frames the body itself), and `Location`
 * mapped back into the client's form — redacted before the mapping (whose URL
 * parser may re-encode a value) and again after it (whatever the resolution
 * against `target` composed).
 */
export function relayResponseHeaders(
  headers: Record<string, string | string[] | undefined>,
  target: ParsedTarget,
  needles: readonly Uint8Array[] | null,
): { headers: ProxyHeaders; changed: boolean } {
  const listed = connectionOptions(headers.connection);
  const out: ProxyHeaders = {};
  let changed = false;
  const redact = (entry: string): string => {
    if (needles === null) return entry;
    const redacted = redactText(entry, needles, "latin1");
    if (redacted.changed) changed = true;
    return redacted.text;
  };
  for (const [rawName, value] of Object.entries(headers)) {
    const name = rawName.toLowerCase();
    if (value === undefined || RESPONSE_STRIPPED.has(name) || listed.has(name)) continue;
    if (needles !== null && name === "content-length") continue;
    const relayed = (Array.isArray(value) ? value : [value]).map((entry) =>
      name === "location" ? redact(mapLocation(redact(entry), target)) : redact(entry),
    );
    out[name] = Array.isArray(value) ? relayed : (relayed[0] as string);
  }
  return { headers: out, changed };
}

export interface UpstreamRequest {
  url: URL;
  method: string;
  headers: ProxyHeaders;
  /** The client's body, streamed unbuffered; null when the request carries none. */
  body: Readable | null;
  /** The addresses `validateUrl` approved — the connection is pinned to them. */
  resolvedAddresses?: string[];
  /** The handle's `http.ca_pem`: the only CA the connector trusts when set. */
  caPem?: string;
  /** Connect and response-head budget. */
  timeoutMs: number;
  /** Idle budget between response body chunks. */
  bodyIdleTimeoutMs: number;
  /** Where the per-call dispatcher is registered while it lives (the proxy's `close()` destroys them). */
  dispatchers: Set<Agent>;
}

export interface UpstreamResponse {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: Readable;
  /** Destroys the per-call dispatcher — called once the response is relayed or abandoned. */
  release(): Promise<void>;
}

/**
 * One request upstream over a per-call dispatcher pinned to the validated
 * addresses (`createPinnedLookup`), its connect timer bound to the budget and
 * destroyed — not closed — at the end (use-secret-injection-http.md Rules).
 * undici's `request()`, not `fetch`: no `Accept-Encoding` of its own, no
 * decompression, no redirect handling, raw status and duplicate fields.
 */
export async function forwardUpstream(req: UpstreamRequest): Promise<UpstreamResponse> {
  const pins = new Map<string, string[]>();
  if (req.resolvedAddresses) pins.set(req.url.hostname.toLowerCase(), req.resolvedAddresses);
  const dispatcher = new Agent({
    connect: {
      lookup: createPinnedLookup(pins),
      timeout: req.timeoutMs,
      ...(req.caPem === undefined ? {} : { ca: req.caPem }),
    },
    headersTimeout: req.timeoutMs,
    bodyTimeout: req.bodyIdleTimeoutMs,
  });
  req.dispatchers.add(dispatcher);
  let released = false;
  const release = async (): Promise<void> => {
    if (released) return;
    released = true;
    req.dispatchers.delete(dispatcher);
    await dispatcher.destroy();
  };
  try {
    const response = await request(req.url, {
      dispatcher,
      method: req.method,
      headers: req.headers,
      body: req.body,
    });
    return {
      statusCode: response.statusCode,
      headers: response.headers,
      body: response.body,
      release,
    };
  } catch (err) {
    await release();
    throw err;
  }
}

/**
 * The class a failed upstream request is named by in its 502 (RQ-14), keyed on
 * the error's `code` alone — a fixed vocabulary, never the error's text.
 */
export function failureClass(err: unknown): ProxyUpstreamFailureReason | undefined {
  switch ((err as { code?: string } | null | undefined)?.code) {
    case "ECONNREFUSED":
    case "ECONNRESET":
    case "ENOTFOUND":
    case "EHOSTUNREACH":
    case "ENETUNREACH":
      return "refused";
    case "UND_ERR_CONNECT_TIMEOUT":
    case "UND_ERR_HEADERS_TIMEOUT":
    case "UND_ERR_BODY_TIMEOUT":
    case "ETIMEDOUT":
      return "timeout";
    case "DEPTH_ZERO_SELF_SIGNED_CERT":
    case "SELF_SIGNED_CERT_IN_CHAIN":
    case "UNABLE_TO_VERIFY_LEAF_SIGNATURE":
    case "UNABLE_TO_GET_ISSUER_CERT_LOCALLY":
    case "CERT_HAS_EXPIRED":
    case "ERR_TLS_CERT_ALTNAME_INVALID":
    case "EPROTO":
      return "tls";
    default:
      return undefined;
  }
}
