import type { IncomingHttpHeaders } from "node:http";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { parsePlaceholder } from "./placeholder.js";
import type { Placement } from "./placeholder.js";

export interface SwapRequest {
  /** The client's request headers as node delivers them (`req.headers`). */
  headers: IncomingHttpHeaders;
  /** The upstream target. */
  url: URL;
}

export interface SwapResult {
  /** A null-prototype copy of the request headers with the credential at the placement. */
  headers: Record<string, string | string[]>;
  /** A copy of the target with the credential at a query placement. */
  url: URL;
  /**
   * The value and, where it differs, the form it took on the wire (the
   * basic-auth base64, the serialized query value) — fresh copies for
   * `createRedactingTransform`, which the caller zero-fills.
   */
  needles: Uint8Array[];
}

/**
 * Put the credential where the placeholder stood, with the bytes the HTTP
 * injector's `applyInjectionConfig` sends for the same placement — basic auth
 * as `base64(<user>:<value>)` with the client's own user, a query value
 * serialized as `URLSearchParams` serializes it — and leave every other
 * header and query component as the client sent it. The request is not
 * modified; no refusal names the value.
 */
export function swapCredential(
  request: SwapRequest,
  placement: Placement,
  value: Uint8Array,
): SwapResult {
  const valueStr = Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("utf8");
  const headers = copyHeaders(request.headers);
  const url = new URL(request.url);
  const needles: Uint8Array[] = [Buffer.from(valueStr, "utf8")];
  switch (placement.type) {
    case "bearer":
      assertHeaderSafe(valueStr);
      headers["authorization"] = `Bearer ${valueStr}`;
      break;
    case "basic_auth": {
      const encoded = Buffer.from(`${placement.user}:${valueStr}`, "utf8").toString("base64");
      headers["authorization"] = `Basic ${encoded}`;
      needles.push(Buffer.from(encoded, "latin1"));
      break;
    }
    case "header":
      assertHeaderSafe(valueStr);
      headers[placement.header_name] = valueStr;
      break;
    case "query": {
      const encoded = new URLSearchParams([["", valueStr]]).toString().slice(1);
      url.search = replaceQueryValue(url.search, placement.query_param, encoded);
      if (encoded !== valueStr) needles.push(Buffer.from(encoded, "latin1"));
      break;
    }
  }
  return { headers, url, needles };
}

function copyHeaders(headers: IncomingHttpHeaders): Record<string, string | string[]> {
  const copy = Object.create(null) as Record<string, string | string[]>;
  for (const [name, value] of Object.entries(headers)) {
    if (value !== undefined) copy[name] = value;
  }
  return copy;
}

function assertHeaderSafe(valueStr: string): void {
  if (/[\r\n\0]/.test(valueStr)) {
    throw new VaultError(
      ErrorCode.INVALID_INJECTION_CONFIG,
      "the secret value cannot be placed in a header: it contains CR, LF or NUL",
    );
  }
}

function replaceQueryValue(search: string, param: string, encoded: string): string {
  const components = search.slice(1).split("&");
  const index = components.findIndex((component) => {
    const [entry] = new URLSearchParams("?" + component);
    return entry !== undefined && entry[0] === param && parsePlaceholder(entry[1]) !== null;
  });
  if (index === -1) {
    throw new VaultError(
      ErrorCode.INVALID_INJECTION_CONFIG,
      `query parameter ${param} carries no placeholder`,
    );
  }
  const component = components[index] as string;
  const equals = component.indexOf("=");
  components[index] = `${equals === -1 ? component : component.slice(0, equals)}=${encoded}`;
  return `?${components.join("&")}`;
}
