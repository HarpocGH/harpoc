import { lookup as dnsLookup } from "node:dns";
import type { LookupAddress } from "node:dns";
import { isIP } from "node:net";
import type {
  FollowRedirects,
  HttpMethod,
  HttpResult,
  InjectionConfig,
  ResponseMode,
} from "@harpoc/shared";
import { DEFAULT_HTTP_TIMEOUT_MS, ErrorCode, VaultError } from "@harpoc/shared";
import { Agent, fetch as undiciFetch } from "undici";
import type { Response as UndiciResponse } from "undici";
import type { AuditAttribution } from "../audit/attribution.js";
import { withAttribution } from "../audit/attribution.js";
import type { AuditLogger } from "../audit/audit-logger.js";
import { matchesUrlAllowlist } from "./allowlist.js";
import { validateUrl } from "./url-validator.js";

type PinnedLookup = (
  hostname: string,
  options: { all?: boolean; family?: number | string },
  callback: (
    err: NodeJS.ErrnoException | null,
    address: string | LookupAddress[],
    family?: number,
  ) => void,
) => void;

/**
 * Connection-time DNS lookup that serves only the addresses the pre-flight
 * validation approved. Pinning at the socket layer keeps the URL's hostname
 * intact, so the Host header and TLS SNI/certificate validation are untouched
 * while the connection cannot be re-resolved to an attacker-controlled address
 * between validation and connect (DNS-rebinding TOCTOU).
 */
export function createPinnedLookup(pins: ReadonlyMap<string, readonly string[]>): PinnedLookup {
  return (hostname, options, callback) => {
    const pinned = pins.get(hostname.toLowerCase());
    if (!pinned || pinned.length === 0) {
      // Only loopback targets reach the socket layer unpinned — validateUrl
      // pins every public hostname. Delegate to the system resolver.
      (dnsLookup as unknown as PinnedLookup)(hostname, options, callback);
      return;
    }
    const requestedFamily = typeof options.family === "number" ? options.family : 0;
    const entries = pinned
      .map((address) => ({ address, family: isIP(address) }))
      .filter(
        (entry) =>
          entry.family !== 0 && (requestedFamily === 0 || entry.family === requestedFamily),
      );
    if (entries.length === 0) {
      const err: NodeJS.ErrnoException = new Error(
        `No pinned address of family ${requestedFamily} for ${hostname}`,
      );
      err.code = "ENOTFOUND";
      callback(err, []);
      return;
    }
    if (options.all) {
      callback(null, entries);
    } else {
      const first = entries[0] as { address: string; family: number };
      callback(null, first.address, first.family);
    }
  };
}

export interface HttpInjectorRequest {
  method: HttpMethod;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  responseMode?: ResponseMode;
  responseHeaderAllowlist?: string[];
  /**
   * The secret's URL allowlist (empty = not enforced). The engine validates the
   * initial URL before injection; the injector re-validates every redirect hop
   * against the same patterns, so a redirect can never carry the request to a
   * non-allowlisted target — whichever follow_redirects mode is active.
   */
  urlAllowlist?: string[];
}

/**
 * Executes HTTP requests with injected credentials.
 * The secret value is injected at the execution layer and never returned to the LLM.
 */
export class HttpInjector {
  constructor(private readonly auditLogger: AuditLogger | null) {}

  async executeWithSecret(
    request: HttpInjectorRequest,
    secretValue: Uint8Array,
    injection: InjectionConfig,
    followRedirects: FollowRedirects = "same-origin",
    secretId?: string,
    attribution?: AuditAttribution,
  ): Promise<HttpResult> {
    try {
      // Validate URL (includes DNS rebinding check)
      const validated = await validateUrl(request.url);
      const url = validated.url;

      // Build headers
      const headers: Record<string, string> = { ...request.headers };
      const valueStr = Buffer.from(secretValue).toString("utf8");

      // Inject credential
      let finalUrl = url.toString();
      switch (injection.type) {
        case "bearer":
          headers["Authorization"] = `Bearer ${valueStr}`;
          break;
        case "basic_auth":
          // RFC 7617: value is expected to be "user:password", base64-encoded as-is
          headers["Authorization"] = `Basic ${Buffer.from(valueStr).toString("base64")}`;
          break;
        case "header":
          if (!injection.header_name) {
            throw new VaultError(
              ErrorCode.INVALID_INJECTION_CONFIG,
              "header_name required for header injection",
            );
          }
          headers[injection.header_name] = valueStr;
          break;
        case "query":
          if (!injection.query_param) {
            throw new VaultError(
              ErrorCode.INVALID_INJECTION_CONFIG,
              "query_param required for query injection",
            );
          }
          url.searchParams.set(injection.query_param, valueStr);
          finalUrl = url.toString();
          break;
      }

      // DNS-rebinding TOCTOU protection: every request connects through a
      // dispatcher whose connection-time lookup serves only the addresses the
      // pre-flight validation approved (redirect hops register their own pins
      // after re-validation). Loopback targets carry no pin — they resolve
      // locally and never leave the host.
      const pins = new Map<string, string[]>();
      if (validated.resolvedAddresses) {
        pins.set(url.hostname.toLowerCase(), validated.resolvedAddresses);
      }
      const dispatcher = new Agent({ connect: { lookup: createPinnedLookup(pins) } });

      const timeoutMs = request.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;

      let response: HttpResult;
      try {
        response = await this.fetchWithRedirects(
          finalUrl,
          request.method,
          headers,
          request.body,
          timeoutMs,
          followRedirects,
          injection,
          request.responseMode ?? "filtered",
          request.responseHeaderAllowlist ?? [],
          request.urlAllowlist ?? [],
          pins,
          dispatcher,
        );
      } finally {
        await dispatcher.close();
      }

      this.auditLogger?.log(
        withAttribution(
          {
            eventType: "secret.use",
            secretId,
            detail: {
              method: request.method,
              url: request.url,
              status: response.status,
              injection_type: injection.type,
              response_mode: request.responseMode ?? "filtered",
            },
          },
          attribution,
        ),
      );

      return response;
    } catch (err) {
      if (err instanceof VaultError) {
        this.auditLogger?.log(
          withAttribution(
            {
              eventType: "secret.use",
              secretId,
              detail: {
                method: request.method,
                url: request.url,
                error: err.code,
                injection_type: injection.type,
                response_mode: request.responseMode ?? "filtered",
              },
              success: false,
            },
            attribution,
          ),
        );

        // DNS resolution failures are operational errors — return as response, don't throw
        if (err.code === ErrorCode.DNS_RESOLUTION_FAILED) {
          return { type: "http", status: null, error: err.code };
        }

        throw err;
      }

      const errorCode = this.classifyFetchError(err);

      this.auditLogger?.log(
        withAttribution(
          {
            eventType: "secret.use",
            secretId,
            detail: {
              method: request.method,
              url: request.url,
              error: errorCode,
              injection_type: injection.type,
              response_mode: request.responseMode ?? "filtered",
            },
            success: false,
          },
          attribution,
        ),
      );

      return {
        type: "http",
        status: null,
        error: errorCode,
      };
    }
  }

  private static readonly MAX_REDIRECTS = 5;

  private async fetchWithRedirects(
    url: string,
    method: HttpMethod,
    headers: Record<string, string>,
    body: string | undefined,
    timeoutMs: number,
    followRedirects: FollowRedirects,
    injection: InjectionConfig | undefined,
    responseMode: ResponseMode,
    responseHeaderAllowlist: string[],
    urlAllowlist: string[],
    pins: Map<string, string[]>,
    dispatcher: Agent,
  ): Promise<HttpResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    let currentUrl = url;
    let currentHeaders = { ...headers };
    let remainingRedirects = HttpInjector.MAX_REDIRECTS;
    let redirectWarning: string | undefined;

    try {
      while (true) {
        const response = await undiciFetch(currentUrl, {
          method,
          headers: currentHeaders,
          body: body ?? null,
          signal: controller.signal,
          redirect: "manual",
          dispatcher,
        });

        // Not a redirect — return response
        if (response.status < 300 || response.status >= 400) {
          const result = await this.buildResponse(response, responseMode, responseHeaderAllowlist);
          if (redirectWarning) result.redirect_warning = redirectWarning;
          return result;
        }

        const location = response.headers.get("location");

        if (followRedirects === "none" || !location) {
          return this.buildResponse(response, responseMode, responseHeaderAllowlist);
        }

        // This hop's body is never read — release the connection before following.
        await response.body?.cancel().catch(() => {});

        if (remainingRedirects <= 0) {
          throw new VaultError(ErrorCode.REDIRECT_POLICY_VIOLATION, "Too many redirects");
        }
        remainingRedirects--;

        // Resolve redirect URL
        const redirectUrl = new URL(location, currentUrl);

        // Validate redirect target against SSRF (includes DNS rebinding check)
        try {
          const redirectValidated = await validateUrl(redirectUrl.toString());
          // Re-pin: this hop's hostname connects only to the addresses its own
          // pre-flight validation just approved.
          if (redirectValidated.resolvedAddresses) {
            pins.set(redirectUrl.hostname.toLowerCase(), redirectValidated.resolvedAddresses);
          }
        } catch {
          throw new VaultError(
            ErrorCode.REDIRECT_POLICY_VIOLATION,
            `Redirect target blocked: ${redirectUrl.toString()}`,
          );
        }

        // §4.5.2: every hop is independently re-validated against the secret's
        // URL allowlist (empty = not enforced) — a redirect can never carry the
        // request to a non-allowlisted target, whichever follow_redirects mode
        // is active. Checked before the hop executes.
        if (!matchesUrlAllowlist(redirectUrl.toString(), urlAllowlist)) {
          throw VaultError.urlNotAllowed(redirectUrl.toString());
        }

        const originalUrl = new URL(currentUrl);
        const isCrossOrigin =
          redirectUrl.protocol !== originalUrl.protocol ||
          redirectUrl.hostname !== originalUrl.hostname ||
          redirectUrl.port !== originalUrl.port;

        if (followRedirects === "same-origin" && isCrossOrigin) {
          // Strip all injected credentials on cross-origin redirect
          currentHeaders = { ...currentHeaders };
          delete currentHeaders["Authorization"];

          // Strip injected query param
          if (injection?.type === "query" && injection.query_param) {
            redirectUrl.searchParams.delete(injection.query_param);
          }

          // Strip injected custom header
          if (injection?.type === "header" && injection.header_name) {
            const headerToStrip = injection.header_name.toLowerCase();
            currentHeaders = Object.fromEntries(
              Object.entries(currentHeaders).filter(([k]) => k.toLowerCase() !== headerToStrip),
            );
          }

          redirectWarning = `Cross-origin redirect to ${redirectUrl.origin} — credentials stripped`;
        }

        currentUrl = redirectUrl.toString();
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  private async buildResponse(
    response: UndiciResponse,
    responseMode: ResponseMode,
    responseHeaderAllowlist: string[],
  ): Promise<HttpResult> {
    if (responseMode === "status_only") {
      // Structural I2a (thesis §4.5.2): the body is never read — the echo
      // channel is absent, not filtered. Cancel releases the connection.
      await response.body?.cancel().catch(() => {});

      const allowed = new Set(responseHeaderAllowlist.map((name) => name.toLowerCase()));
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        if (allowed.has(key.toLowerCase())) {
          responseHeaders[key] = value;
        }
      });

      const result: HttpResult = { type: "http", status: response.status };
      if (Object.keys(responseHeaders).length > 0) {
        result.headers = responseHeaders;
      }
      return result;
    }

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    let body: string | undefined;
    try {
      body = await response.text();
    } catch {
      body = undefined;
    }

    return {
      type: "http",
      status: response.status,
      headers: responseHeaders,
      body,
    };
  }

  private classifyFetchError(err: unknown): string {
    if (!(err instanceof Error)) return ErrorCode.INTERNAL_ERROR;

    // Node's fetch wraps the real error in `cause`
    const cause = (err as { cause?: Error }).cause;
    const message = err.message.toLowerCase();
    const causeMessage = cause?.message?.toLowerCase() ?? "";
    const causeCode = ((cause as { code?: string })?.code ?? "").toLowerCase();
    const combined = `${message} ${causeMessage} ${causeCode}`;

    if (err.name === "AbortError" || combined.includes("abort") || combined.includes("timeout")) {
      return ErrorCode.TIMEOUT;
    }
    if (
      combined.includes("enotfound") ||
      combined.includes("getaddrinfo") ||
      combined.includes("dns")
    ) {
      return ErrorCode.DNS_RESOLUTION_FAILED;
    }
    if (combined.includes("econnrefused") || combined.includes("connection refused")) {
      return ErrorCode.CONNECTION_REFUSED;
    }
    if (
      combined.includes("tls") ||
      combined.includes("ssl") ||
      combined.includes("certificate") ||
      combined.includes("cert_")
    ) {
      return ErrorCode.TLS_ERROR;
    }

    return ErrorCode.INTERNAL_ERROR;
  }
}
