import type {
  FollowRedirects,
  HttpMethod,
  InjectionConfig,
  UseSecretResponse,
} from "@harpoc/shared";
import {
  DEFAULT_HTTP_TIMEOUT_MS,
  ErrorCode,
  VaultError,
} from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { validateUrl } from "./url-validator.js";

export interface HttpInjectorRequest {
  method: HttpMethod;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
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
  ): Promise<UseSecretResponse> {
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
            throw new VaultError(ErrorCode.INVALID_INJECTION_CONFIG, "header_name required for header injection");
          }
          headers[injection.header_name] = valueStr;
          break;
        case "query":
          if (!injection.query_param) {
            throw new VaultError(ErrorCode.INVALID_INJECTION_CONFIG, "query_param required for query injection");
          }
          url.searchParams.set(injection.query_param, valueStr);
          finalUrl = url.toString();
          break;
      }

      // Pin to resolved IP for HTTP to prevent DNS rebinding TOCTOU.
      // For HTTPS, TLS certificate validation provides rebinding protection.
      if (validated.resolvedAddress && url.protocol === "http:") {
        const pinnedUrl = new URL(finalUrl);
        headers["Host"] = pinnedUrl.hostname;
        pinnedUrl.hostname = validated.resolvedAddress;
        finalUrl = pinnedUrl.toString();
      }

      const timeoutMs = request.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;

      const response = await this.fetchWithRedirects(
        finalUrl,
        request.method,
        headers,
        request.body,
        timeoutMs,
        followRedirects,
        injection,
      );

      this.auditLogger?.log({
        eventType: "secret.use",
        secretId,
        detail: {
          method: request.method,
          url: request.url,
          status: response.status,
          injection_type: injection.type,
        },
      });

      return response;
    } catch (err) {
      if (err instanceof VaultError) {
        this.auditLogger?.log({
          eventType: "secret.use",
          secretId,
          detail: {
            method: request.method,
            url: request.url,
            error: err.code,
            injection_type: injection.type,
          },
          success: false,
        });

        // DNS resolution failures are operational errors — return as response, don't throw
        if (err.code === ErrorCode.DNS_RESOLUTION_FAILED) {
          return { status: null, error: err.code };
        }

        throw err;
      }

      const errorCode = this.classifyFetchError(err);

      this.auditLogger?.log({
        eventType: "secret.use",
        secretId,
        detail: {
          method: request.method,
          url: request.url,
          error: errorCode,
          injection_type: injection.type,
        },
        success: false,
      });

      return {
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
    injection?: InjectionConfig,
  ): Promise<UseSecretResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    let currentUrl = url;
    let currentHeaders = { ...headers };
    let remainingRedirects = HttpInjector.MAX_REDIRECTS;
    let redirectWarning: string | undefined;

    try {
      while (true) {
        const response = await fetch(currentUrl, {
          method,
          headers: currentHeaders,
          body: body ?? null,
          signal: controller.signal,
          redirect: "manual",
        });

        // Not a redirect — return response
        if (response.status < 300 || response.status >= 400) {
          const result = await this.buildResponse(response);
          if (redirectWarning) result.redirect_warning = redirectWarning;
          return result;
        }

        const location = response.headers.get("location");

        if (followRedirects === "none" || !location) {
          return this.buildResponse(response);
        }

        if (remainingRedirects <= 0) {
          throw new VaultError(
            ErrorCode.REDIRECT_POLICY_VIOLATION,
            "Too many redirects",
          );
        }
        remainingRedirects--;

        // Resolve redirect URL
        const redirectUrl = new URL(location, currentUrl);

        // Validate redirect target against SSRF (includes DNS rebinding check)
        try {
          const redirectValidated = await validateUrl(redirectUrl.toString());
          // Pin redirect target to resolved IP for HTTP
          if (redirectValidated.resolvedAddress && redirectUrl.protocol === "http:") {
            currentHeaders["Host"] = redirectUrl.hostname;
            redirectUrl.hostname = redirectValidated.resolvedAddress;
          }
        } catch {
          throw new VaultError(
            ErrorCode.REDIRECT_POLICY_VIOLATION,
            `Redirect target blocked: ${redirectUrl.toString()}`,
          );
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
              Object.entries(currentHeaders).filter(
                ([k]) => k.toLowerCase() !== headerToStrip,
              ),
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

  private async buildResponse(response: Response): Promise<UseSecretResponse> {
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
    if (combined.includes("enotfound") || combined.includes("getaddrinfo") || combined.includes("dns")) {
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
