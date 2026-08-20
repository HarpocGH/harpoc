import type { InjectionPolicy, ResponseMode, WebsocketAction } from "@harpoc/shared";
import {
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_WS_COLLECT_WINDOW_MS,
  ResponseMode as ResponseModeValue,
  VaultError,
} from "@harpoc/shared";
import { Agent, WebSocket } from "undici";
import type { CloseEvent, MessageEvent } from "undici";
import { applyInjectionConfig, createPinnedLookup } from "./http-injector.js";
import { redactErrorMessage, redactSecretEncodings } from "./output-sanitizer.js";
import { isResponseModeAllowed } from "./response-mode.js";
import { WS_SCHEMES, validateUrl } from "./url-validator.js";

/** The wire result of a WebSocket exchange: the frames collected (shaped by
 * `response_mode`) and the close code the connection actually closed with. */
export interface WsResult {
  messages: string[];
  close_code: number | null;
}

/** Metadata-only audit projection of a WebSocket exchange — never a frame's
 * content or the credential. `sent` is 1 when `action.message` was sent, 0
 * otherwise; `received` is the number of frames actually captured into the
 * returned result (0 under `status_only`, by the same "never read the body"
 * doctrine the HTTP injector applies — see `buildWsAuditDetails`). */
export interface WsAuditDetails {
  url: string;
  sent: number;
  received: number;
}

/**
 * Builds the metadata-only audit projection for a WebSocket exchange. Pure —
 * the engine (Task 12) calls it once the result is known.
 */
export function buildWsAuditDetails(action: WebsocketAction, result: WsResult): WsAuditDetails {
  return {
    url: action.url,
    sent: action.message !== undefined ? 1 : 0,
    received: result.messages.length,
  };
}

/**
 * Resolves the effective response mode for this invocation: the per-action
 * override may only tighten the secret policy's floor (thesis §4.5.2, same
 * rule the HTTP context enforces at the engine layer — here it lives in the
 * injector itself because the WebSocket signature takes `policy` directly).
 * Checked BEFORE any network activity, so a loosening override never causes a
 * connection to even be attempted.
 */
function resolveResponseMode(action: WebsocketAction, policy: InjectionPolicy): ResponseMode {
  const floor = policy.response_mode ?? ResponseModeValue.FILTERED;
  if (action.response_mode && !isResponseModeAllowed(floor, action.response_mode)) {
    throw VaultError.responseModeNotAllowed(action.response_mode, floor);
  }
  return action.response_mode ?? floor;
}

/** Decodes a `MessageEvent.data` payload (text, ArrayBuffer or a typed array
 * view — `binaryType` is set to `"arraybuffer"` below, so a Blob is never
 * produced) into a UTF-8 string for the collected-messages array. */
function decodeFrameData(data: unknown): string {
  if (typeof data === "string") return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  if (ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("utf8");
  }
  return "";
}

/**
 * Awaits the handshake outcome: resolves on `open`, rejects on `error` (fired
 * synchronously alongside `close` whenever undici fails the connection — a
 * non-101 response, a network error, or — per WHATWG websockets §10.1 / the
 * verified undici 7.28.0 behavior — a 3xx handshake response, which undici's
 * `fetching()` never follows for a WebSocket upgrade: `redirect: "error"` is
 * hard-coded into the request it builds) or on a connect timeout.
 */
function waitForOpen(ws: WebSocket, timeoutMs: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      settle(() => reject(new Error("WebSocket handshake timed out")));
    }, timeoutMs);

    function onOpen(): void {
      settle(resolve);
    }
    function onError(): void {
      settle(() => reject(new Error("WebSocket connection failed")));
    }
    function settle(action: () => void): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ws.removeEventListener("open", onOpen);
      ws.removeEventListener("error", onError);
      action();
    }

    ws.addEventListener("open", onOpen);
    ws.addEventListener("error", onError);
  });
}

/**
 * Collects frames until `maxMessages` is reached, `windowMs` elapses, or the
 * connection closes — whichever comes first. Every path resolves (never
 * rejects): a stalled server that never reaches `maxMessages` still returns
 * whatever arrived once the window closes.
 */
function collectMessages(
  ws: WebSocket,
  maxMessages: number,
  windowMs: number,
  closedPromise: Promise<void>,
): Promise<string[]> {
  return new Promise<string[]>((resolve) => {
    const collected: string[] = [];
    let settled = false;
    const timer = setTimeout(finish, windowMs);

    function onMessage(ev: MessageEvent): void {
      if (settled) return;
      collected.push(decodeFrameData(ev.data));
      if (collected.length >= maxMessages) finish();
    }
    function finish(): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ws.removeEventListener("message", onMessage);
      resolve(collected);
    }

    ws.addEventListener("message", onMessage);
    void closedPromise.then(finish);
  });
}

/**
 * Awaits `promise`, but gives up after `timeoutMs` and resolves anyway. Used
 * to bound the post-`close()` wait: RFC 6455 expects a server to answer a
 * Close frame with its own before the TCP connection ends, but a
 * non-cooperating or hung downstream server that never does leaves undici's
 * `close` event unfired — without this bound, a single such server would
 * hang the one-shot exchange (and its caller) forever.
 */
function waitWithTimeout(promise: Promise<void>, timeoutMs: number): Promise<void> {
  return new Promise<void>((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve();
    }, timeoutMs);
    void promise.then(() => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve();
    });
  });
}

/** Shapes the raw collected frames per the resolved response mode: `filtered`
 * redacts the credential and its encodings from every frame (mirrors the HTTP
 * injector's body redaction), `full` returns them verbatim, `status_only`
 * returns none — the echo channel is absent, not filtered, matching the HTTP
 * injector's "body never read" contract (I2a). */
function shapeMessages(raw: string[], mode: ResponseMode, valueStr: string): string[] {
  if (mode === ResponseModeValue.STATUS_ONLY) return [];
  if (mode === ResponseModeValue.FULL) return raw;
  if (valueStr.length === 0) return raw;
  return raw.map((message) => redactSecretEncodings(message, valueStr));
}

async function dialAndCollect(
  finalUrl: string,
  headers: Record<string, string>,
  dispatcher: Agent,
  action: WebsocketAction,
  responseMode: ResponseMode,
  valueStr: string,
): Promise<WsResult> {
  const ws = new WebSocket(finalUrl, {
    dispatcher,
    headers,
    ...(action.subprotocols && action.subprotocols.length > 0
      ? { protocols: action.subprotocols }
      : {}),
  });
  ws.binaryType = "arraybuffer";

  let closeCode: number | null = null;
  const closedPromise = new Promise<void>((resolve) => {
    ws.addEventListener(
      "close",
      (ev: CloseEvent) => {
        closeCode = ev.code ?? null;
        resolve();
      },
      { once: true },
    );
  });

  try {
    const timeoutMs = action.timeout_ms ?? DEFAULT_HTTP_TIMEOUT_MS;
    await waitForOpen(ws, timeoutMs);

    if (action.message !== undefined) {
      ws.send(action.message);
    }

    let rawMessages: string[] = [];
    if (responseMode !== ResponseModeValue.STATUS_ONLY) {
      const maxMessages = action.collect?.max_messages ?? 1;
      const windowMs = action.collect?.window_ms ?? DEFAULT_WS_COLLECT_WINDOW_MS;
      rawMessages = await collectMessages(ws, maxMessages, windowMs, closedPromise);
    }

    if (ws.readyState !== WebSocket.CLOSED && ws.readyState !== WebSocket.CLOSING) {
      ws.close(1000);
    }
    // Bounded: a downstream server that never completes the RFC 6455 closing
    // handshake must not hang the exchange forever (see waitWithTimeout).
    await waitWithTimeout(closedPromise, timeoutMs);

    return { messages: shapeMessages(rawMessages, responseMode, valueStr), close_code: closeCode };
  } finally {
    if (ws.readyState !== WebSocket.CLOSED && ws.readyState !== WebSocket.CLOSING) {
      ws.close();
    }
  }
}

/**
 * WebSocket injector (request-mediated, v1.3 design). A one-shot exchange:
 * connect with the credential injected at the upgrade handshake — never in a
 * frame — send at most one message, collect frames bounded by `collect`
 * (`max_messages`, default 1, and `window_ms`, default 30s — whichever bound
 * is hit first), then close(1000).
 *
 * Enforcement order, load-bearing: (1) the tighten-only `response_mode`
 * override, checked before any network activity; (2) SSRF pre-flight via the
 * same `validateUrl` the HTTP injector uses (here parameterized with
 * {@link WS_SCHEMES} — `wss:` anywhere, `ws:` loopback-only, matching the
 * schema); (3) the DNS-rebinding pinned dispatcher, so the hostname cannot
 * re-resolve between validation and connect; (4) the credential is placed via
 * the same `applyInjectionConfig` the HTTP injector hoists — bearer/basic_auth
 * set a header, `header` sets a named header, `query` sets a URL search param
 * — all applied to the handshake request, never sent as a frame. A non-101
 * handshake response (including a 3xx — undici's WebSocket never follows a
 * redirect; see `waitForOpen`'s doc comment) surfaces as
 * `websocketConnectFailed(origin)`, origin-only, with the credential stripped
 * from any residual error text via `redactErrorMessage`.
 */
export async function executeWebsocketAction(
  action: WebsocketAction,
  secretValue: Uint8Array,
  policy: InjectionPolicy,
): Promise<WsResult> {
  const responseMode = resolveResponseMode(action, policy);
  const valueStr = Buffer.from(secretValue).toString("utf8");

  const validated = await validateUrl(action.url, WS_SCHEMES);
  const url = validated.url;
  const origin = url.origin;

  const { url: finalUrl, headers } = applyInjectionConfig(url, {}, action.injection, secretValue);

  // DNS-rebinding TOCTOU protection (mirrors the HTTP injector): the socket
  // connects only to the addresses the pre-flight validation just approved.
  const pins = new Map<string, string[]>();
  if (validated.resolvedAddresses) {
    pins.set(url.hostname.toLowerCase(), validated.resolvedAddresses);
  }
  const dispatcher = new Agent({ connect: { lookup: createPinnedLookup(pins) } });

  try {
    return await dialAndCollect(finalUrl, headers, dispatcher, action, responseMode, valueStr);
  } catch (rawErr) {
    const err = redactErrorMessage(rawErr, valueStr);
    if (err instanceof VaultError) throw err;
    throw VaultError.websocketConnectFailed(origin);
  } finally {
    await dispatcher.close();
  }
}
