import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import {
  CLIENT_CAPABILITIES_META_KEY,
  inputRequired,
  inputResponse,
} from "@modelcontextprotocol/server";
import type { InputRequiredResult, McpServer, ServerContext } from "@modelcontextprotocol/server";
import { VaultError } from "@harpoc/shared";
import { valueRequestState } from "./request-state.js";
import type { ValueRequestState } from "./request-state.js";

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const MAX_FORM_BODY_BYTES = 128 * 1024;
const TOKEN_BYTES = 32;
/**
 * Live collectors allowed at once across the process. Each pins a loopback
 * listener and a five-minute timer, and nothing else bounds how many
 * create_secret/rotate_secret calls a client may have in flight — so without a
 * ceiling an agent could hold arbitrarily many open. Reaching it degrades
 * gracefully: the caller falls back to the terminal prompt or deferred entry.
 */
const MAX_CONCURRENT_COLLECTORS = 8;

/**
 * Live collectors one principal may hold at once, keyed by the guard's
 * principal binding (the token's jti, or the tokenless stdio caller): one
 * create and one rotate in flight. A modern round 1 returns with its collector
 * alive for up to five minutes, so without this a single token could hold the
 * whole process ceiling from any of its per-request servers.
 */
const MAX_COLLECTORS_PER_PRINCIPAL = 2;

const liveCollectors = new Map<string, ValueCollector>();

const liveCollectorsByPrincipal = new Map<string, number>();

export interface ValueCollectorOptions {
  /** Secret name shown on the form (display only, HTML-escaped). */
  subject: string;
  operation: "create" | "rotate";
  timeoutMs?: number;
  /** The caller's principal binding (ScopeGuard.principalBinding); bounds the caller, not just the process. */
  principal?: string;
}

export interface ValueCollector {
  readonly id: string;
  /** One-time URL for the user's browser. */
  readonly url: string;
  /** Resolves with the submitted value; rejects on timeout or close(). */
  waitForValue(): Promise<Uint8Array>;
  close(): Promise<void>;
}

/**
 * Ephemeral loopback HTTP server implementing the thesis's URL-mode
 * elicitation channel: it serves a one-time web form whose POST goes directly
 * from the user's browser into the vault process — the value never traverses
 * the MCP channel. One collector per invocation; the URL embeds a 256-bit
 * single-use token (timing-safe compared) and expires after `timeoutMs`.
 */
export async function startValueCollector(options: ValueCollectorOptions): Promise<ValueCollector> {
  if (liveCollectors.size >= MAX_CONCURRENT_COLLECTORS) {
    throw new Error("Too many concurrent value collectors");
  }
  const principal = options.principal;
  if (
    principal !== undefined &&
    (liveCollectorsByPrincipal.get(principal) ?? 0) >= MAX_COLLECTORS_PER_PRINCIPAL
  ) {
    throw new Error("Too many concurrent value collectors for this caller");
  }
  if (principal !== undefined) {
    liveCollectorsByPrincipal.set(principal, (liveCollectorsByPrincipal.get(principal) ?? 0) + 1);
  }
  function releasePrincipal(): void {
    if (principal === undefined) return;
    const left = (liveCollectorsByPrincipal.get(principal) ?? 1) - 1;
    if (left <= 0) liveCollectorsByPrincipal.delete(principal);
    else liveCollectorsByPrincipal.set(principal, left);
  }
  try {
    const id = randomUUID();
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const token = randomBytes(TOKEN_BYTES).toString("base64url");
    const tokenBuffer = Buffer.from(token, "utf8");
    const path = `/collect/${token}`;

    let used = false;
    let settled = false;
    let resolveValue: (value: Uint8Array) => void = () => undefined;
    let rejectValue: (err: Error) => void = () => undefined;
    const valuePromise = new Promise<Uint8Array>((resolve, reject) => {
      resolveValue = resolve;
      rejectValue = reject;
    });
    // A collector closed without a waiter must not surface an unhandled rejection.
    void valuePromise.catch(() => undefined);

    function settle(fn: () => void): void {
      if (!settled) {
        settled = true;
        fn();
      }
    }

    function matchesToken(requestPath: string): boolean {
      const prefix = "/collect/";
      if (!requestPath.startsWith(prefix)) return false;
      const candidate = Buffer.from(requestPath.slice(prefix.length), "utf8");
      return candidate.length === tokenBuffer.length && timingSafeEqual(candidate, tokenBuffer);
    }

    /**
     * node:http calls this synchronously: a throw escaping it is an unhandled
     * exception that takes the whole vault process down. Nothing below is
     * expected to throw — the token length guard in matchesToken is what keeps
     * timingSafeEqual from raising ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH on a
     * short token — but that is one guard away from a remote crash, so the
     * boundary is explicit.
     */
    function handleRequest(req: IncomingMessage, res: ServerResponse): void {
      try {
        route(req, res);
      } catch {
        try {
          sendHtml(res, 500, "Internal Server Error", "<h1>Request failed</h1>");
        } catch {
          res.destroy();
        }
      }
    }

    function route(req: IncomingMessage, res: ServerResponse): void {
      const requestPath = (req.url ?? "/").split("?")[0] ?? "/";

      if (!matchesToken(requestPath)) {
        sendHtml(res, 404, "Not Found", "<h1>Not found</h1>");
        return;
      }

      if (used) {
        sendHtml(res, 410, "Gone", "<h1>This form was already used</h1><p>Close this window.</p>");
        return;
      }

      if (req.method === "GET") {
        sendHtml(res, 200, "OK", formPage(options, requestPath));
        return;
      }

      if (req.method !== "POST") {
        res.setHeader("Allow", "GET, POST");
        sendHtml(res, 405, "Method Not Allowed", "<h1>Method not allowed</h1>");
        return;
      }

      readBody(req)
        .then((body) => {
          const value = new URLSearchParams(body).get("value");
          if (value === null || value.length === 0) {
            sendHtml(res, 400, "Bad Request", "<h1>Empty value</h1><p>Go back and try again.</p>");
            return;
          }
          used = true;
          sendHtml(
            res,
            200,
            "OK",
            "<h1>Value saved to vault</h1><p>You can close this window and return to your agent.</p>",
          );
          settle(() => resolveValue(new Uint8Array(Buffer.from(value, "utf8"))));
        })
        .catch(() => {
          sendHtml(res, 413, "Payload Too Large", "<h1>Value too large</h1>");
        });
    }

    const server = createServer(handleRequest);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
    let released = false;

    const port = (server.address() as AddressInfo).port;
    const url = `http://127.0.0.1:${port}${path}`;

    const timeoutId = setTimeout(() => {
      settle(() => rejectValue(new Error("Value collection timed out")));
      void close();
    }, timeoutMs);
    if (timeoutId.unref) timeoutId.unref();

    async function close(): Promise<void> {
      clearTimeout(timeoutId);
      settle(() => rejectValue(new Error("Value collector closed")));
      if (!released) {
        released = true;
        liveCollectors.delete(id);
        releasePrincipal();
      }
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeIdleConnections();
      });
    }

    const collector: ValueCollector = {
      id,
      url,
      waitForValue: () => valuePromise,
      close,
    };
    liveCollectors.set(id, collector);
    return collector;
  } catch (err) {
    releasePrincipal();
    throw err;
  }
}

/**
 * Collect a secret value through the MCP URL-mode elicitation channel
 * (thesis priority 1). Returns the value, or null when the channel is
 * unavailable (client lacks `elicitation.url`), declined, cancelled or timed
 * out — the caller then falls back to deferred/pending creation.
 */
export async function collectValueViaUrlElicitation(
  mcp: McpServer,
  options: ValueCollectorOptions,
): Promise<Uint8Array | null> {
  const elicitation = mcp.server.getClientCapabilities()?.elicitation as
    | { url?: unknown }
    | undefined;
  if (!elicitation?.url) return null;

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  let collector: ValueCollector;
  try {
    collector = await startValueCollector({ ...options, timeoutMs });
  } catch {
    return null;
  }

  const elicitationId = randomUUID();
  try {
    const valuePromise = collector.waitForValue();

    const verb = options.operation === "create" ? "the value" : "the new value";
    const elicitPromise = mcp.server.elicitInput(
      {
        mode: "url",
        message: `Enter ${verb} for secret "${options.subject}" in the one-time local form. The value is posted directly to the vault and never enters the model context.`,
        url: collector.url,
        elicitationId,
      },
      { timeout: timeoutMs },
    );

    // The browser POST and the elicitation response race: some clients answer
    // "accept" as soon as the URL is opened, others only after the user is
    // done. Whichever terminal signal arrives first decides.
    const outcome = await Promise.race([
      valuePromise.then((value) => ({ kind: "value" as const, value })),
      elicitPromise.then(
        (result) => ({ kind: "elicit" as const, action: result.action }),
        () => ({ kind: "elicit" as const, action: "cancel" as const }),
      ),
    ]);

    let value: Uint8Array;
    if (outcome.kind === "value") {
      value = outcome.value;
    } else if (outcome.action === "accept") {
      value = await valuePromise;
    } else {
      return null;
    }

    try {
      await mcp.server.createElicitationCompletionNotifier(elicitationId)();
    } catch {
      // The completion notification is advisory; the value is already in hand.
    }
    return value;
  } catch {
    return null;
  } finally {
    await collector.close();
  }
}

/** A modern (2026-07-28) request: the per-request envelope is present. */
export function isModernRequest(ctx: { mcpReq: { envelope?: unknown } }): boolean {
  return ctx.mcpReq.envelope !== undefined;
}

/**
 * The modern leg's first round: start the one-time form and hand the client a
 * URL-mode request plus a sealed state naming the collector. The value still
 * never traverses MCP — the browser posts it into this process.
 */
export async function elicitValueViaInputRequired(
  options: ValueCollectorOptions & { principal: string; target: string },
  ctx: ServerContext,
): Promise<InputRequiredResult | null> {
  if (!hasUrlElicitationCapability(ctx)) return null;

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  let collector: ValueCollector;
  try {
    collector = await startValueCollector({ ...options, timeoutMs });
  } catch {
    return null;
  }

  const verb = options.operation === "create" ? "the value" : "the new value";
  let requestState: string;
  try {
    requestState = await valueRequestState.mint(
      {
        collector: collector.id,
        principal: options.principal,
        operation: options.operation,
        target: options.target,
      },
      ctx,
    );
  } catch (err) {
    await collector.close();
    throw err;
  }
  return inputRequired({
    inputRequests: {
      value: inputRequired.elicitUrl({
        message: `Enter ${verb} for secret "${options.subject}" in the one-time local form. The value is posted directly to the vault and never enters the model context.`,
        url: collector.url,
      }),
    },
    requestState,
  });
}

/**
 * The retry: the state named a live collector of this caller's, the client
 * accepted, the form was (or is about to be) posted. Null on a decline.
 */
export async function resumeValueCollection(
  state: ValueRequestState,
  round: Omit<ValueRequestState, "collector">,
  inputResponses: Record<string, unknown> | undefined,
): Promise<Uint8Array | null> {
  const collector = liveCollectors.get(state.collector);
  if (
    !collector ||
    state.principal !== round.principal ||
    state.operation !== round.operation ||
    state.target !== round.target
  ) {
    if (collector) await collector.close();
    throw VaultError.schemaValidation(
      "requestState names no live value collection for this caller",
    );
  }
  try {
    const response = inputResponse(inputResponses, "value");
    if (response.kind !== "elicit" || response.action !== "accept") return null;
    return await collector.waitForValue();
  } catch {
    return null;
  } finally {
    await collector.close();
  }
}

/** One modern value round, as the tool describes it. */
export interface ModernValueRound {
  subject: string;
  operation: "create" | "rotate";
  principal: string;
  target: string;
  /** Runs before round 1 opens the form, never on the retry; a throw refuses the call. */
  preflight?: () => Promise<void>;
}

export type ModernValueRoundResult<T> =
  | { kind: "pending"; result: InputRequiredResult }
  | { kind: "done"; result: T }
  | { kind: "fallthrough" };

/**
 * The modern leg's whole value round for a tool: round 1 runs the preflight,
 * opens the one-time form and answers inputRequired; the retry resumes the
 * collection the sealed state names, hands the value (null on a decline) to
 * `finish` and zeroes it afterwards. "fallthrough" means no round ran — the
 * client lacks the URL channel or a ceiling was reached — and the tool takes
 * the terminal-or-deferred ladder.
 */
export async function runModernValueRound<T>(
  ctx: ServerContext,
  round: ModernValueRound,
  finish: (value: Uint8Array | null) => Promise<T>,
): Promise<ModernValueRoundResult<T>> {
  const state = ctx.mcpReq.requestState<ValueRequestState>();
  if (state === undefined) {
    await round.preflight?.();
    const pending = await elicitValueViaInputRequired(
      {
        subject: round.subject,
        operation: round.operation,
        principal: round.principal,
        target: round.target,
      },
      ctx,
    );
    return pending === null ? { kind: "fallthrough" } : { kind: "pending", result: pending };
  }
  const value = await resumeValueCollection(
    state,
    { principal: round.principal, operation: round.operation, target: round.target },
    ctx.mcpReq.inputResponses,
  );
  try {
    return { kind: "done", result: await finish(value) };
  } finally {
    value?.fill(0);
  }
}

function hasUrlElicitationCapability(ctx: ServerContext): boolean {
  const envelope = ctx.mcpReq.envelope as Record<string, unknown> | undefined;
  const capabilities = envelope?.[CLIENT_CAPABILITIES_META_KEY] as
    | { elicitation?: { url?: unknown } }
    | undefined;
  return capabilities?.elicitation?.url !== undefined;
}

function sendHtml(res: ServerResponse, status: number, statusText: string, body: string): void {
  res.writeHead(status, statusText, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    Connection: "close",
  });
  res.end(
    `<!doctype html><html><head><meta charset="utf-8"><title>Harpoc</title>${STYLE}</head><body>${body}</body></html>`,
  );
}

const STYLE =
  "<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem}" +
  "input{width:100%;padding:.5rem;font-size:1rem;margin:.75rem 0}" +
  "button{padding:.5rem 1.25rem;font-size:1rem}code{background:#eee;padding:0 .25rem}</style>";

function formPage(options: ValueCollectorOptions, actionPath: string): string {
  const subject = escapeHtml(options.subject);
  const heading =
    options.operation === "create" ? "Provide secret value" : "Provide new secret value";
  return (
    `<h1>${heading}</h1>` +
    `<p>Secret: <code>${subject}</code></p>` +
    "<p>This one-time form posts directly to your local Harpoc vault. The value never passes through the AI model.</p>" +
    `<form method="post" action="${actionPath}" autocomplete="off">` +
    '<input type="password" name="value" autofocus required autocomplete="new-password" aria-label="Secret value">' +
    '<button type="submit">Save to vault</button></form>'
  );
}

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
    total += buf.length;
    if (total > MAX_FORM_BODY_BYTES) {
      throw new Error("Form body too large");
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}
