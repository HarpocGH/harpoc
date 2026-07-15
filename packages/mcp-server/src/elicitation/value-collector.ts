import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const MAX_FORM_BODY_BYTES = 128 * 1024;
const TOKEN_BYTES = 32;

export interface ValueCollectorOptions {
  /** Secret name shown on the form (display only, HTML-escaped). */
  subject: string;
  operation: "create" | "rotate";
  timeoutMs?: number;
}

export interface ValueCollector {
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

  function handleRequest(req: IncomingMessage, res: ServerResponse): void {
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

  const port = (server.address() as AddressInfo).port;
  const url = `http://127.0.0.1:${port}${path}`;

  const timeoutId = setTimeout(() => {
    settle(() => rejectValue(new Error("Value collection timed out")));
    void close();
  }, timeoutMs);

  async function close(): Promise<void> {
    clearTimeout(timeoutId);
    settle(() => rejectValue(new Error("Value collector closed")));
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeIdleConnections();
    });
  }

  return {
    url,
    waitForValue: () => valuePromise,
    close,
  };
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
