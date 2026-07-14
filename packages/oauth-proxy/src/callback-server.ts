import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { VaultError } from "@harpoc/shared";

const DEFAULT_PORT = 19876;
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

export interface CallbackResult {
  code: string;
  state: string;
}

export class CallbackServer {
  private server: Server | null = null;
  private requestedPort: number;
  private boundPort: number | null = null;
  private timeoutId: ReturnType<typeof setTimeout> | null = null;
  private callbackPromise: Promise<CallbackResult> | null = null;
  private resolve: ((result: CallbackResult) => void) | null = null;
  private reject: ((err: Error) => void) | null = null;
  private settled = false;

  constructor(port: number = DEFAULT_PORT) {
    this.requestedPort = port;
  }

  /**
   * Settle the callback promise exactly once and clear the timeout. Every
   * terminal branch funnels through here so a standalone CallbackServer can
   * never leave the 5-minute timer live after the flow has been decided.
   */
  private settle(outcome: { result: CallbackResult } | { err: Error }): void {
    if (this.settled) return;
    this.settled = true;
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }
    if ("result" in outcome) {
      this.resolve?.(outcome.result);
    } else {
      this.reject?.(outcome.err);
    }
  }

  /**
   * Start the callback server. Resolves when the server is listening.
   * Call waitForCallback() after this to wait for the OAuth redirect.
   */
  async start(expectedState: string, timeoutMs: number = DEFAULT_TIMEOUT_MS): Promise<void> {
    if (this.server) {
      throw VaultError.oauthFlowFailed("Callback server already running");
    }

    this.settled = false;
    this.callbackPromise = new Promise<CallbackResult>((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });

    const expectedStateBuffer = Buffer.from(expectedState, "utf8");

    this.server = createServer((req: IncomingMessage, res: ServerResponse) => {
      this.handleRequest(req, res, expectedStateBuffer);
    });

    await new Promise<void>((resolve, reject) => {
      const srv = this.server as Server;
      srv.on("error", reject);
      srv.listen(this.requestedPort, "127.0.0.1", () => {
        const addr = srv.address() as { port: number };
        this.boundPort = addr.port;
        resolve();
      });
    });

    // Set timeout; unref'd so a pending flow never blocks process exit —
    // the settle path, not the event loop, owns its lifetime.
    this.timeoutId = setTimeout(() => {
      this.settle({ err: VaultError.oauthCallbackTimeout() });
      this.stop().catch(() => {});
    }, timeoutMs);
    this.timeoutId.unref();
  }

  /**
   * Wait for the OAuth redirect callback. Must call start() first.
   */
  waitForCallback(): Promise<CallbackResult> {
    if (!this.callbackPromise) {
      throw VaultError.oauthFlowFailed("Callback server not started");
    }
    return this.callbackPromise;
  }

  private handleRequest(
    req: IncomingMessage,
    res: ServerResponse,
    expectedStateBuffer: Buffer,
  ): void {
    // Constant base: only path + query matter, and boundPort may already be
    // nulled by the post-settle stop() when a second in-flight request lands.
    const url = new URL(req.url ?? "/", "http://127.0.0.1");

    if (url.pathname !== "/oauth/callback") {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not Found");
      return;
    }

    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const error = url.searchParams.get("error");

    if (error) {
      const description = url.searchParams.get("error_description") ?? error;
      this.settle({ err: VaultError.oauthFlowFailed(description) });
      this.respondAndStop(
        res,
        400,
        "<html><body><h1>Authorization Failed</h1><p>You can close this window.</p></body></html>",
      );
      return;
    }

    if (!code || !state) {
      this.settle({ err: VaultError.oauthFlowFailed("Missing code or state in callback") });
      this.respondAndStop(
        res,
        400,
        "<html><body><h1>Invalid Callback</h1><p>Missing parameters.</p></body></html>",
      );
      return;
    }

    // Timing-safe state comparison
    const stateBuffer = Buffer.from(state, "utf8");
    if (
      stateBuffer.length !== expectedStateBuffer.length ||
      !timingSafeEqual(stateBuffer, expectedStateBuffer)
    ) {
      this.settle({ err: VaultError.oauthInvalidState() });
      this.respondAndStop(
        res,
        400,
        "<html><body><h1>Invalid State</h1><p>CSRF protection triggered.</p></body></html>",
      );
      return;
    }

    this.settle({ result: { code, state } });
    this.respondAndStop(
      res,
      200,
      "<html><body><h1>Authorization Successful</h1><p>You can close this window and return to the terminal.</p></body></html>",
    );
  }

  /** Answer the browser, then close the server once the response is flushed. */
  private respondAndStop(res: ServerResponse, status: number, html: string): void {
    res.writeHead(status, { "Content-Type": "text/html" });
    res.end(html, () => {
      this.stop().catch(() => {});
    });
  }

  /**
   * Stop the callback server and clean up resources.
   */
  async stop(): Promise<void> {
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }

    if (this.server) {
      const srv = this.server;
      this.server = null;
      this.boundPort = null;
      // callbackPromise deliberately survives: the callback handler stops the
      // server right after settling, and a caller must still be able to await
      // the settled result. start() replaces the promise for a fresh flow.
      await new Promise<void>((resolve) => {
        srv.close(() => resolve());
      });
    }
  }

  get isRunning(): boolean {
    return this.server !== null;
  }

  /**
   * The port the server is actually listening on.
   * If port 0 was requested, this returns the OS-assigned port.
   * Returns the requested port if the server has not yet started.
   */
  get listenPort(): number {
    return this.boundPort ?? this.requestedPort;
  }
}
