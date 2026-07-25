import { spawn, type ChildProcess } from "node:child_process";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { MAX_MCP_STDERR_BYTES, MAX_MCP_STDOUT_BUFFER_BYTES } from "@harpoc/shared";
import { CappedOutput } from "./capped-output.js";

/** Exit code/signal of a terminated downstream MCP server child. */
export interface ChildExitInfo {
  code: number | null;
  signal: string | null;
}

export interface StdioChildParams {
  /** Absolute binary path already pinned by resolveAndMatchCommand — spawned verbatim. */
  resolvedCommand: string;
  args: string[];
  /** Clean environment (buildCleanEnv output) carrying the injected credential. */
  env: Record<string, string>;
  cwd?: string;
}

/** Grace period between shutdown escalation steps (stdin end → SIGTERM → SIGKILL). */
const CLOSE_GRACE_MS = 2_000;

type McpStdioModule = typeof import("@modelcontextprotocol/sdk/shared/stdio.js");

/**
 * MCP client transport over a vault-spawned stdio child (thesis §4.5.4).
 *
 * Deliberately NOT the SDK's StdioClientTransport: that transport spawns via
 * cross-spawn, which wraps non-.exe/.com commands in cmd.exe on Windows (a
 * shell invocation), force-merges an inherited default environment, and
 * discards the child's exit code/signal. This transport preserves the
 * process-context execution discipline — direct spawn with shell:false of a
 * pinned resolved path, clean environment, windowsHide — and records exit
 * forensics for the crash audit trail. `exitInfo` is assigned BEFORE `onclose`
 * fires, so crash handlers observing the close deterministically see it.
 *
 * stderr is captured into a capped buffer (never inherited, never returned to
 * the agent); it may contain the credential and is only ever used
 * pattern-sanitized in audit detail.
 *
 * Line framing is the vault's own rather than the SDK's ReadBuffer: the
 * downstream server is untrusted output, so the pending buffer is capped (an
 * unframed stream would otherwise grow without bound) and every line is
 * consumed BEFORE it is parsed, so a line the parser cannot even stringify
 * cannot leave the drain loop spinning on an unchanged buffer — which, being
 * synchronous, would block the vault's event loop permanently.
 */
export class StdioChildTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  exitInfo: ChildExitInfo | null = null;
  readonly stderrTail = new CappedOutput(MAX_MCP_STDERR_BYTES);

  private child: ChildProcess | null = null;
  private serializeMessage: McpStdioModule["serializeMessage"] | null = null;
  private deserializeMessage: McpStdioModule["deserializeMessage"] | null = null;
  private started = false;
  private stdoutBuffer: Buffer = Buffer.alloc(0);
  private framingFailed = false;

  constructor(private readonly params: StdioChildParams) {}

  get pid(): number | undefined {
    return this.child?.pid;
  }

  async start(): Promise<void> {
    if (this.started) {
      throw new Error("StdioChildTransport already started");
    }
    this.started = true;

    // Lazy SDK import (dependency confinement, §5.2): SDK code enters the
    // process only once a downstream server is actually spawned.
    const stdio = await import("@modelcontextprotocol/sdk/shared/stdio.js");
    this.serializeMessage = stdio.serializeMessage;
    this.deserializeMessage = stdio.deserializeMessage;

    await new Promise<void>((resolve, reject) => {
      const child = spawn(this.params.resolvedCommand, this.params.args, {
        shell: false,
        env: this.params.env,
        cwd: this.params.cwd,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      });
      this.child = child;

      let settled = false;
      child.once("spawn", () => {
        settled = true;
        resolve();
      });
      child.on("error", (err) => {
        if (!settled) {
          settled = true;
          reject(err);
        } else {
          this.onerror?.(err);
        }
      });

      child.stdout?.on("data", (chunk: Buffer) => this.onStdout(chunk));
      child.stderr?.on("data", (chunk: Buffer) => this.stderrTail.push(chunk));

      // EPIPE lands on the stdin stream (not the ChildProcess) when the child
      // dies mid-write — without a listener it crashes the process as an
      // unhandled 'error' event (observed on macOS, where a fast-exiting child
      // races the initialize write). The write failure itself is surfaced by
      // send()'s callback; exit forensics arrive via 'close'.
      child.stdin?.on("error", () => {});

      child.on("close", (code, signal) => {
        this.exitInfo = { code, signal };
        this.child = null;
        this.stdoutBuffer = Buffer.alloc(0);
        this.onclose?.();
      });
    });
  }

  send(message: JSONRPCMessage): Promise<void> {
    return new Promise((resolve, reject) => {
      const stdin = this.child?.stdin;
      const serializeMessage = this.serializeMessage;
      if (!stdin || !serializeMessage) {
        reject(new Error("Not connected"));
        return;
      }
      // The write callback fires on flush or failure — a dead pipe rejects
      // instead of waiting forever for a 'drain' that never comes.
      stdin.write(serializeMessage(message), (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async close(): Promise<void> {
    const child = this.child;
    if (!child) return;

    await new Promise<void>((resolve) => {
      const term = setTimeout(() => child.kill("SIGTERM"), CLOSE_GRACE_MS);
      const kill = setTimeout(() => child.kill("SIGKILL"), CLOSE_GRACE_MS * 2);
      if (term.unref) term.unref();
      if (kill.unref) kill.unref();

      child.once("close", () => {
        clearTimeout(term);
        clearTimeout(kill);
        resolve();
      });

      child.stdin?.end();
    });
  }

  /** Best-effort synchronous kill for seal paths that cannot await. */
  killSync(): void {
    this.child?.kill("SIGKILL");
  }

  private onStdout(chunk: Buffer): void {
    if (this.framingFailed) return;
    if (this.stdoutBuffer.length + chunk.length > MAX_MCP_STDOUT_BUFFER_BYTES) {
      // One oversized or never-terminated line would otherwise buffer the whole
      // stream in the vault's memory. Fail the connection visibly instead: the
      // registry sees the close as a crash, audits it, and never auto-respawns.
      this.failFraming(
        `Downstream MCP server exceeded ${String(MAX_MCP_STDOUT_BUFFER_BYTES)} bytes of unframed stdout`,
      );
      return;
    }
    this.stdoutBuffer = Buffer.concat([this.stdoutBuffer, chunk]);
    this.drainMessages();
  }

  private drainMessages(): void {
    const deserialize = this.deserializeMessage;
    if (!deserialize) return;
    for (;;) {
      const index = this.stdoutBuffer.indexOf(0x0a);
      if (index === -1) return;
      const line = this.stdoutBuffer.subarray(0, index);
      // Consume before parsing: progress is then structural, so no parse
      // failure — not even one thrown before a line can be stringified — can
      // spin this loop on an unchanged buffer.
      this.stdoutBuffer = this.stdoutBuffer.subarray(index + 1);
      let message: JSONRPCMessage;
      try {
        message = deserialize(line.toString("utf8").replace(/\r$/, ""));
      } catch (err) {
        this.onerror?.(err instanceof Error ? err : new Error(String(err)));
        continue;
      }
      this.onmessage?.(message);
    }
  }

  private failFraming(reason: string): void {
    this.framingFailed = true;
    this.stdoutBuffer = Buffer.alloc(0);
    this.onerror?.(new Error(reason));
    this.child?.kill("SIGKILL");
  }
}
