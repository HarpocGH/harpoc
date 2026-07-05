import { spawn, type ChildProcess } from "node:child_process";
import { ReadBuffer, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { MAX_MCP_STDERR_BYTES } from "@harpoc/shared";
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
 */
export class StdioChildTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  exitInfo: ChildExitInfo | null = null;
  readonly stderrTail = new CappedOutput(MAX_MCP_STDERR_BYTES);

  private child: ChildProcess | null = null;
  private readonly readBuffer = new ReadBuffer();
  private started = false;

  constructor(private readonly params: StdioChildParams) {}

  get pid(): number | undefined {
    return this.child?.pid;
  }

  async start(): Promise<void> {
    if (this.started) {
      throw new Error("StdioChildTransport already started");
    }
    this.started = true;

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

      child.stdout?.on("data", (chunk: Buffer) => {
        this.readBuffer.append(chunk);
        this.drainMessages();
      });
      child.stderr?.on("data", (chunk: Buffer) => this.stderrTail.push(chunk));

      child.on("close", (code, signal) => {
        this.exitInfo = { code, signal };
        this.child = null;
        this.readBuffer.clear();
        this.onclose?.();
      });
    });
  }

  send(message: JSONRPCMessage): Promise<void> {
    return new Promise((resolve, reject) => {
      const stdin = this.child?.stdin;
      if (!stdin) {
        reject(new Error("Not connected"));
        return;
      }
      const json = serializeMessage(message);
      if (stdin.write(json)) {
        resolve();
      } else {
        stdin.once("drain", resolve);
      }
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

  private drainMessages(): void {
    for (;;) {
      let message: JSONRPCMessage | null;
      try {
        message = this.readBuffer.readMessage();
      } catch (err) {
        this.onerror?.(err instanceof Error ? err : new Error(String(err)));
        continue;
      }
      if (message === null) return;
      this.onmessage?.(message);
    }
  }
}
