import { spawn, type ChildProcess } from "node:child_process";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { MAX_MCP_STDERR_BYTES, MAX_MCP_STDOUT_BUFFER_BYTES } from "@harpoc/shared";
import { CappedOutput } from "./capped-output.js";
import type { TreeKillMechanism } from "./win32-job-wrapper.js";
import { isJobWrapperFailure } from "./win32-job-wrapper.js";

/** Exit code/signal of a terminated downstream MCP server child. */
export interface ChildExitInfo {
  code: number | null;
  signal: string | null;
  /**
   * The wrapper's own failure line (2026-09-10): the reserved exit code plus
   * the `harpoc-job: ` marker under the job tier — the server never started.
   * `code` and `signal` are null then, as for a Node-level spawn failure.
   */
  wrapper_failure?: string;
}

export interface StdioChildParams {
  /**
   * The pinned resolved path, or the vault-authored isolation wrapper carrying
   * it as the payload (D51) — spawned verbatim either way.
   */
  resolvedCommand: string;
  args: string[];
  /** Clean environment (buildCleanEnv output) carrying the injected credential. */
  env: Record<string, string>;
  cwd?: string;
  /** The tier the launch runs under (2026-09-10); under `job` a reserved exit is checked for the wrapper's marker. */
  treeKill?: TreeKillMechanism;
  /**
   * The policy's strict tree exit (D2, 2026-09-10): on POSIX the server is
   * spawned `detached` — its own process group — and the group is killed when
   * the server exits, on its own or under close(). Off POSIX the job does it.
   */
  strictTreeExit?: boolean;
}

/** Grace period between shutdown escalation steps (stdin end → SIGTERM → SIGKILL). */
const CLOSE_GRACE_MS = 2_000;

/**
 * Cap on the wrapper-failure line kept in `exitInfo` (I1, 2026-09-10). The
 * line is downstream stderr — a payload faking the reserved exit code and the
 * marker chooses it — and it reaches a `VaultError` message, hence the model's
 * tool-result text and the REST error body. `stderrTail` bounds it only at
 * `MAX_MCP_STDERR_BYTES` (64 KiB); a diagnostic line needs far less, and the
 * wrapper's own lines are under 100 characters.
 */
const MAX_WRAPPER_FAILURE_CHARS = 512;

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
        detached: this.params.strictTreeExit === true && process.platform !== "win32",
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

      if (this.params.strictTreeExit === true && process.platform !== "win32") {
        child.on("exit", () => {
          // The POSIX arm (D2): the server led its own group; nothing it
          // started outlives it. ESRCH means nobody was left.
          if (child.pid === undefined) return;
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            // The group is empty, or already gone.
          }
        });
      }

      child.on("close", (code, signal) => {
        const stderrHead = this.stderrTail.toString();
        const wrapperFailed =
          this.params.treeKill === "job" && isJobWrapperFailure(code, stderrHead);
        this.exitInfo = wrapperFailed
          ? {
              code: null,
              signal: null,
              wrapper_failure: (stderrHead.split(/\r?\n/, 1)[0] ?? stderrHead)
                .trim()
                .slice(0, MAX_WRAPPER_FAILURE_CHARS),
            }
          : { code, signal };
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
      // An exit that ALREADY fired is the one that landed first (I2,
      // 2026-09-10): a server that died on its own while a grandchild held the
      // pipes never ran the 'close' listener, so `this.child` is still set and
      // there is no future 'exit' left to observe. Waiting on 'close' alone
      // would block the caller — and burn the shutdown budget — for the
      // grandchild's life, while the escalation timers signalled a dead pid.
      if (child.exitCode !== null || child.signalCode !== null) {
        child.stdin?.end();
        resolve();
        return;
      }

      const term = setTimeout(() => child.kill("SIGTERM"), CLOSE_GRACE_MS);
      const kill = setTimeout(() => child.kill("SIGKILL"), CLOSE_GRACE_MS * 2);
      if (term.unref) term.unref();
      if (kill.unref) kill.unref();

      // 'exit' or 'close', whichever lands first (note 7, 2026-09-10): a
      // grandchild holding the inherited pipes can withhold 'close' for its
      // whole life on the unwrapped tier; after SIGKILL 'exit' is certain.
      let done = false;
      const settle = (): void => {
        if (done) return;
        done = true;
        clearTimeout(term);
        clearTimeout(kill);
        resolve();
      };
      child.once("exit", settle);
      child.once("close", settle);

      child.stdin?.end();
    });
    this.child = null;
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
