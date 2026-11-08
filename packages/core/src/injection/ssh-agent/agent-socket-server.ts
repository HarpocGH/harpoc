import { chmodSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { ErrorCode, VaultError, agentSocketCaller } from "@harpoc/shared";
import type { CallerContext, ServerTransport } from "@harpoc/shared";
import { createAgentConnectionResponder } from "./agent-connection.js";
import type {
  AgentBinding,
  AgentIdentity,
  AgentIdentityProvider,
  AgentSignRequest,
} from "./agent-connection.js";
import { prepareUnixSocketPath } from "./unix-socket.js";
import { restrictWindowsPipeToAccount } from "../../session/owner-only.js";

/**
 * The engine surface the agent socket uses — three members a `VaultEngine`
 * has; declared here so the server depends on them, not on the class (the
 * egress proxy's `ProxyEngine`, RQ-14). The engine judges every request and
 * writes its row; the server only frames.
 */
export interface AgentSocketEngine {
  listAgentSocketIdentities(
    caller: CallerContext,
    binding: AgentBinding | null,
  ): Promise<AgentIdentity[]>;
  signForAgentSocket(caller: CallerContext, request: AgentSignRequest): Promise<Buffer>;
  auditServerStart(options: {
    transport: ServerTransport;
    tokenless: boolean;
    consumer?: string;
  }): void;
}

export interface AgentSocketServerOptions {
  /** `<runtime-dir>/<consumer>/ssh-agent.sock`; on Windows a named pipe `\\.\pipe\<name>` (the daemon's `\\.\pipe\harpoc-<consumer>-ssh-agent`). */
  socketPath: string;
  /** The registered agent the socket signs for; the socket's directory is its only authentication. */
  consumer: string;
  engine: AgentSocketEngine;
  /** Every request an engine throw answered `SSH_AGENT_FAILURE`, value-free: the engine's `VaultError`, any other throw as `INTERNAL_ERROR`. */
  onError?: (err: VaultError) => void;
  /** Concurrent connections, the rest closed at accept; `AGENT_SOCKET_MAX_CONNECTIONS` by default. */
  maxConnections?: number;
  /** A connection with no traffic for this long is closed; `AGENT_SOCKET_IDLE_TIMEOUT_MS` by default. */
  idleTimeoutMs?: number;
  /**
   * Windows only: the consumer's account SID. The pipe's DACL is then set to this account,
   * SYSTEM and Administrators (full) and the consumer (read and write) — Everyone's and
   * Anonymous's read removed — before the start row; without it the pipe keeps Node's default
   * DACL (read and write for this account, SYSTEM and Administrators only). Ignored on POSIX.
   */
  win32ConsumerSid?: string;
}

/** ssh holds its agent connection for the authentication only (`sshconnect2.c` `pubkey_cleanup`). */
export const AGENT_SOCKET_MAX_CONNECTIONS = 64;
export const AGENT_SOCKET_IDLE_TIMEOUT_MS = 120_000;

const LABEL = "ssh-agent socket";
const WIN32_PIPE = /^\\\\\.\\pipe\\[^\\]+$/;

function internalAgentSocketError(): VaultError {
  return new VaultError(ErrorCode.INTERNAL_ERROR, "Internal agent socket error");
}

/** A bind failure as a code, never node's text (hard rule 9). */
function bindRefusal(err: unknown, path: string): VaultError {
  if (err instanceof VaultError) return err;
  const code = (err as NodeJS.ErrnoException).code;
  if (code === "EADDRINUSE") {
    return VaultError.invalidInput(`${LABEL}: another process is listening on ${path}`);
  }
  return VaultError.invalidInput(`${LABEL}: cannot listen on ${path} (${code ?? "unknown error"})`);
}

/**
 * The persistent ssh-agent socket of deployment model B (design § 3 M5):
 * one per consumer directory, serving the keys the engine grants the
 * consumer — signatures only, bound to a pinned, allowlisted host by
 * `session-bind@openssh.com`. The ssh-agent protocol carries no caller
 * identity: the `02750` consumer directory and the socket's `0660` mode are
 * the authentication. Console-free — `onError` is the diagnostics channel.
 */
export class AgentSocketServer {
  private readonly sockets = new Set<Socket>();
  private readonly inFlight = new Set<Promise<void>>();
  private stopping: Promise<void> | null = null;
  /** Connections accepted before the start row is written wait here, unread, until it is. */
  private early: Socket[] | null = [];

  private constructor(
    readonly socketPath: string,
    readonly consumer: string,
    private readonly server: Server,
    private readonly posix: boolean,
  ) {}

  /** Bind `socketPath`, then write the listener's one `server.start` row; an unwritable row undoes the bind. */
  static async start(options: AgentSocketServerOptions): Promise<AgentSocketServer> {
    const { socketPath, consumer, engine, onError } = options;
    const posix = process.platform !== "win32";
    if (!posix && !WIN32_PIPE.test(socketPath)) {
      throw VaultError.invalidInput(
        `${LABEL}: not supported on Windows except on a named pipe \\\\.\\pipe\\<name> (no socket directory mode to rely on): ${socketPath}`,
      );
    }
    if (posix) {
      try {
        await prepareUnixSocketPath(socketPath, LABEL);
      } catch (err) {
        throw bindRefusal(err, socketPath);
      }
    }

    const caller = agentSocketCaller(consumer);
    const server = createServer();
    server.maxConnections = options.maxConnections ?? AGENT_SOCKET_MAX_CONNECTIONS;
    const instance = new AgentSocketServer(socketPath, consumer, server, posix);
    const provider: AgentIdentityProvider = {
      sessionBind: true,
      identities: (binding) =>
        instance.track(() => engine.listAgentSocketIdentities(caller, binding), onError),
      sign: (request) => instance.track(() => engine.signForAgentSocket(caller, request), onError),
    };
    const idleTimeoutMs = options.idleTimeoutMs ?? AGENT_SOCKET_IDLE_TIMEOUT_MS;
    server.on("connection", (stream: Socket) => instance.accept(stream, provider, idleTimeoutMs));

    await new Promise<void>((resolve, reject) => {
      const refuse = (err: Error): void => reject(bindRefusal(err, socketPath));
      server.once("error", refuse);
      server.listen(socketPath, () => {
        server.removeListener("error", refuse);
        // An accept error after the bind (EMFILE) drops that connection; the listener stays.
        server.on("error", () => undefined);
        resolve();
      });
    });
    // A connection accepted before the row waits unread: none is served before it is written.
    try {
      if (posix) chmodSync(socketPath, 0o660);
    } catch (err) {
      await instance.stop();
      throw bindRefusal(err, socketPath);
    }
    if (!posix && options.win32ConsumerSid !== undefined) {
      try {
        await restrictWindowsPipeToAccount(socketPath, options.win32ConsumerSid);
      } catch {
        await instance.stop();
        throw VaultError.invalidInput(
          `${LABEL}: the access list of ${socketPath} could not be set to the consumer's account`,
        );
      }
    }
    try {
      engine.auditServerStart({ transport: "ssh-agent", tokenless: true, consumer });
    } catch (err) {
      await instance.stop();
      throw err;
    }
    instance.release(provider, idleTimeoutMs);
    return instance;
  }

  /** Close the listener and every connection, let in-flight engine calls settle, remove the socket file. */
  stop(): Promise<void> {
    this.stopping ??= (async () => {
      const closed = new Promise<void>((resolve) => this.server.close(() => resolve()));
      for (const stream of this.sockets) stream.destroy();
      this.sockets.clear();
      this.early = null;
      await closed;
      while (this.inFlight.size > 0) await Promise.all(this.inFlight);
      if (this.posix) rmSync(this.socketPath, { force: true });
    })();
    return this.stopping;
  }

  /** Serve a connection once the start row is written; until then keep it, unread, for `release`. */
  private accept(stream: Socket, provider: AgentIdentityProvider, idleTimeoutMs: number): void {
    if (this.stopping) {
      stream.destroy();
      return;
    }
    this.sockets.add(stream);
    stream.on("close", () => this.sockets.delete(stream));
    stream.on("error", () => {
      /* per-connection transport error — ignore, the client sees its connection end */
    });
    if (this.early !== null) {
      this.early.push(stream);
      return;
    }
    this.serve(stream, provider, idleTimeoutMs);
  }

  /** The start row is written: serve every connection that arrived before it, in order. */
  private release(provider: AgentIdentityProvider, idleTimeoutMs: number): void {
    const waiting = this.early ?? [];
    this.early = null;
    for (const stream of waiting) {
      if (!stream.destroyed) this.serve(stream, provider, idleTimeoutMs);
    }
  }

  private serve(stream: Socket, provider: AgentIdentityProvider, idleTimeoutMs: number): void {
    if (this.stopping) {
      stream.destroy();
      return;
    }
    stream.setTimeout(idleTimeoutMs, () => stream.destroy());

    const respond = createAgentConnectionResponder(provider);
    stream.on("data", (chunk: Buffer) => {
      // One chunk in flight per connection: the next chunk — and a half-closing
      // client's end, which ends this side too — is read after the reply is written.
      stream.pause();
      void respond(chunk).then(
        (reply) => {
          if (stream.destroyed) return;
          if (reply.length > 0) stream.write(reply);
          stream.resume();
        },
        () => {
          stream.destroy();
        },
      );
    });
  }

  private track<T>(call: () => Promise<T>, onError?: (err: VaultError) => void): Promise<T> {
    const run = new Promise<T>((resolve) => resolve(call())).catch((err: unknown) => {
      onError?.(err instanceof VaultError ? err : internalAgentSocketError());
      throw err;
    });
    const settled = run.then(
      () => undefined,
      () => undefined,
    );
    this.inFlight.add(settled);
    void settled.then(() => this.inFlight.delete(settled));
    return run;
  }
}
