import {
  SESSION_BIND_EXTENSION,
  parseSessionBind,
  verifyHostKeySignature,
} from "./session-bind.js";
import type { AgentBinding } from "./session-bind.js";
import { SshReader, writeByte, writeString, writeUint32 } from "./ssh-wire.js";

export type { AgentBinding } from "./session-bind.js";

/**
 * The agent protocol of the persistent agent socket (RFC 9987; OpenSSH `PROTOCOL.agent`):
 * one responder per connection over an asynchronous identity provider. It serves
 * `REQUEST_IDENTITIES`, `SIGN_REQUEST` and the one extension `session-bind@openssh.com`;
 * every other request is `SSH_AGENT_FAILURE`, as in the ephemeral agent's responder
 * (`agent-protocol.ts`, which stays as it is). Requests on one connection are answered in
 * order. The responder decides only what the wire decides — framing, the bind — and hands
 * every well-formed sign request to the provider with the connection's facts, so the
 * provider judges and audits every refusal of a signature.
 */
const SSH_AGENT_FAILURE = 5;
const SSH_AGENT_SUCCESS = 6;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;
const SSH_AGENTC_EXTENSION = 27;
const SSH_AGENT_EXTENSION_FAILURE = 28;

/** OpenSSH's `AGENT_MAX_LEN`, and the ephemeral agent's cap. */
const MAX_MESSAGE = 256 * 1024;

const frame = (body: Buffer): Buffer => Buffer.concat([writeUint32(body.length), body]);
const FAILURE = frame(writeByte(SSH_AGENT_FAILURE));
const SUCCESS = frame(writeByte(SSH_AGENT_SUCCESS));
const EXTENSION_FAILURE = frame(writeByte(SSH_AGENT_EXTENSION_FAILURE));
const SESSION_BIND_NAME = Buffer.from(SESSION_BIND_EXTENSION, "utf8");

export interface AgentIdentity {
  publicKeyBlob: Buffer;
  comment: string;
}

export interface AgentSignRequest {
  keyBlob: Buffer;
  data: Buffer;
  flags: number;
  /** The connection's verified authentication bind, or null. */
  binding: AgentBinding | null;
  /** The connection refused a forwarding bind (`is_forwarding` set); `binding` is then null. */
  forwarding: boolean;
}

/** What a connection serves; every refusal of a signature is the provider's to judge and audit. */
export interface AgentIdentityProvider {
  /** False: every bind is answered `SSH_AGENT_FAILURE` and the connection stays unbound. */
  readonly sessionBind: boolean;
  /** The identities to list on a connection with this binding (null: unbound). */
  identities(binding: AgentBinding | null): Promise<AgentIdentity[]>;
  /** The SSH signature blob for the request; a rejection answers `SSH_AGENT_FAILURE`. */
  sign(request: AgentSignRequest): Promise<Buffer>;
}

/**
 * The binding rules of OpenSSH's `process_ext_session_bind` with forwarding refused:
 * a bind whose signature verifies and whose `is_forwarding` is false binds an unbound
 * connection; every bind after it is refused (a connection bound for authentication takes
 * no second bind, a duplicate included), and once a bind is refused the connection never
 * binds — a forwarded channel's own first bind is a forwarding bind, so the next hop's
 * bind relayed through it is refused too.
 */
class AgentConnectionState {
  private bound: AgentBinding | null = null;
  private refused: "forwarding" | "invalid" | null = null;

  get binding(): AgentBinding | null {
    return this.bound;
  }

  get forwarding(): boolean {
    return this.refused === "forwarding";
  }

  bind(contents: Buffer): boolean {
    if (this.bound !== null || this.refused !== null) return false;
    const bind = parseSessionBind(contents);
    if (
      bind === null ||
      !verifyHostKeySignature(bind.hostKeyBlob, bind.signature, bind.sessionId)
    ) {
      this.refused = "invalid";
      return false;
    }
    if (bind.isForwarding) {
      this.refused = "forwarding";
      return false;
    }
    this.bound = {
      hostKeyBlob: Buffer.from(bind.hostKeyBlob),
      sessionId: Buffer.from(bind.sessionId),
    };
    return true;
  }
}

/**
 * Build the responder of one connection: feed it each chunk read; it resolves with the
 * reply bytes for every request the chunk completed (empty until a frame completes), in
 * request order — calls are queued, so a chunk is processed only after the previous
 * chunk's replies are settled. A frame claiming an implausible length fails closed and
 * resets, as the ephemeral responder does. Never rejects.
 */
export function createAgentConnectionResponder(
  provider: AgentIdentityProvider,
): (chunk: Buffer) => Promise<Buffer> {
  const state = new AgentConnectionState();
  let buffer: Buffer = Buffer.alloc(0);
  let queue: Promise<unknown> = Promise.resolve();

  async function handle(message: Buffer): Promise<Buffer> {
    const type = message[0];
    const payload = message.subarray(1);
    if (type === SSH_AGENTC_REQUEST_IDENTITIES) {
      if (state.forwarding) return identitiesAnswer([]);
      try {
        return identitiesAnswer(await provider.identities(state.binding));
      } catch {
        return FAILURE;
      }
    }
    if (type === SSH_AGENTC_SIGN_REQUEST) {
      let request: AgentSignRequest;
      try {
        const r = new SshReader(payload);
        const keyBlob = r.readString();
        const data = r.readString();
        const flags = r.readUint32();
        const { binding, forwarding } = state;
        request = { keyBlob, data, flags, binding, forwarding };
      } catch {
        return FAILURE;
      }
      try {
        const signature = await provider.sign(request);
        return frame(Buffer.concat([writeByte(SSH_AGENT_SIGN_RESPONSE), writeString(signature)]));
      } catch {
        return FAILURE;
      }
    }
    if (type === SSH_AGENTC_EXTENSION) {
      try {
        const name = new SshReader(payload).readString();
        if (!name.equals(SESSION_BIND_NAME) || !provider.sessionBind) return FAILURE;
        return state.bind(payload.subarray(4 + name.length)) ? SUCCESS : EXTENSION_FAILURE;
      } catch {
        return FAILURE;
      }
    }
    return FAILURE;
  }

  async function consume(chunk: Buffer): Promise<Buffer> {
    buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
    const out: Buffer[] = [];
    while (buffer.length >= 4) {
      const len = buffer.readUInt32BE(0);
      if (len === 0 || len > MAX_MESSAGE) {
        out.push(FAILURE);
        buffer = Buffer.alloc(0);
        break;
      }
      if (buffer.length < 4 + len) break;
      const message = buffer.subarray(4, 4 + len);
      buffer = buffer.subarray(4 + len);
      out.push(await handle(message));
    }
    return out.length === 0 ? Buffer.alloc(0) : Buffer.concat(out);
  }

  return (chunk: Buffer): Promise<Buffer> => {
    const reply = queue.then(() => consume(chunk));
    queue = reply.then(
      () => undefined,
      () => undefined,
    );
    return reply;
  };
}

function identitiesAnswer(identities: readonly AgentIdentity[]): Buffer {
  const body = [writeByte(SSH_AGENT_IDENTITIES_ANSWER), writeUint32(identities.length)];
  for (const id of identities) body.push(writeString(id.publicKeyBlob), writeString(id.comment));
  return frame(Buffer.concat(body));
}
