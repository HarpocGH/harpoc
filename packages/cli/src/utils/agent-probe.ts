import { createHash } from "node:crypto";
import { connect } from "node:net";

const SSH_AGENT_FAILURE = 5;
const SSH_AGENT_IDENTITIES_ANSWER = 12;

/** One `SSH_AGENTC_REQUEST_IDENTITIES` (11) in its length prefix — RFC 9987 § 5.5. */
const REQUEST_IDENTITIES = Buffer.from([0, 0, 0, 1, 11]);

/** The vault agent's own message bound (core's `agent-protocol.ts`): an answer claiming more is no agent's. */
const MAX_ANSWER = 256 * 1024;

/** One identity an agent lists — public facts only, as `ssh-add -l` and `ssh-add -L` print them. */
export interface AgentListedIdentity {
  /** The key type the public-key blob names: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, … */
  keyType: string;
  /** `SHA256:<unpadded base64>` of the blob — the form `ssh-add -l` and `ssh-keygen -l` print. */
  fingerprint: string;
  comment: string;
  /** The OpenSSH public-key line `<type> <base64> <comment>` — the form `ssh-add -L` prints. */
  publicKey: string;
}

/** Why a probe found no agent answering: the connect error's class, the deadline, or the bytes. */
export type AgentProbeFailure =
  | "no_socket"
  | "not_a_socket"
  | "refused"
  | "permission_denied"
  | "timeout"
  | "not_an_agent"
  | "unreachable";

/**
 * What one identities request found at a socket path: an agent and the identities it lists, an
 * agent that answered `SSH_AGENT_FAILURE` (`identities: null` — a sealed vault answers so), or no
 * agent and the reason.
 */
export type AgentProbe =
  | { listening: true; identities: AgentListedIdentity[] | null }
  | { listening: false; reason: AgentProbeFailure };

/** `SHA256:` and the unpadded base64 of the public-key blob's SHA-256 (`ssh-keygen -l -E sha256`). */
export function sshKeyFingerprint(publicKeyBlob: Uint8Array): string {
  const digest = createHash("sha256").update(publicKeyBlob).digest("base64");
  return `SHA256:${digest.replace(/=+$/, "")}`;
}

/**
 * Ask the agent at `socketPath` for its identities — the one request `ssh-add -l` sends — and read
 * the one answer under `timeoutMs`. Sends nothing else, signs nothing, and never rejects: every
 * failure is an `AgentProbe` with its reason.
 */
export function probeAgentSocket(socketPath: string, timeoutMs: number): Promise<AgentProbe> {
  return new Promise((resolve) => {
    let received = Buffer.alloc(0);
    let settled = false;
    const socket = connect(socketPath);
    const finish = (probe: AgentProbe): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(probe);
    };
    const timer = setTimeout(() => finish({ listening: false, reason: "timeout" }), timeoutMs);
    socket.on("connect", () => socket.write(REQUEST_IDENTITIES));
    socket.on("data", (chunk: Buffer) => {
      received = Buffer.concat([received, chunk]);
      if (received.length < 4) return;
      const length = received.readUInt32BE(0);
      if (length === 0 || length > MAX_ANSWER) {
        finish({ listening: false, reason: "not_an_agent" });
        return;
      }
      if (received.length >= 4 + length) finish(readAnswer(received.subarray(4, 4 + length)));
    });
    socket.on("error", (err: NodeJS.ErrnoException) => {
      finish({ listening: false, reason: failureOf(err.code) });
    });
    socket.on("close", () => finish({ listening: false, reason: "not_an_agent" }));
  });
}

/** A bounds-checked reader over one agent message: big-endian `uint32` and `string` (RFC 4251 § 5). */
class MessageReader {
  private offset = 0;

  constructor(private readonly message: Buffer) {}

  get remaining(): number {
    return this.message.length - this.offset;
  }

  byte(): number {
    if (this.remaining < 1) throw new RangeError("truncated");
    return this.message.readUInt8(this.offset++);
  }

  uint32(): number {
    if (this.remaining < 4) throw new RangeError("truncated");
    const value = this.message.readUInt32BE(this.offset);
    this.offset += 4;
    return value;
  }

  string(): Buffer {
    const length = this.uint32();
    if (this.remaining < length) throw new RangeError("truncated");
    const value = this.message.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }
}

/** `SSH_AGENT_IDENTITIES_ANSWER`: `uint32 nkeys`, then `string key blob · string comment` per key. */
function readAnswer(message: Buffer): AgentProbe {
  try {
    const reader = new MessageReader(message);
    const type = reader.byte();
    if (type === SSH_AGENT_FAILURE && reader.remaining === 0) {
      return { listening: true, identities: null };
    }
    if (type !== SSH_AGENT_IDENTITIES_ANSWER) return { listening: false, reason: "not_an_agent" };
    const count = reader.uint32();
    const identities: AgentListedIdentity[] = [];
    for (let i = 0; i < count; i++) {
      const blob = reader.string();
      const comment = reader.string().toString("utf8");
      const keyType = new MessageReader(blob).string().toString("utf8");
      const key = `${keyType} ${blob.toString("base64")}`;
      identities.push({
        keyType,
        fingerprint: sshKeyFingerprint(blob),
        comment,
        publicKey: comment === "" ? key : `${key} ${comment}`,
      });
    }
    if (reader.remaining !== 0) return { listening: false, reason: "not_an_agent" };
    return { listening: true, identities };
  } catch {
    return { listening: false, reason: "not_an_agent" };
  }
}

function failureOf(code: string | undefined): AgentProbeFailure {
  switch (code) {
    case "ENOENT":
    case "ENOTDIR":
      return "no_socket";
    case "ENOTSOCK":
      return "not_a_socket";
    case "ECONNREFUSED":
      return "refused";
    case "EACCES":
    case "EPERM":
      return "permission_denied";
    default:
      return "unreachable";
  }
}
