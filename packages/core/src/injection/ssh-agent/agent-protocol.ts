import { SshReader, writeByte, writeString, writeUint32 } from "./ssh-wire.js";
import type { LoadedKey } from "./key-loader.js";

/**
 * The OpenSSH agent protocol (OpenSSH `PROTOCOL.agent`), implemented for a
 * single ephemeral identity. Messages are `uint32 length ‖ byte type ‖ payload`.
 * Only identity listing and signing are served; every other request, key
 * mismatch or parse error yields SSH_AGENT_FAILURE. Fail-closed by construction.
 */
const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;

const MAX_MESSAGE = 256 * 1024; // an agent request carrying data-to-sign is small

/** Wrap a message body (type byte + payload) in its uint32 length prefix. */
function frame(body: Buffer): Buffer {
  return Buffer.concat([writeUint32(body.length), body]);
}

const FAILURE = frame(writeByte(SSH_AGENT_FAILURE));

function handleMessage(message: Buffer, key: LoadedKey): Buffer {
  if (message.length === 0) return FAILURE;
  const type = message[0];
  const payload = message.subarray(1);

  try {
    if (type === SSH_AGENTC_REQUEST_IDENTITIES) {
      const body = Buffer.concat([
        writeByte(SSH_AGENT_IDENTITIES_ANSWER),
        writeUint32(1),
        writeString(key.publicKeyBlob),
        writeString("harpoc-ephemeral"),
      ]);
      return frame(body);
    }

    if (type === SSH_AGENTC_SIGN_REQUEST) {
      const r = new SshReader(payload);
      const keyBlob = r.readString();
      const data = r.readString();
      const flags = r.readUint32();
      if (!keyBlob.equals(key.publicKeyBlob)) {
        return FAILURE; // signature requested for an identity this agent does not hold
      }
      const signature = key.sign(data, flags);
      return frame(Buffer.concat([writeByte(SSH_AGENT_SIGN_RESPONSE), writeString(signature)]));
    }
  } catch {
    return FAILURE; // malformed request or signing error — never leak, never crash
  }

  return FAILURE; // unsupported request (add/remove/lock/extension/…)
}

/**
 * Build a stateful byte-stream responder over one agent connection. Feed it
 * socket chunks; it accumulates until a full length-prefixed frame is present,
 * dispatches it, and returns the bytes to write back (empty until a frame
 * completes). A frame claiming an implausible length fails closed and resets.
 */
export function createAgentResponder(key: LoadedKey): (chunk: Buffer) => Buffer {
  let buffer = Buffer.alloc(0);
  return (chunk: Buffer): Buffer => {
    buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
    const out: Buffer[] = [];

    while (buffer.length >= 4) {
      const len = buffer.readUInt32BE(0);
      if (len === 0 || len > MAX_MESSAGE) {
        out.push(FAILURE);
        buffer = Buffer.alloc(0);
        break;
      }
      if (buffer.length < 4 + len) break; // wait for the rest of the frame
      const message = buffer.subarray(4, 4 + len);
      buffer = buffer.subarray(4 + len);
      out.push(handleMessage(message, key));
    }

    return out.length === 0 ? Buffer.alloc(0) : Buffer.concat(out);
  };
}
