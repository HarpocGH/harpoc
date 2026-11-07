import { createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { connect } from "node:net";
import type { Socket } from "node:net";

/**
 * A hand-built ssh-agent client modelled on core's
 * `packages/core/src/injection/__fixtures__/agent-client.ts`: a Socket-based
 * sibling with its own wire helpers and signer, not a copy — core exports only
 * `"."`, so its `key-loader` and `ssh-wire` are unreachable from this package.
 * It speaks the frames the agent-socket suite sends — `REQUEST_IDENTITIES`,
 * `session-bind@openssh.com`, `SIGN_REQUEST` — and has no `sendRaw` and no
 * `hostKeyBinding(fixtureName, …)`: the host key it binds with is an Ed25519
 * pair `generateHostKey()` makes on `node:crypto`, whose public line is the
 * known_hosts pin, and `verifyEd25519Signature` checks an agent's signature
 * against an `ssh-ed25519` public-key blob.
 */

const DEADLINE_MS = 10_000;

export const SSH_AGENT_FAILURE = 5;
export const SSH_AGENT_SUCCESS = 6;
export const SSH_AGENT_IDENTITIES_ANSWER = 12;
export const SSH_AGENT_SIGN_RESPONSE = 14;

export interface AgentReply {
  type: number;
  payload: Buffer;
}

export interface AgentIdentity {
  publicKeyBlob: Buffer;
  comment: string;
}

function sshString(data: Buffer | string): Buffer {
  const body = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  const len = Buffer.alloc(4);
  len.writeUInt32BE(body.length, 0);
  return Buffer.concat([len, body]);
}

function uint32(value: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value >>> 0, 0);
  return b;
}

function frame(type: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat([Buffer.from([type]), ...parts]);
  return Buffer.concat([uint32(body.length), body]);
}

/** Reads SSH `string`s off a buffer, refusing a length past its end. */
function reader(buf: Buffer): { u32(): number; str(): Buffer } {
  let offset = 0;
  const u32 = (): number => {
    if (offset + 4 > buf.length) throw new Error("agent-client: truncated uint32");
    const v = buf.readUInt32BE(offset);
    offset += 4;
    return v;
  };
  const str = (): Buffer => {
    const len = u32();
    if (offset + len > buf.length) throw new Error("agent-client: truncated string");
    const v = buf.subarray(offset, offset + len);
    offset += len;
    return v;
  };
  return { u32, str };
}

export function connectAgent(path: string): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const sock = connect(path);
    sock.once("error", reject);
    sock.once("connect", () => {
      sock.off("error", reject);
      sock.on("error", () => undefined);
      resolve(sock);
    });
  });
}

function exchange(sock: Socket, request: Buffer): Promise<AgentReply> {
  return new Promise((resolve, reject) => {
    if (sock.destroyed) {
      reject(new Error("the agent closed the connection"));
      return;
    }
    let buf = Buffer.alloc(0);
    const settle = (): void => {
      clearTimeout(timer);
      sock.off("data", onData);
      sock.off("error", onClosed);
      sock.off("close", onClosed);
    };
    const timer = setTimeout(() => {
      settle();
      reject(new Error(`agent-client: no reply within ${String(DEADLINE_MS)} ms`));
    }, DEADLINE_MS);
    const onData = (chunk: Buffer): void => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4 || buf.length < 4 + buf.readUInt32BE(0)) return;
      settle();
      resolve({ type: buf[4] as number, payload: buf.subarray(5, 4 + buf.readUInt32BE(0)) });
    };
    const onClosed = (): void => {
      settle();
      reject(new Error("the agent closed the connection"));
    };
    sock.on("data", onData);
    sock.once("error", onClosed);
    sock.once("close", onClosed);
    sock.write(request);
  });
}

export async function requestIdentities(
  sock: Socket,
): Promise<AgentReply & { identities: AgentIdentity[] }> {
  const reply = await exchange(sock, frame(11));
  const identities: AgentIdentity[] = [];
  if (reply.type === SSH_AGENT_IDENTITIES_ANSWER) {
    const r = reader(reply.payload);
    for (let n = r.u32(); n > 0; n--) {
      identities.push({ publicKeyBlob: r.str(), comment: r.str().toString("utf8") });
    }
  }
  return { ...reply, identities };
}

export interface SessionBind {
  hostKeyBlob: Buffer;
  sessionId: Buffer;
  signature: Buffer;
  isForwarding: boolean;
}

export function bindSession(sock: Socket, bind: SessionBind): Promise<AgentReply> {
  return exchange(
    sock,
    frame(
      27,
      sshString("session-bind@openssh.com"),
      sshString(bind.hostKeyBlob),
      sshString(bind.sessionId),
      sshString(bind.signature),
      Buffer.from([bind.isForwarding ? 1 : 0]),
    ),
  );
}

export function requestSignature(
  sock: Socket,
  request: { keyBlob: Buffer; data: Buffer; flags: number },
): Promise<AgentReply> {
  return exchange(
    sock,
    frame(13, sshString(request.keyBlob), sshString(request.data), uint32(request.flags)),
  );
}

/** RFC 4252 § 7: the data an SSH client asks its agent to sign for `publickey` authentication. */
export function buildUserauthRequest(request: {
  sessionId: Buffer;
  user: string;
  service: string;
  method: string;
  algorithm: string;
  publicKeyBlob: Buffer;
}): Buffer {
  return Buffer.concat([
    sshString(request.sessionId),
    Buffer.from([50]),
    sshString(request.user),
    sshString(request.service),
    sshString(request.method),
    Buffer.from([1]),
    sshString(request.algorithm),
    sshString(request.publicKeyBlob),
  ]);
}

/** A server host key: its `ssh-ed25519` blob, its known_hosts key field, and the bind it signs. */
export interface HostKey {
  hostKeyBlob: Buffer;
  knownHostsKey: string;
  binding(sessionId: Buffer): SessionBind;
}

export function generateHostKey(): HostKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  const hostKeyBlob = Buffer.concat([sshString("ssh-ed25519"), sshString(raw)]);
  return {
    hostKeyBlob,
    knownHostsKey: `ssh-ed25519 ${hostKeyBlob.toString("base64")}`,
    binding: (sessionId) => ({
      hostKeyBlob,
      sessionId,
      signature: Buffer.concat([
        sshString("ssh-ed25519"),
        sshString(sign(null, sessionId, privateKey)),
      ]),
      isForwarding: false,
    }),
  };
}

/** Whether `signResponse` (an agent's `SIGN_RESPONSE` body) is a valid Ed25519 signature of `data`. */
export function verifyEd25519Signature(
  publicKeyBlob: Buffer,
  data: Buffer,
  signResponse: Buffer,
): boolean {
  const key = reader(publicKeyBlob);
  if (key.str().toString("utf8") !== "ssh-ed25519") return false;
  const x = key.str().toString("base64url");
  const sig = reader(reader(signResponse).str());
  if (sig.str().toString("utf8") !== "ssh-ed25519") return false;
  return verify(
    null,
    data,
    createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" }),
    sig.str(),
  );
}
