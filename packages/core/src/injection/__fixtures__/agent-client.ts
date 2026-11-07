import { readFileSync } from "node:fs";
import { connect } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPrivateKey } from "../ssh-agent/key-loader.js";
import type { LoadedKey } from "../ssh-agent/key-loader.js";
import { SshReader, writeByte, writeString, writeUint32 } from "../ssh-agent/ssh-wire.js";

/**
 * A hand-built ssh-agent client for the agent-socket suites: it speaks the agent protocol
 * (RFC 9987, OpenSSH `PROTOCOL.agent`) frame by frame, so a suite can send what no real
 * `ssh` sends — a sign request on an unbound connection, a forged or forwarding bind, a
 * second bind, raw bytes. Every reply is awaited under a deadline that destroys the
 * connection and rejects. The host-key helpers sign a session identifier with a fixture
 * private key under `__fixtures__/ssh/`, standing in for the server's KEX signature.
 */
export const SSH_AGENT_FAILURE = 5;
export const SSH_AGENT_SUCCESS = 6;
export const SSH_AGENTC_REQUEST_IDENTITIES = 11;
export const SSH_AGENT_IDENTITIES_ANSWER = 12;
export const SSH_AGENTC_SIGN_REQUEST = 13;
export const SSH_AGENT_SIGN_RESPONSE = 14;
export const SSH_AGENTC_EXTENSION = 27;
export const SSH_AGENT_EXTENSION_FAILURE = 28;

/** The deadline every awaited reply carries unless the caller passes another. */
export const AGENT_REPLY_DEADLINE_MS = 5_000;

export interface AgentReply {
  type: number;
  payload: Buffer;
}

export interface AgentClient {
  /** Frame `body` (type byte + payload) and resolve with the next reply. */
  request(body: Buffer): Promise<AgentReply>;
  /** Write `bytes` exactly as given and resolve with the next reply. */
  sendRaw(bytes: Buffer): Promise<AgentReply>;
  /** Resolves when the agent closes the connection (or it is destroyed). */
  closed: Promise<void>;
  /** Half-close: no further writes, replies still read. */
  end(): void;
  close(): void;
}

export interface SessionBindFields {
  hostKeyBlob: Buffer;
  sessionId: Buffer;
  signature: Buffer;
  isForwarding: boolean;
}

export interface SignRequestFields {
  keyBlob: Buffer;
  data: Buffer;
  flags: number;
}

export interface UserauthFields {
  sessionId: Buffer;
  user?: string;
  service?: string;
  method?: string;
  algorithm: string;
  publicKeyBlob: Buffer;
  hostKeyBlob?: Buffer;
  /** The boolean after the method name; RFC 4252 § 7 requires TRUE (1). */
  signatureFollows?: number;
}

export interface AgentIdentityEntry {
  publicKeyBlob: Buffer;
  comment: string;
}

const SSH_FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "ssh");

/** A key fixture's file text (`ed25519_openssh`, `rsa_openssh.pub`, …). */
export function readSshFixture(name: string): string {
  return readFileSync(join(SSH_FIXTURES, name), "utf8");
}

/** The fixture private key, loaded the way the vault loads a stored key. */
export function fixtureKey(name: string): LoadedKey {
  return loadPrivateKey(readSshFixture(name));
}

/** The SSH public-key blob of a fixture's `.pub` line. */
export function fixturePublicBlob(name: string): Buffer {
  return Buffer.from(readSshFixture(`${name}.pub`).trim().split(/\s+/)[1] as string, "base64");
}

/** The fixture's `.pub` key spelled as a known_hosts line for `hosts` (`a,[b]:2222`). */
export function fixtureKnownHostsLine(name: string, hosts: string): string {
  const [keyType, base64] = readSshFixture(`${name}.pub`).trim().split(/\s+/);
  return `${hosts} ${keyType as string} ${base64 as string}`;
}

/**
 * What a server's KEX reply gives the client for `session-bind`: the fixture's public blob
 * as the host key and its signature over `sessionId` (RSA as `rsa-sha2-512` unless `flags`
 * says otherwise — `SSH_AGENT_RSA_SHA2_256 = 2`).
 */
export function hostKeyBinding(
  fixtureName: string,
  sessionId: Buffer,
  flags = 4,
): { hostKeyBlob: Buffer; sessionId: Buffer; signature: Buffer } {
  const key = fixtureKey(fixtureName);
  return { hostKeyBlob: key.publicKeyBlob, sessionId, signature: key.sign(sessionId, flags) };
}

/** The `SSH_AGENTC_EXTENSION` body of a `session-bind@openssh.com` request. */
export function sessionBindBody(fields: SessionBindFields): Buffer {
  return Buffer.concat([
    writeByte(SSH_AGENTC_EXTENSION),
    writeString("session-bind@openssh.com"),
    writeString(fields.hostKeyBlob),
    writeString(fields.sessionId),
    writeString(fields.signature),
    writeByte(fields.isForwarding ? 1 : 0),
  ]);
}

/** The data an SSH client signs for public-key userauth (RFC 4252 § 7), OpenSSH's layout. */
export function buildUserauthRequest(fields: UserauthFields): Buffer {
  const method =
    fields.method ?? (fields.hostKeyBlob ? "publickey-hostbound-v00@openssh.com" : "publickey");
  return Buffer.concat([
    writeString(fields.sessionId),
    writeByte(50),
    writeString(fields.user ?? "git"),
    writeString(fields.service ?? "ssh-connection"),
    writeString(method),
    writeByte(fields.signatureFollows ?? 1),
    writeString(fields.algorithm),
    writeString(fields.publicKeyBlob),
    ...(fields.hostKeyBlob ? [writeString(fields.hostKeyBlob)] : []),
  ]);
}

export function connectAgent(
  path: string,
  deadlineMs = AGENT_REPLY_DEADLINE_MS,
): Promise<AgentClient> {
  return new Promise((resolve, reject) => {
    const sock = connect(path);
    const waiting: { resolve: (r: AgentReply) => void; reject: (e: Error) => void }[] = [];
    let pending = Buffer.alloc(0);
    const failAll = (err: Error): void => {
      for (const w of waiting.splice(0)) w.reject(err);
    };
    let markClosed: () => void = () => undefined;
    const closed = new Promise<void>((settle) => {
      markClosed = settle;
    });
    sock.once("error", reject);
    sock.on("close", () => {
      failAll(new Error("the agent closed the connection"));
      markClosed();
    });
    sock.on("data", (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      while (pending.length >= 4 && pending.length >= 4 + pending.readUInt32BE(0)) {
        const len = pending.readUInt32BE(0);
        const body = pending.subarray(4, 4 + len);
        pending = pending.subarray(4 + len);
        waiting.shift()?.resolve({ type: body[0] ?? -1, payload: body.subarray(1) });
      }
    });
    sock.once("connect", () => {
      sock.off("error", reject);
      sock.on("error", () => {
        /* surfaced through "close" */
      });
      const sendRaw = (bytes: Buffer): Promise<AgentReply> =>
        new Promise<AgentReply>((res, rej) => {
          const timer = setTimeout(() => {
            sock.destroy();
            rej(new Error(`no agent reply within ${deadlineMs} ms`));
          }, deadlineMs);
          waiting.push({
            resolve: (r) => {
              clearTimeout(timer);
              res(r);
            },
            reject: (e) => {
              clearTimeout(timer);
              rej(e);
            },
          });
          sock.write(bytes);
        });
      resolve({
        request: (body) => sendRaw(Buffer.concat([writeUint32(body.length), body])),
        sendRaw,
        closed,
        end: () => sock.end(),
        close: () => sock.destroy(),
      });
    });
  });
}

export function requestIdentities(client: AgentClient): Promise<AgentReply> {
  return client.request(writeByte(SSH_AGENTC_REQUEST_IDENTITIES));
}

export function bindSession(client: AgentClient, fields: SessionBindFields): Promise<AgentReply> {
  return client.request(sessionBindBody(fields));
}

export function requestSignature(
  client: AgentClient,
  fields: SignRequestFields,
): Promise<AgentReply> {
  return client.request(
    Buffer.concat([
      writeByte(SSH_AGENTC_SIGN_REQUEST),
      writeString(fields.keyBlob),
      writeString(fields.data),
      writeUint32(fields.flags),
    ]),
  );
}

export function sendRaw(client: AgentClient, bytes: Buffer): Promise<AgentReply> {
  return client.sendRaw(bytes);
}

/** The identities of an `SSH_AGENT_IDENTITIES_ANSWER` reply; throws on any other reply. */
export function parseIdentities(reply: AgentReply): AgentIdentityEntry[] {
  if (reply.type !== SSH_AGENT_IDENTITIES_ANSWER) {
    throw new Error(`expected SSH_AGENT_IDENTITIES_ANSWER, got ${reply.type}`);
  }
  const r = new SshReader(reply.payload);
  const n = r.readUint32();
  const out: AgentIdentityEntry[] = [];
  for (let i = 0; i < n; i++) out.push({ publicKeyBlob: r.readString(), comment: r.readCString() });
  return out;
}

/** The signature blob of an `SSH_AGENT_SIGN_RESPONSE` reply; throws on any other reply. */
export function parseSignature(reply: AgentReply): Buffer {
  if (reply.type !== SSH_AGENT_SIGN_RESPONSE) {
    throw new Error(`expected SSH_AGENT_SIGN_RESPONSE, got ${reply.type}`);
  }
  return new SshReader(reply.payload).readString();
}
