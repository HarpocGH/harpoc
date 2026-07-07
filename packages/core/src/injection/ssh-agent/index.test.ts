import { connect } from "node:net";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ErrorCode } from "@harpoc/shared";
import { describe, expect, it } from "vitest";
import { EphemeralSshAgent } from "./index.js";
import { SshReader, writeByte, writeString, writeUint32 } from "./ssh-wire.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "__fixtures__", "ssh");
const readFixture = (name: string): string => readFileSync(join(FIXTURES, name), "utf8");

// --- a minimal agent-protocol client, so the test needs no ssh2 -------------

const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENTC_SIGN_REQUEST = 13;

function agentRequest(authSock: string, body: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const sock = connect(authSock);
    const chunks: Buffer[] = [];
    let expected = -1;
    sock.on("connect", () => sock.write(Buffer.concat([writeUint32(body.length), body])));
    sock.on("data", (d: Buffer) => {
      chunks.push(d);
      const all = Buffer.concat(chunks);
      if (expected < 0 && all.length >= 4) expected = all.readUInt32BE(0);
      if (expected >= 0 && all.length >= 4 + expected) {
        sock.end();
        resolve(all.subarray(4, 4 + expected));
      }
    });
    sock.on("error", reject);
  });
}

async function listIdentities(authSock: string): Promise<Buffer> {
  const reply = await agentRequest(authSock, writeByte(SSH_AGENTC_REQUEST_IDENTITIES));
  const r = new SshReader(reply);
  expect(r.readByte()).toBe(12); // SSH_AGENT_IDENTITIES_ANSWER
  expect(r.readUint32()).toBe(1);
  return r.readString(); // key blob
}

async function signWith(authSock: string, keyBlob: Buffer, data: Buffer, flags: number): Promise<Buffer> {
  const body = Buffer.concat([
    writeByte(SSH_AGENTC_SIGN_REQUEST),
    writeString(keyBlob),
    writeString(data),
    writeUint32(flags),
  ]);
  const reply = await agentRequest(authSock, body);
  const r = new SshReader(reply);
  expect(r.readByte()).toBe(14); // SSH_AGENT_SIGN_RESPONSE
  return r.readString(); // signature blob
}

function ed25519PubFromBlob(blob: Buffer) {
  const r = new SshReader(blob);
  r.readCString();
  const a = r.readString();
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: a.toString("base64url") }, format: "jwk" });
}

const CHALLENGE = Buffer.from("agent-socket challenge");

describe("EphemeralSshAgent", () => {
  it("serves the identity and produces a verifiable signature over the socket", async () => {
    const agent = await EphemeralSshAgent.start(readFixture("ed25519_openssh"));
    try {
      const blob = await listIdentities(agent.authSock);
      const sig = await signWith(agent.authSock, blob, CHALLENGE, 0);

      const inner = (() => {
        const r = new SshReader(sig);
        expect(r.readCString()).toBe("ssh-ed25519");
        return r.readString();
      })();
      expect(cryptoVerify(null, CHALLENGE, ed25519PubFromBlob(blob), inner)).toBe(true);
    } finally {
      agent.dispose();
    }
  });

  it("returns SSH_AGENT_FAILURE for a sign request naming an unknown key", async () => {
    const agent = await EphemeralSshAgent.start(readFixture("ed25519_openssh"));
    try {
      const reply = await agentRequest(
        agent.authSock,
        Buffer.concat([
          writeByte(SSH_AGENTC_SIGN_REQUEST),
          writeString(Buffer.from("bogus-key-blob")),
          writeString(CHALLENGE),
          writeUint32(0),
        ]),
      );
      expect(reply[0]).toBe(5); // SSH_AGENT_FAILURE
    } finally {
      agent.dispose();
    }
  });

  it("serves an RSA identity too", async () => {
    const agent = await EphemeralSshAgent.start(readFixture("rsa_openssh"));
    try {
      const blob = await listIdentities(agent.authSock);
      const sig = await signWith(agent.authSock, blob, CHALLENGE, 2);
      expect(new SshReader(sig).readCString()).toBe("rsa-sha2-256");
    } finally {
      agent.dispose();
    }
  });

  it("rejects an invalid private key", async () => {
    await expect(EphemeralSshAgent.start("not a private key")).rejects.toMatchObject({
      code: ErrorCode.SSH_AGENT_FAILED,
    });
  });

  it("rejects an encrypted private key", async () => {
    await expect(EphemeralSshAgent.start(readFixture("ed25519_enc"))).rejects.toMatchObject({
      code: ErrorCode.SSH_AGENT_FAILED,
    });
  });

  it("removes the socket directory on dispose (POSIX)", async () => {
    const agent = await EphemeralSshAgent.start(readFixture("ed25519_openssh"));
    const sock = agent.authSock;
    agent.dispose();
    if (process.platform !== "win32") {
      expect(existsSync(sock)).toBe(false);
    }
  });
});
