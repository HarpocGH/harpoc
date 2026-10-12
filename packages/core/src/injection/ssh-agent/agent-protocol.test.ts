import { readFileSync } from "node:fs";
import { connect } from "node:net";
import type { Socket } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EphemeralSshAgent } from "./index.js";
import { writeByte, writeString, writeUint32 } from "./ssh-wire.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "__fixtures__", "ssh");

const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENTC_ADD_IDENTITY = 17;
const SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19;
const MAX_MESSAGE = 256 * 1024;

const frame = (body: Buffer): Buffer => Buffer.concat([writeUint32(body.length), body]);

interface AgentConnection {
  /** Writes raw bytes and resolves with the body of the next reply frame. */
  request(raw: Buffer): Promise<Buffer>;
  close(): void;
}

async function openAgent(authSock: string): Promise<AgentConnection> {
  const sock: Socket = connect(authSock);
  await new Promise<void>((resolve, reject) => {
    sock.once("connect", () => resolve());
    sock.once("error", reject);
  });
  let pending = Buffer.alloc(0);
  const waiting: { resolve: (body: Buffer) => void; reject: (err: Error) => void }[] = [];
  sock.on("data", (chunk: Buffer) => {
    pending = Buffer.concat([pending, chunk]);
    while (pending.length >= 4 && pending.length >= 4 + pending.readUInt32BE(0)) {
      const len = pending.readUInt32BE(0);
      const body = pending.subarray(4, 4 + len);
      pending = pending.subarray(4 + len);
      waiting.shift()?.resolve(body);
    }
  });
  sock.on("error", () => {
    /* surfaced through "close" below */
  });
  sock.on("close", () => {
    for (const w of waiting.splice(0)) w.reject(new Error("the agent closed the connection"));
  });
  return {
    request: (raw) =>
      new Promise<Buffer>((resolve, reject) => {
        waiting.push({ resolve, reject });
        sock.write(raw);
      }),
    close: () => sock.destroy(),
  };
}

/** The I11 contract: the request is answered SSH_AGENT_FAILURE and the connection still lists the identity. */
async function expectFailureThenServed(conn: AgentConnection, raw: Buffer): Promise<void> {
  expect([...(await conn.request(raw))]).toEqual([SSH_AGENT_FAILURE]);
  const list = await conn.request(frame(writeByte(SSH_AGENTC_REQUEST_IDENTITIES)));
  expect(list[0]).toBe(SSH_AGENT_IDENTITIES_ANSWER);
}

describe("agent protocol: every foreign or malformed request is answered SSH_AGENT_FAILURE over the live socket (I11)", () => {
  let agent: EphemeralSshAgent;

  beforeAll(async () => {
    agent = await EphemeralSshAgent.start(readFileSync(join(FIXTURES, "ed25519_openssh"), "utf8"));
  });

  afterAll(() => {
    agent.dispose();
  });

  const withConnection = async (run: (c: AgentConnection) => Promise<void>): Promise<void> => {
    const conn = await openAgent(agent.authSock);
    try {
      await run(conn);
    } finally {
      conn.close();
    }
  };

  it("SSH_AGENTC_ADD_IDENTITY (17)", async () => {
    await withConnection((c) =>
      expectFailureThenServed(
        c,
        frame(
          Buffer.concat([
            writeByte(SSH_AGENTC_ADD_IDENTITY),
            writeString("ssh-ed25519"),
            writeString(Buffer.alloc(32, 1)),
          ]),
        ),
      ),
    );
  });

  it("SSH_AGENTC_REMOVE_ALL_IDENTITIES (19)", async () => {
    await withConnection((c) =>
      expectFailureThenServed(c, frame(writeByte(SSH_AGENTC_REMOVE_ALL_IDENTITIES))),
    );
  });

  it("an unknown request type byte", async () => {
    await withConnection((c) => expectFailureThenServed(c, frame(writeByte(0xfe))));
  });

  it("an empty message (length 0)", async () => {
    await withConnection((c) => expectFailureThenServed(c, writeUint32(0)));
  });

  it("a truncated frame: a sign request whose key blob claims more bytes than it carries", async () => {
    await withConnection((c) =>
      expectFailureThenServed(
        c,
        frame(
          Buffer.concat([writeByte(SSH_AGENTC_SIGN_REQUEST), writeUint32(64), Buffer.from("abc")]),
        ),
      ),
    );
  });

  it("an implausible length (past the 256 KiB message cap)", async () => {
    await withConnection((c) => expectFailureThenServed(c, writeUint32(MAX_MESSAGE + 1)));
  });
});
