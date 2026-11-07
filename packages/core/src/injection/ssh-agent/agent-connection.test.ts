import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  SSH_AGENT_EXTENSION_FAILURE,
  SSH_AGENT_FAILURE,
  SSH_AGENT_IDENTITIES_ANSWER,
  SSH_AGENT_SUCCESS,
  bindSession,
  buildUserauthRequest,
  connectAgent,
  fixtureKey,
  fixturePublicBlob,
  hostKeyBinding,
  parseIdentities,
  parseSignature,
  requestIdentities,
  requestSignature,
  sessionBindBody,
} from "../__fixtures__/agent-client.js";
import type { AgentReply, SessionBindFields } from "../__fixtures__/agent-client.js";
import { CAPTURED_SESSION_BIND } from "../__fixtures__/ssh-agent-capture.js";
import { createAgentConnectionResponder } from "./agent-connection.js";
import type { AgentIdentity, AgentIdentityProvider, AgentSignRequest } from "./agent-connection.js";
import type { AgentBinding } from "./session-bind.js";
import { writeByte, writeString, writeUint32 } from "./ssh-wire.js";

const MAX_MESSAGE = 256 * 1024;
const SID = createHash("sha256").update("lane P connection session").digest();
const OTHER_SID = createHash("sha256").update("lane P another session").digest();
const USER = fixtureKey("ed25519_openssh");
const IDENTITY: AgentIdentity = { publicKeyBlob: USER.publicKeyBlob, comment: "secret://deploy" };
const SIGNATURE = Buffer.from("a provider's signature blob");

const frame = (body: Buffer): Buffer => Buffer.concat([writeUint32(body.length), body]);
const bind = (fixture: string, sessionId = SID, isForwarding = false): SessionBindFields => ({
  ...hostKeyBinding(fixture, sessionId),
  isForwarding,
});
const identitiesBody = writeByte(11);
const signBody = (data: Buffer, keyBlob = USER.publicKeyBlob, flags = 0): Buffer =>
  Buffer.concat([writeByte(13), writeString(keyBlob), writeString(data), writeUint32(flags)]);
const userauth = (sessionId = SID): Buffer =>
  buildUserauthRequest({
    sessionId,
    algorithm: "ssh-ed25519",
    publicKeyBlob: USER.publicKeyBlob,
  });

/** Split a reply byte stream into its frames. */
function replies(bytes: Buffer): AgentReply[] {
  const out: AgentReply[] = [];
  let rest = bytes;
  while (rest.length >= 4) {
    const len = rest.readUInt32BE(0);
    out.push({ type: rest[4] ?? -1, payload: rest.subarray(5, 4 + len) });
    rest = rest.subarray(4 + len);
  }
  return out;
}

interface Recording {
  provider: AgentIdentityProvider;
  identityCalls: (AgentBinding | null)[];
  signCalls: AgentSignRequest[];
}

function recordingProvider(
  overrides: Partial<Omit<AgentIdentityProvider, "sessionBind">> & { sessionBind?: boolean } = {},
): Recording {
  const identityCalls: (AgentBinding | null)[] = [];
  const signCalls: AgentSignRequest[] = [];
  return {
    identityCalls,
    signCalls,
    provider: {
      sessionBind: overrides.sessionBind ?? true,
      identities: async (binding) => {
        identityCalls.push(binding);
        return overrides.identities ? overrides.identities(binding) : [IDENTITY];
      },
      sign: async (request) => {
        signCalls.push(request);
        return overrides.sign ? overrides.sign(request) : SIGNATURE;
      },
    },
  };
}

/** One in-memory connection: `send` frames one request and resolves with its one reply. */
function connection(provider: AgentIdentityProvider) {
  const respond = createAgentConnectionResponder(provider);
  return {
    respond,
    raw: async (bytes: Buffer): Promise<AgentReply[]> => replies(await respond(bytes)),
    async send(body: Buffer): Promise<AgentReply> {
      const [reply, ...more] = replies(await respond(frame(body)));
      expect(more).toEqual([]);
      return reply as AgentReply;
    },
  };
}

describe("createAgentConnectionResponder — identities and the session-bind@openssh.com extension", () => {
  it("lists the provider's identities on an unbound connection, the provider asked with no binding", async () => {
    const rec = recordingProvider();
    const reply = await connection(rec.provider).send(identitiesBody);
    expect(parseIdentities(reply)).toEqual([IDENTITY]);
    expect(rec.identityCalls).toEqual([null]);
  });

  it("answers a verified authentication bind SSH_AGENT_SUCCESS and asks for the bound identities with the binding", async () => {
    const rec = recordingProvider();
    const c = connection(rec.provider);
    const fields = bind("ecdsa256_openssh");
    expect((await c.send(sessionBindBody(fields))).type).toBe(SSH_AGENT_SUCCESS);
    await c.send(identitiesBody);
    expect(rec.identityCalls).toEqual([
      { hostKeyBlob: fields.hostKeyBlob, sessionId: fields.sessionId },
    ]);
  });

  it("accepts the bind Win32-OpenSSH 9.5p2 sent on this host", async () => {
    const rec = recordingProvider();
    const c = connection(rec.provider);
    expect((await c.send(CAPTURED_SESSION_BIND)).type).toBe(SSH_AGENT_SUCCESS);
    await c.send(identitiesBody);
    expect(rec.identityCalls[0]?.hostKeyBlob).toEqual(fixturePublicBlob("ecdsa256_openssh"));
  });

  it("answers every bind SSH_AGENT_FAILURE for a provider without sessionBind, the connection unbound", async () => {
    const rec = recordingProvider({ sessionBind: false });
    const c = connection(rec.provider);
    expect((await c.send(sessionBindBody(bind("ecdsa256_openssh")))).type).toBe(SSH_AGENT_FAILURE);
    await c.send(identitiesBody);
    expect(rec.identityCalls).toEqual([null]);
  });

  it("refuses a second authentication bind SSH_AGENT_EXTENSION_FAILURE and keeps the first binding", async () => {
    const rec = recordingProvider();
    const c = connection(rec.provider);
    await c.send(sessionBindBody(bind("ecdsa256_openssh")));
    const second = await c.send(sessionBindBody(bind("ed25519_openssh", OTHER_SID)));
    expect(second.type).toBe(SSH_AGENT_EXTENSION_FAILURE);
    await c.send(identitiesBody);
    expect(rec.identityCalls[0]?.sessionId).toEqual(SID);
  });

  it("refuses a duplicate bind (the same sid and key): OpenSSH refuses every bind on a connection bound for authentication", async () => {
    const c = connection(recordingProvider().provider);
    const fields = bind("ecdsa256_openssh");
    await c.send(sessionBindBody(fields));
    expect((await c.send(sessionBindBody(fields))).type).toBe(SSH_AGENT_EXTENSION_FAILURE);
  });

  it("refuses the bound session identifier under another host key", async () => {
    const c = connection(recordingProvider().provider);
    await c.send(sessionBindBody(bind("ecdsa256_openssh")));
    expect((await c.send(sessionBindBody(bind("ed25519_openssh")))).type).toBe(
      SSH_AGENT_EXTENSION_FAILURE,
    );
  });

  it("refuses a forwarding bind (R-P4): the connection then lists no identity without asking the provider", async () => {
    const rec = recordingProvider();
    const c = connection(rec.provider);
    const reply = await c.send(sessionBindBody(bind("ecdsa256_openssh", SID, true)));
    expect(reply.type).toBe(SSH_AGENT_EXTENSION_FAILURE);
    expect(parseIdentities(await c.send(identitiesBody))).toEqual([]);
    expect(rec.identityCalls).toEqual([]);
  });

  it("refuses the next hop's authentication bind relayed through a refused forwarding channel; its sign request reaches the provider unbound, forwarding", async () => {
    const rec = recordingProvider({ sign: () => Promise.reject(new Error("refused")) });
    const c = connection(rec.provider);
    await c.send(sessionBindBody(bind("ecdsa256_openssh", SID, true)));
    const hop = await c.send(sessionBindBody(bind("ed25519_openssh", OTHER_SID)));
    expect(hop.type).toBe(SSH_AGENT_EXTENSION_FAILURE);
    expect((await c.send(signBody(userauth(OTHER_SID)))).type).toBe(SSH_AGENT_FAILURE);
    expect(rec.signCalls[0]).toMatchObject({ binding: null, forwarding: true });
  });

  it.each([
    [
      "a signature over another session identifier",
      { ...bind("ecdsa256_openssh"), sessionId: OTHER_SID },
    ],
    [
      "a signature by another key",
      { ...bind("ecdsa256_openssh"), hostKeyBlob: fixturePublicBlob("ecdsa256_pem") },
    ],
  ])(
    "refuses a bind with %s and leaves the connection unbound for good",
    async (_label, fields) => {
      const rec = recordingProvider();
      const c = connection(rec.provider);
      expect((await c.send(sessionBindBody(fields))).type).toBe(SSH_AGENT_EXTENSION_FAILURE);
      expect((await c.send(sessionBindBody(bind("ecdsa256_openssh")))).type).toBe(
        SSH_AGENT_EXTENSION_FAILURE,
      );
      await c.send(signBody(userauth()));
      expect(rec.signCalls[0]).toMatchObject({ binding: null, forwarding: false });
    },
  );

  it("refuses a truncated bind SSH_AGENT_EXTENSION_FAILURE", async () => {
    const body = sessionBindBody(bind("ecdsa256_openssh"));
    const c = connection(recordingProvider().provider);
    expect((await c.send(body.subarray(0, body.length - 1))).type).toBe(
      SSH_AGENT_EXTENSION_FAILURE,
    );
  });

  it.each(["query", "restrict-destination-v00@openssh.com", "session-bind@openssh.co"])(
    "answers the extension %s SSH_AGENT_FAILURE (not supported)",
    async (name) => {
      const c = connection(recordingProvider().provider);
      expect((await c.send(Buffer.concat([writeByte(27), writeString(name)]))).type).toBe(
        SSH_AGENT_FAILURE,
      );
    },
  );

  it("answers an extension request whose name is truncated SSH_AGENT_FAILURE", async () => {
    const c = connection(recordingProvider().provider);
    const reply = await c.send(Buffer.concat([writeByte(27), writeUint32(40), Buffer.from("se")]));
    expect(reply.type).toBe(SSH_AGENT_FAILURE);
  });

  it("answers a provider's identities rejection SSH_AGENT_FAILURE", async () => {
    const c = connection(
      recordingProvider({ identities: () => Promise.reject(new Error("sealed")) }).provider,
    );
    expect((await c.send(identitiesBody)).type).toBe(SSH_AGENT_FAILURE);
  });
});

describe("createAgentConnectionResponder — sign requests reach the provider with the connection's facts", () => {
  it("an unbound connection's sign request: binding null and the raw data; the provider's refusal answers SSH_AGENT_FAILURE", async () => {
    const rec = recordingProvider({ sign: () => Promise.reject(new Error("SSH_AGENT_UNBOUND")) });
    const c = connection(rec.provider);
    expect((await c.send(signBody(userauth()))).type).toBe(SSH_AGENT_FAILURE);
    expect(rec.signCalls[0]).toMatchObject({ binding: null, forwarding: false, flags: 0 });
    expect(rec.signCalls[0]?.data).toEqual(userauth());
  });

  it("a bound connection's sign request: the provider is called with the binding and the raw data, its signature framed in SSH_AGENT_SIGN_RESPONSE", async () => {
    const rec = recordingProvider();
    const c = connection(rec.provider);
    const fields = bind("ecdsa256_openssh");
    await c.send(sessionBindBody(fields));
    const reply = await c.send(signBody(userauth(), USER.publicKeyBlob, 2));
    expect(parseSignature(reply)).toEqual(SIGNATURE);
    expect(rec.signCalls[0]).toMatchObject({
      keyBlob: USER.publicKeyBlob,
      flags: 2,
      binding: { hostKeyBlob: fields.hostKeyBlob, sessionId: SID },
      forwarding: false,
      data: userauth(),
    });
    expect(Object.keys(rec.signCalls[0] ?? {}).sort()).toEqual([
      "binding",
      "data",
      "flags",
      "forwarding",
      "keyBlob",
    ]);
  });

  it("a bound sign request carrying another session's userauth request reaches the provider byte for byte, with the binding", async () => {
    const rec = recordingProvider();
    const c = connection(rec.provider);
    await c.send(sessionBindBody(bind("ecdsa256_openssh")));
    await c.send(signBody(userauth(OTHER_SID)));
    expect(rec.signCalls[0]?.data).toEqual(userauth(OTHER_SID));
    expect(rec.signCalls[0]?.binding?.sessionId).toEqual(SID);
  });

  it("data that is not a userauth request (an SSHSIG preamble) still reaches the provider, unjudged", async () => {
    const rec = recordingProvider();
    const c = connection(rec.provider);
    await c.send(sessionBindBody(bind("ecdsa256_openssh")));
    await c.send(signBody(Buffer.from("SSHSIG not a userauth request")));
    expect(rec.signCalls[0]?.data).toEqual(Buffer.from("SSHSIG not a userauth request"));
  });

  it("a truncated sign request is SSH_AGENT_FAILURE without a provider call", async () => {
    const rec = recordingProvider();
    const reply = await connection(rec.provider).send(
      Buffer.concat([writeByte(13), writeUint32(64), Buffer.from("abc")]),
    );
    expect(reply.type).toBe(SSH_AGENT_FAILURE);
    expect(rec.signCalls).toEqual([]);
  });
});

describe("createAgentConnectionResponder — framing and order", () => {
  it.each([
    ["SSH_AGENTC_ADD_IDENTITY (17)", writeByte(17)],
    ["SSH_AGENTC_REMOVE_ALL_IDENTITIES (19)", writeByte(19)],
    ["SSH_AGENTC_LOCK (22)", writeByte(22)],
    ["an unknown type byte", writeByte(0xfe)],
  ])("answers %s SSH_AGENT_FAILURE and still serves the connection", async (_label, body) => {
    const c = connection(recordingProvider().provider);
    expect((await c.send(body)).type).toBe(SSH_AGENT_FAILURE);
    expect((await c.send(identitiesBody)).type).toBe(SSH_AGENT_IDENTITIES_ANSWER);
  });

  it.each([
    ["an empty message", writeUint32(0)],
    ["a length past the 256 KiB cap", writeUint32(MAX_MESSAGE + 1)],
  ])("fails %s closed, resets, and serves the next request", async (_label, bytes) => {
    const c = connection(recordingProvider().provider);
    expect((await c.raw(bytes)).map((r) => r.type)).toEqual([SSH_AGENT_FAILURE]);
    expect((await c.send(identitiesBody)).type).toBe(SSH_AGENT_IDENTITIES_ANSWER);
  });

  it("answers a frame split across chunks once it is complete", async () => {
    const c = connection(recordingProvider().provider);
    const bytes = frame(identitiesBody);
    expect(await c.raw(bytes.subarray(0, 3))).toEqual([]);
    expect((await c.raw(bytes.subarray(3))).map((r) => r.type)).toEqual([
      SSH_AGENT_IDENTITIES_ANSWER,
    ]);
  });

  it("answers two requests of one chunk in order, in one reply", async () => {
    const c = connection(recordingProvider().provider);
    const chunk = Buffer.concat([frame(identitiesBody), frame(writeByte(0xfe))]);
    expect((await c.raw(chunk)).map((r) => r.type)).toEqual([
      SSH_AGENT_IDENTITIES_ANSWER,
      SSH_AGENT_FAILURE,
    ]);
  });

  it("settles a later chunk only after the earlier chunk's request, which the provider still works on", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const c = connection(
      recordingProvider({ identities: () => gate.then(() => [IDENTITY]) }).provider,
    );
    const settled: string[] = [];
    const first = c.respond(frame(identitiesBody)).then((r) => settled.push(`first ${r[4]}`));
    const second = c
      .respond(frame(sessionBindBody(bind("ecdsa256_openssh"))))
      .then((r) => settled.push(`second ${r[4]}`));
    await Promise.resolve();
    expect(settled).toEqual([]);
    release();
    await Promise.all([first, second]);
    expect(settled).toEqual([
      `first ${SSH_AGENT_IDENTITIES_ANSWER}`,
      `second ${SSH_AGENT_SUCCESS}`,
    ]);
  });
});

describe("createAgentConnectionResponder over a live connection, through the hand-built client", () => {
  let server: Server | undefined;
  let dir: string | undefined;
  const sockets = new Set<Socket>();

  afterEach(async () => {
    for (const s of sockets) s.destroy();
    sockets.clear();
    await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
    server = undefined;
    if (dir) rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    dir = undefined;
  });

  async function listen(provider: AgentIdentityProvider): Promise<string> {
    let path: string;
    if (process.platform === "win32") {
      path = `\\\\.\\pipe\\harpoc-agent-connection-${randomBytes(8).toString("hex")}`;
    } else {
      dir = mkdtempSync(join(tmpdir(), "harpoc-agent-connection-"));
      path = join(dir, "agent.sock");
    }
    const srv = createServer((stream) => {
      sockets.add(stream);
      stream.on("close", () => sockets.delete(stream));
      stream.on("error", () => {
        /* the client's reset; nothing to answer */
      });
      const respond = createAgentConnectionResponder(provider);
      stream.on("data", (chunk: Buffer) => {
        stream.pause();
        void respond(chunk).then((reply) => {
          if (reply.length > 0) stream.write(reply);
          stream.resume();
        });
      });
    });
    server = srv;
    await new Promise<void>((resolve) => srv.listen(path, resolve));
    return path;
  }

  it("binds, lists the bound identities and returns the provider's signature for the bound userauth request", async () => {
    const rec = recordingProvider({ sign: async (req) => USER.sign(req.data, req.flags) });
    const client = await connectAgent(await listen(rec.provider));
    try {
      const fields = bind("rsa_openssh");
      expect((await bindSession(client, fields)).type).toBe(SSH_AGENT_SUCCESS);
      expect(parseIdentities(await requestIdentities(client))).toEqual([IDENTITY]);
      const data = userauth();
      const signature = parseSignature(
        await requestSignature(client, { keyBlob: USER.publicKeyBlob, data, flags: 0 }),
      );
      expect(signature).toEqual(USER.sign(data, 0));
      expect(rec.identityCalls).toEqual([{ hostKeyBlob: fields.hostKeyBlob, sessionId: SID }]);
      expect(rec.signCalls[0]?.binding?.hostKeyBlob).toEqual(fields.hostKeyBlob);
    } finally {
      client.close();
    }
  });
});
