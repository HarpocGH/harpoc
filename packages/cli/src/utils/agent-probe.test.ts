import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EphemeralSshAgent } from "@harpoc/core";
import { probeAgentSocket, sshKeyFingerprint } from "./agent-probe.js";

// The public halves of core's fixture keys (core/src/injection/__fixtures__/ssh/*.pub) and what
// `ssh-keygen -lf` (C:\Windows\System32\OpenSSH, OpenSSH_for_Windows_9.5p2) printed for them.
const ED25519 = {
  keyType: "ssh-ed25519",
  blob: "AAAAC3NzaC1lZDI1NTE5AAAAIOCrwIj6+onGT6amn11WaE7DBDJU/Zcim3GZknGAAwyw",
  fingerprint: "SHA256:vKqyAVTrbMF3MHOKboGKqIW51KxwLjApBtP/N48OLeo",
};
const ECDSA256 = {
  keyType: "ecdsa-sha2-nistp256",
  blob: "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ/QFP3G4F4xZlD/T+Aj459FydBO+OMsgSEEE9ej/ZvkUP4KagQHcySSRBY2bJFIRP4uL6ijgcG2OIZHow14hxc=",
  fingerprint: "SHA256:7dcaydo930fNrjtVUaiof/9VYG5XTSIZsm5+Q+F96ag",
};

const TIMEOUT_MS = 2_000;

function u32(value: number): Buffer {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value);
  return buffer;
}

function sshString(data: Buffer | string): Buffer {
  const body = typeof data === "string" ? Buffer.from(data) : data;
  return Buffer.concat([u32(body.length), body]);
}

function frame(body: Buffer): Buffer {
  return Buffer.concat([u32(body.length), body]);
}

function identitiesAnswer(identities: { blob: string; comment: string }[]): Buffer {
  return frame(
    Buffer.concat([
      Buffer.from([12]),
      u32(identities.length),
      ...identities.flatMap(({ blob, comment }) => [
        sshString(Buffer.from(blob, "base64")),
        sshString(comment),
      ]),
    ]),
  );
}

const servers: Server[] = [];
const dirs: string[] = [];

afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(
    servers
      .splice(0)
      .map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
  for (const dir of dirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

/** A pipe on win32 (the ephemeral agent's transport), a socket in a private temp directory elsewhere. */
function freshPath(): string {
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\harpoc-probe-${randomBytes(8).toString("hex")}`;
  }
  const dir = mkdtempSync(join(tmpdir(), "harpoc-probe-"));
  dirs.push(dir);
  return join(dir, "agent.sock");
}

/** An agent stand-in: `answer` gets every request chunk and returns the bytes to send, or null for silence. */
async function fakeAgent(
  answer: (request: Buffer) => Buffer | null,
): Promise<{ path: string; requests: Buffer[]; connected: Promise<Socket> }> {
  const path = freshPath();
  const requests: Buffer[] = [];
  let onConnection: (socket: Socket) => void = () => undefined;
  const connected = new Promise<Socket>((resolve) => {
    onConnection = resolve;
  });
  const server = createServer((socket) => {
    socket.on("error", () => undefined);
    onConnection(socket);
    socket.on("data", (chunk: Buffer) => {
      requests.push(chunk);
      const reply = answer(chunk);
      if (reply !== null) socket.write(reply);
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(path, () => resolve()));
  return { path, requests, connected };
}

describe("probeAgentSocket — one identities request, the answer read as ssh-add reads it", () => {
  it("lists every identity with ssh-keygen's SHA256 fingerprint and the ssh-add -L line", async () => {
    const agent = await fakeAgent(() =>
      identitiesAnswer([
        { blob: ED25519.blob, comment: "secret://deploy-key" },
        { blob: ECDSA256.blob, comment: "secret://ci/build-key" },
      ]),
    );

    await expect(probeAgentSocket(agent.path, TIMEOUT_MS)).resolves.toEqual({
      listening: true,
      identities: [
        {
          keyType: "ssh-ed25519",
          fingerprint: ED25519.fingerprint,
          comment: "secret://deploy-key",
          publicKey: `ssh-ed25519 ${ED25519.blob} secret://deploy-key`,
        },
        {
          keyType: "ecdsa-sha2-nistp256",
          fingerprint: ECDSA256.fingerprint,
          comment: "secret://ci/build-key",
          publicKey: `ecdsa-sha2-nistp256 ${ECDSA256.blob} secret://ci/build-key`,
        },
      ],
    });
  });

  it("sends exactly one SSH_AGENTC_REQUEST_IDENTITIES frame and nothing else", async () => {
    const agent = await fakeAgent(() => identitiesAnswer([]));

    await expect(probeAgentSocket(agent.path, TIMEOUT_MS)).resolves.toEqual({
      listening: true,
      identities: [],
    });
    expect(Buffer.concat(agent.requests)).toEqual(Buffer.from([0, 0, 0, 1, 11]));
  });

  it("reads core's ephemeral agent's one identity over its real socket", async () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const ephemeral = await EphemeralSshAgent.start(pem);
    try {
      const blob = Buffer.from(ephemeral.publicKeyOpenssh.split(" ")[1] as string, "base64");
      const digest = createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
      await expect(probeAgentSocket(ephemeral.authSock, TIMEOUT_MS)).resolves.toEqual({
        listening: true,
        identities: [
          {
            keyType: "ssh-ed25519",
            fingerprint: `SHA256:${digest}`,
            comment: "harpoc-ephemeral",
            publicKey: ephemeral.publicKeyOpenssh,
          },
        ],
      });
    } finally {
      ephemeral.dispose();
    }
  });

  it("an agent that answers SSH_AGENT_FAILURE is listening and lists nothing (a sealed vault answers so)", async () => {
    const agent = await fakeAgent(() => frame(Buffer.from([5])));

    await expect(probeAgentSocket(agent.path, TIMEOUT_MS)).resolves.toEqual({
      listening: true,
      identities: null,
    });
  });

  it("nothing at the path: not listening, no socket", async () => {
    await expect(probeAgentSocket(freshPath(), TIMEOUT_MS)).resolves.toEqual({
      listening: false,
      reason: "no_socket",
    });
  });

  it.each([
    ["another message type", frame(Buffer.concat([Buffer.from([14]), sshString("sig")]))],
    ["a truncated identity list", frame(Buffer.concat([Buffer.from([12]), u32(2)]))],
    [
      "trailing bytes after the list",
      frame(Buffer.concat([Buffer.from([12]), u32(0), Buffer.from([0])])),
    ],
    ["a length over the agent's 256 KiB bound", u32(256 * 1024 + 1)],
  ])("%s is not an agent's answer", async (_label, reply) => {
    const agent = await fakeAgent(() => reply);

    await expect(probeAgentSocket(agent.path, TIMEOUT_MS)).resolves.toEqual({
      listening: false,
      reason: "not_an_agent",
    });
  });

  it("a peer that hangs up before answering is not an agent", async () => {
    const agent = await fakeAgent(() => null);
    const probe = probeAgentSocket(agent.path, TIMEOUT_MS);
    (await agent.connected).end();

    await expect(probe).resolves.toEqual({ listening: false, reason: "not_an_agent" });
  });

  it("a peer that accepts and never answers: no answer within the deadline", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const agent = await fakeAgent(() => null);
    const probe = probeAgentSocket(agent.path, TIMEOUT_MS);
    await agent.connected;
    await vi.waitFor(() => expect(agent.requests.length).toBe(1));
    await vi.advanceTimersByTimeAsync(TIMEOUT_MS);

    await expect(probe).resolves.toEqual({ listening: false, reason: "timeout" });
  });

  // Measured on this host (Node 24.13.1): connect(2) to a regular file answers ENOTSOCK on
  // win32; Linux answers ECONNREFUSED there (af_unix.c) and darwin is unmeasured.
  it.runIf(process.platform === "win32")(
    "a regular file at the path is not a socket (win32)",
    async () => {
      const dir = mkdtempSync(join(tmpdir(), "harpoc-probe-"));
      dirs.push(dir);
      const file = join(dir, "ssh-agent.sock");
      writeFileSync(file, "");

      await expect(probeAgentSocket(file, TIMEOUT_MS)).resolves.toEqual({
        listening: false,
        reason: "not_a_socket",
      });
    },
  );
});

describe("sshKeyFingerprint", () => {
  it("is ssh-keygen -l's SHA256 form: the unpadded base64 of the blob's SHA-256", () => {
    expect(sshKeyFingerprint(Buffer.from(ED25519.blob, "base64"))).toBe(ED25519.fingerprint);
    expect(sshKeyFingerprint(Buffer.from(ECDSA256.blob, "base64"))).toBe(ECDSA256.fingerprint);
  });
});
