import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import type { Socket } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { ErrorCode, VaultError, agentSocketCaller } from "@harpoc/shared";
import { AgentSocketServer } from "./agent-socket-server.js";
import type { AgentSocketEngine, AgentSocketServerOptions } from "./agent-socket-server.js";
import { loadPrivateKey } from "./key-loader.js";
import { SshReader, writeByte, writeUint32 } from "./ssh-wire.js";
import { agentSocketAccepts } from "../__fixtures__/agent-socket.js";
import {
  bindSession,
  buildUserauthRequest,
  connectAgent,
  hostKeyBinding,
  parseIdentities,
  requestIdentities,
  requestSignature,
} from "../__fixtures__/agent-client.js";
import type { AgentClient } from "../__fixtures__/agent-client.js";
import { restrictWindowsPipeToAccount } from "../../session/owner-only.js";
import { system32Path } from "../../win32-paths.js";
import { expectVaultError } from "@harpoc/test-utils";

// A spy around the real DACL step: the Windows rows observe it and make it fail once.
vi.mock("../../session/owner-only.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../session/owner-only.js")>();
  return {
    ...actual,
    restrictWindowsPipeToAccount: vi.fn(actual.restrictWindowsPipeToAccount),
  };
});

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "__fixtures__", "ssh");
const blobOf = (name: string): Buffer =>
  loadPrivateKey(readFileSync(join(FIXTURES, name), "utf8")).publicKeyBlob;

const ECDSA = blobOf("ecdsa256_openssh");
const RSA = blobOf("rsa_openssh");
const IDENTITIES = [
  { publicKeyBlob: ECDSA, comment: "secret://deploy-a" },
  { publicKeyBlob: RSA, comment: "secret://team/deploy-b" },
];
const SIGNATURE = Buffer.from("the engine's signature blob");

const SSH_AGENT_FAILURE = 5;
const SSH_AGENT_SUCCESS = 6;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENT_SIGN_RESPONSE = 14;

interface EngineDouble {
  engine: AgentSocketEngine;
  listAgentSocketIdentities: Mock<AgentSocketEngine["listAgentSocketIdentities"]>;
  signForAgentSocket: Mock<AgentSocketEngine["signForAgentSocket"]>;
  auditServerStart: Mock<AgentSocketEngine["auditServerStart"]>;
}

function engineDouble(): EngineDouble {
  const listAgentSocketIdentities = vi.fn<AgentSocketEngine["listAgentSocketIdentities"]>(
    async () => IDENTITIES,
  );
  const signForAgentSocket = vi.fn<AgentSocketEngine["signForAgentSocket"]>(async () => SIGNATURE);
  const auditServerStart = vi.fn<AgentSocketEngine["auditServerStart"]>();
  return {
    engine: { listAgentSocketIdentities, signForAgentSocket, auditServerStart },
    listAgentSocketIdentities,
    signForAgentSocket,
    auditServerStart,
  };
}

let dir: string | undefined;
let double: EngineDouble;
let onError: Mock<(err: VaultError) => void>;
const servers: AgentSocketServer[] = [];
const clients: AgentClient[] = [];

/** A named pipe on Windows (the ephemeral agent's form), a socket in a mkdtemp directory elsewhere. */
function socketPathFor(name: string): string {
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\harpoc-agent-socket-${randomBytes(8).toString("hex")}-${name}`;
  }
  dir ??= mkdtempSync(join(tmpdir(), "harpoc-agent-socket-"));
  return join(dir, `${name}.sock`);
}

async function start(
  overrides: Partial<AgentSocketServerOptions> = {},
): Promise<AgentSocketServer> {
  const server = await AgentSocketServer.start({
    socketPath: socketPathFor("consumer"),
    consumer: "consumer",
    engine: double.engine,
    onError,
    ...overrides,
  });
  servers.push(server);
  return server;
}

async function connect(path: string): Promise<AgentClient> {
  const client = await connectAgent(path);
  clients.push(client);
  return client;
}

beforeEach(() => {
  vi.mocked(restrictWindowsPipeToAccount).mockReset();
  double = engineDouble();
  onError = vi.fn<(err: VaultError) => void>();
});

afterEach(async () => {
  for (const client of clients.splice(0)) client.close();
  try {
    await Promise.all(servers.splice(0).map((server) => server.stop()));
  } finally {
    if (dir !== undefined) {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      dir = undefined;
    }
  }
});

describe("AgentSocketServer: the listener", () => {
  it("binds, then writes one server.start row { transport: ssh-agent, tokenless: true, consumer }", async () => {
    const server = await start();

    expect(await agentSocketAccepts(server.socketPath)).toBe(true);
    expect(double.auditServerStart).toHaveBeenCalledTimes(1);
    expect(double.auditServerStart).toHaveBeenCalledWith({
      transport: "ssh-agent",
      tokenless: true,
      consumer: "consumer",
    });
    expect(server.consumer).toBe("consumer");
  });

  it("an unwritable start row undoes the bind", async () => {
    double.auditServerStart.mockImplementationOnce(() => {
      throw VaultError.vaultLocked();
    });
    const socketPath = socketPathFor("consumer");

    await expectVaultError(() => start({ socketPath }), ErrorCode.VAULT_LOCKED);
    expect(await agentSocketAccepts(socketPath)).toBe(false);
  });

  it("refuses a path another agent socket listens on, writes no row, and leaves the first serving", async () => {
    const first = await start();
    const second = engineDouble();

    const err = await expectVaultError(
      () => start({ socketPath: first.socketPath, engine: second.engine }),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `ssh-agent socket: another process is listening on ${first.socketPath}`,
    );
    expect(second.auditServerStart).not.toHaveBeenCalled();
    expect((await requestIdentities(await connect(first.socketPath))).type).toBe(
      SSH_AGENT_IDENTITIES_ANSWER,
    );
  });

  it("stop() closes the listener and every open connection, and is idempotent", async () => {
    const server = await start();
    const client = await connect(server.socketPath);
    expect((await requestIdentities(client)).type).toBe(SSH_AGENT_IDENTITIES_ANSWER);

    await server.stop();
    await server.stop();

    await client.closed;
    expect(await agentSocketAccepts(server.socketPath)).toBe(false);
  });

  it("stop() resolves only after an in-flight engine call settles", async () => {
    let release: () => void = () => undefined;
    double.signForAgentSocket.mockImplementationOnce(
      () =>
        new Promise<Buffer>((resolve) => {
          release = () => resolve(SIGNATURE);
        }),
    );
    const server = await start();
    const client = await connect(server.socketPath);
    const reply = requestSignature(client, {
      keyBlob: ECDSA,
      data: Buffer.from("x"),
      flags: 0,
    }).catch((err: unknown) => err);
    await vi.waitFor(() => expect(double.signForAgentSocket).toHaveBeenCalledTimes(1));

    const order: string[] = [];
    const stopped = server.stop().then(() => order.push("stopped"));
    await client.closed;
    // The listener is closed (on POSIX the file may stand until stop() removes it: a refused connect).
    await vi.waitFor(async () =>
      expect(await agentSocketAccepts(server.socketPath).catch(() => false)).toBe(false),
    );
    await new Promise((resolve) => setImmediate(resolve));
    expect(order).toEqual([]);

    order.push("released");
    release();
    await stopped;
    expect(order).toEqual(["released", "stopped"]);
    expect(await reply).toBeInstanceOf(Error);
  });

  it("stop() also waits for an engine call queued behind another on the same connection", async () => {
    let releaseFirst: () => void = () => undefined;
    let releaseSecond: () => void = () => undefined;
    double.listAgentSocketIdentities
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            releaseFirst = () => resolve(IDENTITIES);
          }),
      )
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            releaseSecond = () => resolve(IDENTITIES);
          }),
      );
    const server = await start();
    const client = await connect(server.socketPath);
    const identitiesFrame = Buffer.concat([writeUint32(1), writeByte(11)]);
    const reply = client
      .sendRaw(Buffer.concat([identitiesFrame, identitiesFrame]))
      .catch((err: unknown) => err);
    await vi.waitFor(() => expect(double.listAgentSocketIdentities).toHaveBeenCalledTimes(1));

    const stopping = server.stop();
    await client.closed;
    await vi.waitFor(async () =>
      expect(await agentSocketAccepts(server.socketPath).catch(() => false)).toBe(false),
    );
    releaseFirst();
    await vi.waitFor(() => expect(double.listAgentSocketIdentities).toHaveBeenCalledTimes(2));

    await expect(
      Promise.race([
        stopping.then(() => "stopped"),
        new Promise((resolve) => setImmediate(() => resolve("pending"))),
      ]),
    ).resolves.toBe("pending");
    releaseSecond();
    await stopping;
    expect(await reply).toBeInstanceOf(Error);
  });

  it("two consumers on two paths: each socket asks the engine for its own consumer", async () => {
    const alice = await start({ socketPath: socketPathFor("alice"), consumer: "alice" });
    const bob = await start({ socketPath: socketPathFor("bob"), consumer: "bob" });

    await requestIdentities(await connect(alice.socketPath));
    await requestIdentities(await connect(bob.socketPath));

    expect(double.listAgentSocketIdentities.mock.calls.map(([caller]) => caller)).toEqual([
      agentSocketCaller("alice"),
      agentSocketCaller("bob"),
    ]);
    expect(double.auditServerStart.mock.calls.map(([options]) => options.consumer)).toEqual([
      "alice",
      "bob",
    ]);
  });
});

describe("AgentSocketServer: one responder per connection over the engine", () => {
  it("an unbound REQUEST_IDENTITIES asks the engine with the consumer's caller and no binding", async () => {
    const server = await start();

    const reply = await requestIdentities(await connect(server.socketPath));

    expect(double.listAgentSocketIdentities).toHaveBeenCalledWith(
      agentSocketCaller("consumer"),
      null,
    );
    expect(agentSocketCaller("consumer")).toEqual({
      principal_type: "agent",
      principal_id: "consumer",
      interface: "ssh_agent",
    });
    expect(reply.type).toBe(SSH_AGENT_IDENTITIES_ANSWER);
    expect(parseIdentities(reply)).toEqual([
      { publicKeyBlob: ECDSA, comment: "secret://deploy-a" },
      { publicKeyBlob: RSA, comment: "secret://team/deploy-b" },
    ]);
  });

  it("a verified session-bind answers SUCCESS and the next identities request carries the binding", async () => {
    const server = await start();
    const client = await connect(server.socketPath);
    const bind = hostKeyBinding("ed25519_openssh", randomBytes(32));

    expect((await bindSession(client, { ...bind, isForwarding: false })).type).toBe(
      SSH_AGENT_SUCCESS,
    );
    await requestIdentities(client);

    expect(double.listAgentSocketIdentities).toHaveBeenLastCalledWith(
      agentSocketCaller("consumer"),
      { hostKeyBlob: bind.hostKeyBlob, sessionId: bind.sessionId },
    );
  });

  it("a bound sign request reaches the engine with the binding and the forwarding flag; its signature is framed", async () => {
    const server = await start();
    const client = await connect(server.socketPath);
    const bind = hostKeyBinding("ed25519_openssh", randomBytes(32));
    await bindSession(client, { ...bind, isForwarding: false });
    const data = buildUserauthRequest({
      sessionId: bind.sessionId,
      user: "git",
      service: "ssh-connection",
      method: "publickey",
      algorithm: "ecdsa-sha2-nistp256",
      publicKeyBlob: ECDSA,
    });

    const reply = await requestSignature(client, { keyBlob: ECDSA, data, flags: 0 });

    expect(reply.type).toBe(SSH_AGENT_SIGN_RESPONSE);
    expect(new SshReader(reply.payload).readString().equals(SIGNATURE)).toBe(true);
    expect(double.signForAgentSocket).toHaveBeenCalledWith(agentSocketCaller("consumer"), {
      keyBlob: ECDSA,
      data,
      flags: 0,
      binding: { hostKeyBlob: bind.hostKeyBlob, sessionId: bind.sessionId },
      forwarding: false,
    });
    expect(onError).not.toHaveBeenCalled();
  });

  it("an engine refusal answers SSH_AGENT_FAILURE, reaches onError as thrown, and the connection serves on", async () => {
    const refusal = VaultError.sshAgentUnbound("unbound");
    double.signForAgentSocket.mockRejectedValueOnce(refusal);
    const server = await start();
    const client = await connect(server.socketPath);

    const reply = await requestSignature(client, {
      keyBlob: ECDSA,
      data: Buffer.from("x"),
      flags: 0,
    });

    expect([reply.type, reply.payload.length]).toEqual([SSH_AGENT_FAILURE, 0]);
    expect(double.signForAgentSocket.mock.calls[0]?.[1].binding).toBeNull();
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError).toHaveBeenCalledWith(refusal);
    expect((await requestIdentities(client)).type).toBe(SSH_AGENT_IDENTITIES_ANSWER);
  });

  it("any other engine throw answers SSH_AGENT_FAILURE and reaches onError as INTERNAL_ERROR, naming nothing of it", async () => {
    double.listAgentSocketIdentities.mockRejectedValueOnce(
      new Error("driver text naming /var/lib/harpoc/vault.db"),
    );
    const server = await start();
    const client = await connect(server.socketPath);

    expect((await requestIdentities(client)).type).toBe(SSH_AGENT_FAILURE);

    const reported = onError.mock.calls[0]?.[0];
    expect(reported).toBeInstanceOf(VaultError);
    expect([reported?.code, reported?.message]).toEqual([
      ErrorCode.INTERNAL_ERROR,
      "Internal agent socket error",
    ]);
    expect((await requestIdentities(client)).type).toBe(SSH_AGENT_IDENTITIES_ANSWER);
  });

  it("a sealed engine answers SSH_AGENT_FAILURE to identities and sign alike", async () => {
    double.listAgentSocketIdentities.mockRejectedValue(VaultError.vaultLocked());
    double.signForAgentSocket.mockRejectedValue(VaultError.vaultLocked());
    const server = await start();
    const client = await connect(server.socketPath);

    expect((await requestIdentities(client)).type).toBe(SSH_AGENT_FAILURE);
    expect(
      (await requestSignature(client, { keyBlob: ECDSA, data: Buffer.from("x"), flags: 0 })).type,
    ).toBe(SSH_AGENT_FAILURE);
    expect(onError.mock.calls.map(([err]) => err.code)).toEqual([
      ErrorCode.VAULT_LOCKED,
      ErrorCode.VAULT_LOCKED,
    ]);
  });

  it("answers in request order: a request arriving while an earlier one is in the engine waits for it", async () => {
    let release: () => void = () => undefined;
    double.listAgentSocketIdentities.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = () => resolve(IDENTITIES);
        }),
    );
    const server = await start();
    const client = await connect(server.socketPath);

    const first = requestIdentities(client);
    await vi.waitFor(() => expect(double.listAgentSocketIdentities).toHaveBeenCalledTimes(1));
    const second = client.request(writeByte(0xfe));
    await new Promise((resolve) => setImmediate(resolve));
    release();

    expect([(await first).type, (await second).type]).toEqual([
      SSH_AGENT_IDENTITIES_ANSWER,
      SSH_AGENT_FAILURE,
    ]);
  });

  it("a client that half-closes after its request still reads the reply", async () => {
    // The engine answers on a later turn of the loop, as a store read can.
    double.listAgentSocketIdentities.mockImplementationOnce(
      () => new Promise((resolve) => setImmediate(() => resolve(IDENTITIES))),
    );
    const server = await start();
    const client = await connect(server.socketPath);

    const reply = requestIdentities(client);
    client.end();

    expect((await reply).type).toBe(SSH_AGENT_IDENTITIES_ANSWER);
    await client.closed;
  });
});

describe("AgentSocketServer: connection bounds", () => {
  it("closes a connection idle for idleTimeoutMs", async () => {
    const server = await start({ idleTimeoutMs: 50 });
    const client = await connect(server.socketPath);
    expect((await requestIdentities(client)).type).toBe(SSH_AGENT_IDENTITIES_ANSWER);

    await client.closed;
  });

  it("closes a connection past maxConnections at accept and keeps serving the others", async () => {
    const server = await start({ maxConnections: 1 });
    const kept = await connect(server.socketPath);
    expect((await requestIdentities(kept)).type).toBe(SSH_AGENT_IDENTITIES_ANSWER);

    const refused = await connect(server.socketPath);
    await refused.closed;

    expect((await requestIdentities(kept)).type).toBe(SSH_AGENT_IDENTITIES_ANSWER);
    expect(double.listAgentSocketIdentities).toHaveBeenCalledTimes(2);
  });
});

describe.runIf(process.platform === "win32")("AgentSocketServer on Windows", () => {
  it("refuses a path that is not a named pipe before anything binds or is recorded", async () => {
    const err = await expectVaultError(
      () => start({ socketPath: "C:\\harpoc\\run\\agent\\ssh-agent.sock", consumer: "agent" }),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      "ssh-agent socket: not supported on Windows except on a named pipe \\\\.\\pipe\\<name> (no socket directory mode to rely on): C:\\harpoc\\run\\agent\\ssh-agent.sock",
    );
    expect(double.auditServerStart).not.toHaveBeenCalled();
  });

  /** The pipe's DACL in SDDL, read through a client handle opened for ReadPermissions only. */
  function pipeDacl(path: string): string {
    const name = path.slice("\\\\.\\pipe\\".length);
    const res = spawnSync(
      system32Path("WindowsPowerShell", "v1.0", "powershell.exe"),
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        `$c=[System.IO.Pipes.NamedPipeClientStream]::new('.','${name}',[System.IO.Pipes.PipeAccessRights]'ReadData, ReadPermissions',[System.IO.Pipes.PipeOptions]::None,[System.Security.Principal.TokenImpersonationLevel]::Identification,[System.IO.HandleInheritability]::None);$c.Connect(5000);[System.Console]::Out.WriteLine($c.GetAccessControl().GetSecurityDescriptorSddlForm('Access'));$c.Dispose()`,
      ],
      { encoding: "utf8", shell: false, windowsHide: true, timeout: 15_000 },
    );
    expect(res.status).toBe(0);
    return res.stdout.trim();
  }

  // P1 (B7): Node's pipe grants Everyone and Anonymous read (FR) and nobody else but the owner,
  // SYSTEM and Administrators write — so neither another user nor the consumer can send a request.
  it("without win32ConsumerSid the pipe keeps Node's default DACL: Everyone and Anonymous read, no other writer", async () => {
    const server = await start();
    const dacl = pipeDacl(server.socketPath);
    expect(dacl).toContain("(A;;FR;;;WD)");
    expect(dacl).toContain("(A;;FR;;;AN)");
    expect(vi.mocked(restrictWindowsPipeToAccount)).not.toHaveBeenCalled();
  });

  it("with win32ConsumerSid the DACL is protected: this account, SYSTEM and Administrators full, the consumer read-write, before the one start row", async () => {
    const server = await start({ win32ConsumerSid: "S-1-5-32-545" });
    const dacl = pipeDacl(server.socketPath);
    expect(dacl.startsWith("D:P")).toBe(true);
    expect(dacl).toContain("(A;;0x12019b;;;BU)");
    expect(dacl).toContain("(A;;0x1f019f;;;SY)");
    expect(dacl).toContain("(A;;0x1f019f;;;BA)");
    expect(dacl).not.toContain(";;;WD)");
    expect(dacl).not.toContain(";;;AN)");
    const [restricted] = vi.mocked(restrictWindowsPipeToAccount).mock.invocationCallOrder;
    const [recorded] = double.auditServerStart.mock.invocationCallOrder;
    expect(restricted).toBeLessThan(recorded as number);
    expect(double.auditServerStart.mock.calls).toEqual([
      [{ transport: "ssh-agent", tokenless: true, consumer: "consumer" }],
    ]);
    const client = await connect(server.socketPath);
    expect(parseIdentities(await requestIdentities(client))).toHaveLength(2);
  });

  it("a DACL that cannot be set refuses INVALID_INPUT naming the pipe, writes no row and stops listening", async () => {
    vi.mocked(restrictWindowsPipeToAccount).mockRejectedValueOnce(
      new Error("pipe access list: not as set"),
    );
    const socketPath = socketPathFor("consumer");
    const err = await expectVaultError(
      () => start({ socketPath, win32ConsumerSid: "S-1-5-32-545" }),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `ssh-agent socket: the access list of ${socketPath} could not be set to the consumer's account`,
    );
    expect(double.auditServerStart).not.toHaveBeenCalled();
    await expect(connectAgent(socketPath)).rejects.toThrow();
  });

  it("a connection accepted while the DACL is set is served only after the start row", async () => {
    let release: () => void = () => undefined;
    const socketPath = socketPathFor("consumer");
    vi.mocked(restrictWindowsPipeToAccount).mockImplementationOnce(
      () => new Promise((resolve) => (release = () => resolve({ user: "", owner: "", rules: [] }))),
    );
    const starting = start({ socketPath, win32ConsumerSid: "S-1-5-32-545" });
    await vi.waitFor(() => expect(restrictWindowsPipeToAccount).toHaveBeenCalled());
    const client = await connect(socketPath);
    const answer = requestIdentities(client);
    await new Promise((resolve) => setImmediate(resolve));
    expect(double.listAgentSocketIdentities).not.toHaveBeenCalled();
    release();
    await starting;
    expect(parseIdentities(await answer)).toHaveLength(2);
    const [recorded] = double.auditServerStart.mock.invocationCallOrder;
    const [listed] = double.listAgentSocketIdentities.mock.invocationCallOrder;
    expect(recorded).toBeLessThan(listed as number);
  });

  it("an early connection is tracked once: served, it carries the close and error listeners of a connection accepted after the row", async () => {
    let release: () => void = () => undefined;
    const socketPath = socketPathFor("consumer");
    vi.mocked(restrictWindowsPipeToAccount).mockImplementationOnce(
      () => new Promise((resolve) => (release = () => resolve({ user: "", owner: "", rules: [] }))),
    );
    const accept = vi.spyOn(
      AgentSocketServer.prototype as unknown as { accept: (...args: unknown[]) => void },
      "accept",
    );
    try {
      const starting = start({ socketPath, win32ConsumerSid: "S-1-5-32-545" });
      await vi.waitFor(() => expect(restrictWindowsPipeToAccount).toHaveBeenCalled());
      const early = await connect(socketPath);
      const earlyAnswer = requestIdentities(early);
      await vi.waitFor(() => expect(accept).toHaveBeenCalledTimes(1));
      release();
      const server = await starting;
      expect(parseIdentities(await earlyAnswer)).toHaveLength(2);
      const late = await connect(socketPath);
      expect(parseIdentities(await requestIdentities(late))).toHaveLength(2);

      const streams = [...(server as unknown as { sockets: Set<Socket> }).sockets];
      expect(streams).toHaveLength(2);
      const [first, second] = streams as [Socket, Socket];
      expect(first.listenerCount("close")).toBe(second.listenerCount("close"));
      expect(first.listenerCount("error")).toBe(second.listenerCount("error"));
    } finally {
      accept.mockRestore();
    }
  });
});

// The Unix-socket ladder (prepareUnixSocketPath, its own suite) and the 0660 mode exist
// on POSIX only: Windows serves a named pipe, whose access list is B7's (DB-7).
describe.skipIf(process.platform === "win32")("AgentSocketServer on a Unix socket (POSIX)", () => {
  it("binds mode 0660 and removes the socket file at stop()", async () => {
    const server = await start();

    expect(statSync(server.socketPath).mode & 0o777).toBe(0o660);
    await server.stop();
    expect(existsSync(server.socketPath)).toBe(false);
  });

  it("ignores win32ConsumerSid: the socket's 0660 is the factor, no DACL step runs", async () => {
    const server = await start({ win32ConsumerSid: "S-1-5-32-545" });

    expect(statSync(server.socketPath).mode & 0o777).toBe(0o660);
    expect(vi.mocked(restrictWindowsPipeToAccount)).not.toHaveBeenCalled();
  });

  it("refuses a path over 107 bytes, naming its length, before anything is created or recorded", async () => {
    const base = mkdtempSync(join(tmpdir(), "harpoc-agent-socket-"));
    dir = base;
    const socketPath = join(base, "x".repeat(108 - base.length - 1));
    expect(Buffer.byteLength(socketPath)).toBe(108);

    const err = await expectVaultError(() => start({ socketPath }), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(
      `ssh-agent socket: path is 108 bytes, over the 107 a Unix socket address holds: ${socketPath}`,
    );
    expect(existsSync(socketPath)).toBe(false);
    expect(double.auditServerStart).not.toHaveBeenCalled();
  });

  it("a ladder errno (a path under a regular file) is INVALID_INPUT naming the path and the code, and nothing is recorded", async () => {
    const base = mkdtempSync(join(tmpdir(), "harpoc-agent-socket-"));
    dir = base;
    const file = join(base, "file");
    writeFileSync(file, "not a directory");
    const socketPath = join(file, "ssh-agent.sock");

    const err = await expectVaultError(() => start({ socketPath }), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(`ssh-agent socket: cannot listen on ${socketPath} (ENOTDIR)`);
    expect(double.auditServerStart).not.toHaveBeenCalled();
  });
});
