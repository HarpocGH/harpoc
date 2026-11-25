import { randomBytes } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { connect } from "node:net";
import type { Socket } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ssh2 from "ssh2";
import type {
  ClientChannel,
  ConnectConfig,
  IdentityCallback,
  ParsedKey,
  SFTPWrapper,
  SignCallback,
  SigningRequestOptions,
  Client as SshClient,
} from "ssh2";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateEd25519HostKeys } from "./ssh2-host-keys.js";
import { hostAddress, startSftpSshServer } from "./ssh2-sftp-server.js";
import type {
  SftpFault,
  SftpRequestName,
  SftpServer,
  SftpServerOptions,
} from "./ssh2-sftp-server.js";

const { BaseAgent, Client, utils } = ssh2;

const USER = "deploy";
const KEYS = join(dirname(fileURLToPath(import.meta.url)), "ssh");
const USER_KEY = readFileSync(join(KEYS, "ed25519_openssh"), "utf8");
const AUTHORIZED = readFileSync(join(KEYS, "ed25519_openssh.pub"), "utf8")
  .trim()
  .split(/\s+/)
  .slice(0, 2)
  .join(" ");
const HOST = hostAddress();
const SILENCE_MS = 500;

const FXP = {
  INIT: 1,
  VERSION: 2,
  OPEN: 3,
  CLOSE: 4,
  WRITE: 6,
  FSTAT: 8,
  OPENDIR: 11,
  STATUS: 101,
  HANDLE: 102,
  EXTENDED: 200,
} as const;
const PFLAGS_CREATE = 0x02 | 0x08 | 0x10;

type ClientError = Error & { level?: string };
type SftpError = Error & { code?: number };

let base: string;
let root: string;
const servers: SftpServer[] = [];
const clients: SshClient[] = [];

beforeEach(() => {
  base = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-sftp-fx-")));
  root = join(base, "root");
  mkdirSync(root);
});

afterEach(async () => {
  for (const client of clients.splice(0)) client.end();
  await Promise.all(servers.splice(0).map((server) => server.close()));
  rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

async function serve(options: Partial<SftpServerOptions> = {}): Promise<SftpServer> {
  const server = await startSftpSshServer({
    user: USER,
    authorizedKey: AUTHORIZED,
    root,
    ...options,
  });
  servers.push(server);
  return server;
}

function login(
  server: SftpServer,
  config: Partial<ConnectConfig> = {},
): Promise<{ client: SshClient; error: ClientError | null }> {
  const client = new Client();
  clients.push(client);
  return new Promise((resolve) => {
    const settle = (error: ClientError | null): void => resolve({ client, error });
    client.once("ready", () => settle(null));
    client.on("error", (err: ClientError) => settle(err));
    client.once("close", () => settle(new Error("the connection closed")));
    client.connect({
      host: "127.0.0.1",
      port: server.port,
      username: USER,
      privateKey: USER_KEY,
      readyTimeout: 10_000,
      ...config,
    });
  });
}

async function connected(server: SftpServer, host?: string): Promise<SshClient> {
  const { client, error } = await login(server, host === undefined ? {} : { host });
  if (error !== null) throw error;
  return client;
}

function sftpOf(client: SshClient): Promise<SFTPWrapper> {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => (err ? reject(err) : resolve(sftp)));
  });
}

async function session(options: Partial<SftpServerOptions> = {}) {
  const server = await serve(options);
  const sftp = await sftpOf(await connected(server));
  return { server, sftp };
}

function done<T = void>(run: (cb: (err?: Error | null, value?: T) => void) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    run((err, value) => (err ? reject(err) : resolve(value as T)));
  });
}

async function refusal(call: Promise<unknown>): Promise<SftpError | undefined> {
  let thrown: unknown;
  try {
    await call;
  } catch (err) {
    thrown = err;
  }
  return thrown as SftpError | undefined;
}

function subsys(client: SshClient, name: string): Promise<ClientChannel> {
  return new Promise((resolve, reject) => {
    client.subsys(name, (err, channel) => (err ? reject(err) : resolve(channel)));
  });
}

function u32(value: number): Buffer {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function str(value: Buffer | string): Buffer {
  const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : value;
  return Buffer.concat([u32(bytes.length), bytes]);
}

function packet(type: number, ...parts: Buffer[]): Buffer {
  const payload = Buffer.concat([Buffer.from([type]), ...parts]);
  return Buffer.concat([u32(payload.length), payload]);
}

const INIT = packet(FXP.INIT, u32(3));
const NO_ATTRS = u32(0);

interface Inbox {
  bytes(count: number): Promise<Buffer>;
  frame(): Promise<Buffer>;
  pending(): number;
  closed: Promise<void>;
}

function inboxOf(channel: ClientChannel): Inbox {
  let held = Buffer.alloc(0);
  let ended = false;
  let wake: () => void = () => undefined;
  const closed = new Promise<void>((resolve) => {
    channel.once("close", () => {
      ended = true;
      wake();
      resolve();
    });
  });
  channel.on("data", (chunk: Buffer) => {
    held = Buffer.concat([held, chunk]);
    wake();
  });
  const bytes = async (count: number): Promise<Buffer> => {
    while (held.length < count) {
      if (ended) throw new Error("the channel closed before the bytes came");
      await new Promise<void>((resolve) => {
        wake = resolve;
      });
    }
    const out = held.subarray(0, count);
    held = held.subarray(count);
    return out;
  };
  return {
    bytes,
    frame: async () => bytes((await bytes(4)).readUInt32BE(0)),
    pending: () => held.length,
    closed,
  };
}

async function rawSession(options: Partial<SftpServerOptions> = {}) {
  const server = await serve(options);
  const channel = await subsys(await connected(server), "sftp");
  const inbox = inboxOf(channel);
  channel.write(INIT);
  expect((await inbox.frame())[0]).toBe(FXP.VERSION);
  return { server, channel, inbox };
}

async function rawOpen(channel: ClientChannel, inbox: Inbox): Promise<Buffer> {
  channel.write(packet(FXP.OPEN, u32(1), str("/f"), u32(PFLAGS_CREATE), NO_ATTRS));
  const reply = await inbox.frame();
  expect(reply[0]).toBe(FXP.HANDLE);
  return reply.subarray(9, 9 + reply.readUInt32BE(5));
}

function status(reply: Buffer): { type: number; id: number; code: number } {
  return { type: reply[0] as number, id: reply.readUInt32BE(1), code: reply.readUInt32BE(5) };
}

function version(payload: Buffer): { type: number; version: number; pairs: [string, string][] } {
  const pairs: [string, string][] = [];
  let at = 5;
  const text = (): string => {
    const length = payload.readUInt32BE(at);
    const value = payload.subarray(at + 4, at + 4 + length).toString("utf8");
    at += 4 + length;
    return value;
  };
  while (at < payload.length) pairs.push([text(), text()]);
  return { type: payload[0] as number, version: payload.readUInt32BE(1), pairs };
}

const authorizedPublic = utils.parseKey(AUTHORIZED) as ParsedKey;

class ForgingAgent extends BaseAgent<ParsedKey> {
  private readonly forger = utils.parseKey(generateEd25519HostKeys().private) as ParsedKey;

  getIdentities(cb: IdentityCallback<ParsedKey>): void {
    cb(undefined, [authorizedPublic]);
  }

  sign(
    _key: ParsedKey,
    data: Buffer,
    options?: SigningRequestOptions | SignCallback,
    cb?: SignCallback,
  ): void {
    const callback = typeof options === "function" ? options : cb;
    callback?.(undefined, this.forger.sign(data));
  }
}

describe("the ssh2 SFTP server fixture against ssh2's own client", () => {
  it("the authorized key logs in; another key, another user and a password are refused", async () => {
    const server = await serve();

    expect((await login(server)).error).toBeNull();
    const refused = [
      await login(server, { privateKey: generateEd25519HostKeys().private }),
      await login(server, { username: "someone-else" }),
      await login(server, { privateKey: undefined, password: randomBytes(12).toString("hex") }),
      await login(server, { privateKey: undefined, agent: new ForgingAgent() }),
    ];

    expect(refused.map(({ error }) => error?.level)).toStrictEqual([
      "client-authentication",
      "client-authentication",
      "client-authentication",
      "client-authentication",
    ]);
    expect(server.seen.methods).toContain("publickey");
    expect(server.seen.methods).toContain("password");
    expect(server.seen.connections).toBe(5);
  });

  it("exec, shell and a subsystem other than sftp are refused and recorded", async () => {
    const server = await serve();
    const client = await connected(server);

    const opened = (open: (cb: (err: Error | undefined) => void) => void): Promise<boolean> =>
      new Promise((resolve) => open((err) => resolve(err === undefined)));

    expect(await opened((cb) => client.exec("id", (err) => cb(err)))).toBe(false);
    expect(await opened((cb) => client.shell(false, (err) => cb(err)))).toBe(false);
    expect(await opened((cb) => client.subsys("other", (err) => cb(err)))).toBe(false);
    expect(server.seen.execs).toStrictEqual(["id", "shell"]);
    expect(server.seen.subsystems).toStrictEqual(["other"]);
    expect(server.seen.requests).toStrictEqual([]);
  });

  it("INIT is answered VERSION 3 with posix-rename@openssh.com and fsync@openssh.com", async () => {
    const server = await serve();
    const client = await connected(server);
    const channel = await subsys(client, "sftp");
    const inbox = inboxOf(channel);
    channel.write(INIT);

    expect(version(await inbox.frame())).toStrictEqual({
      type: FXP.VERSION,
      version: 3,
      pairs: [
        ["posix-rename@openssh.com", "1"],
        ["fsync@openssh.com", "1"],
      ],
    });
    expect(inbox.pending()).toBe(0);

    const sftp = await sftpOf(client);
    const handle = await done<Buffer>((cb) => sftp.open("a", "w", cb));
    await done((cb) => sftp.ext_openssh_fsync(handle, cb));
    await done((cb) => sftp.close(handle, cb));
    await done((cb) => sftp.ext_openssh_rename("a", "b", cb));
    expect(existsSync(join(root, "b"))).toBe(true);
    expect(existsSync(join(root, "a"))).toBe(false);
  });

  it.each([
    { off: "posixRename", refused: "posix-rename@openssh.com", served: "fsync@openssh.com" },
    { off: "fsync", refused: "fsync@openssh.com", served: "posix-rename@openssh.com" },
  ] as const)("each extension can be switched off — $off", async ({ off, refused, served }) => {
    const { sftp } = await session({ extensions: { [off]: false } });
    const handle = await done<Buffer>((cb) => sftp.open("a", "w", cb));
    const fsync = (): Promise<void> => done((cb) => sftp.ext_openssh_fsync(handle, cb));
    const rename = (): Promise<void> => done((cb) => sftp.ext_openssh_rename("a", "b", cb));
    const run = { "fsync@openssh.com": fsync, "posix-rename@openssh.com": rename };

    expect((await refusal(run[refused]()))?.message).toBe(
      "Server does not support this extended request",
    );
    await expect(run[served]()).resolves.toBeUndefined();

    const raw = await rawSession({ extensions: { [off]: false } });
    raw.channel.write(packet(FXP.EXTENDED, u32(7), str(refused), str("/a"), str("/c")));
    expect(status(await raw.inbox.frame())).toStrictEqual({ type: FXP.STATUS, id: 7, code: 8 });
  });

  it("a version other than 3 and bytes before VERSION are sent as configured", async () => {
    const preamble = Buffer.from("Welcome\n");
    const server = await serve({ version: 4, preamble });
    const channel = await subsys(await connected(server), "sftp");
    const inbox = inboxOf(channel);
    channel.write(INIT);

    expect((await inbox.bytes(preamble.length)).equals(preamble)).toBe(true);
    const reply = version(await inbox.frame());
    expect([reply.type, reply.version]).toStrictEqual([FXP.VERSION, 4]);
  });

  it("the stderr text reaches the client's error stream before VERSION", async () => {
    const text = "Host key verification failed.\r\n";
    const server = await serve({ stderr: text });
    const channel = await subsys(await connected(server), "sftp");
    const order: string[] = [];
    let stderr = "";
    channel.stderr.on("data", (chunk: Buffer) => {
      order.push("stderr");
      stderr += chunk.toString("utf8");
    });
    channel.on("data", () => order.push("stdout"));
    const inbox = inboxOf(channel);
    channel.write(INIT);

    expect((await inbox.frame())[0]).toBe(FXP.VERSION);
    expect(stderr).toBe(text);
    expect(order[0]).toBe("stderr");
  });

  it("an exclusive open with 0600, fsetstat, fstat, write, fsync, close and posix-rename publish the bytes", async () => {
    const { server, sftp } = await session();
    const bytes = randomBytes(64);

    const handle = await done<Buffer>((cb) => sftp.open(".a.tmp", "wx", { mode: 0o600 }, cb));
    await done((cb) => sftp.fchmod(handle, 0o600, cb));
    const stats = await done<{ mode: number; size: number }>((cb) => sftp.fstat(handle, cb));
    await done((cb) => sftp.write(handle, bytes, 0, bytes.length, 0, cb));
    await done((cb) => sftp.ext_openssh_fsync(handle, cb));
    await done((cb) => sftp.close(handle, cb));
    await done((cb) => sftp.ext_openssh_rename(".a.tmp", "a", cb));

    expect(readFileSync(join(root, "a")).equals(bytes)).toBe(true);
    expect(existsSync(join(root, ".a.tmp"))).toBe(false);
    expect(server.permissions("/a")).toBe(0o600);
    expect([stats.mode, stats.size]).toStrictEqual([0o100600, 0]);
    expect(server.seen.requests).toStrictEqual([
      "INIT",
      "OPEN",
      "FSETSTAT",
      "FSTAT",
      "WRITE",
      "fsync@openssh.com",
      "CLOSE",
      "posix-rename@openssh.com",
    ]);
  });

  // win32 keeps no POSIX mode bits: the disk's mode is judged off win32 alone.
  it.skipIf(process.platform === "win32")(
    "an exclusive open with 0600 and fsetstat 0600 publish a file of mode 0600 on disk",
    async () => {
      const { sftp } = await session();

      const handle = await done<Buffer>((cb) => sftp.open(".a.tmp", "wx", { mode: 0o600 }, cb));
      await done((cb) => sftp.fchmod(handle, 0o600, cb));
      await done((cb) => sftp.close(handle, cb));
      await done((cb) => sftp.ext_openssh_rename(".a.tmp", "a", cb));

      expect(statSync(join(root, "a")).mode & 0o777).toBe(0o600);
    },
  );

  it("an exclusive open of an existing name fails, and collideOnOpen plants one", async () => {
    writeFileSync(join(root, "x"), "kept\n");
    const { sftp } = await session();

    expect((await refusal(done((cb) => sftp.open("x", "wx", cb))))?.code).toBe(4);
    expect(readFileSync(join(root, "x"), "utf8")).toBe("kept\n");

    const colliding = await session({ collideOnOpen: true });
    expect((await refusal(done((cb) => colliding.sftp.open("y", "wx", cb))))?.code).toBe(4);
    expect(readFileSync(join(root, "y"), "utf8")).toBe("planted\n");
    const plain = await done<Buffer>((cb) => colliding.sftp.open("z", "w", cb));
    await done((cb) => colliding.sftp.close(plain, cb));
    expect(readFileSync(join(root, "z"), "utf8")).toBe("");
  });

  it("opendir and readdir list the names, remove removes", async () => {
    for (const name of ["one", "two", "three"]) writeFileSync(join(root, name), name);
    const { sftp } = await session();

    const handle = await done<Buffer>((cb) => sftp.opendir("/", cb));
    const listed = await done<{ filename: string }[]>((cb) => sftp.readdir(handle, cb));
    const end = await refusal(done((cb) => sftp.readdir(handle, cb)));
    await done((cb) => sftp.close(handle, cb));
    await done((cb) => sftp.unlink("two", cb));

    expect(listed.map((entry) => entry.filename).sort()).toStrictEqual(["one", "three", "two"]);
    expect(end?.code).toBe(1);
    expect(existsSync(join(root, "two"))).toBe(false);
    expect(existsSync(join(root, "one"))).toBe(true);
  });

  it("posix-rename replaces a file, and fails over a directory", async () => {
    writeFileSync(join(root, "target"), "old\n");
    writeFileSync(join(root, "source"), "new\n");
    writeFileSync(join(root, "other"), "other\n");
    mkdirSync(join(root, "dir"));
    const { sftp } = await session();

    await done((cb) => sftp.ext_openssh_rename("source", "target", cb));
    const overDirectory = await refusal(done((cb) => sftp.ext_openssh_rename("other", "dir", cb)));

    expect(readFileSync(join(root, "target"), "utf8")).toBe("new\n");
    expect(existsSync(join(root, "source"))).toBe(false);
    expect(overDirectory).toBeInstanceOf(Error);
    expect(lstatSync(join(root, "dir")).isDirectory()).toBe(true);
    expect(readFileSync(join(root, "other"), "utf8")).toBe("other\n");
  });

  // A symbolic link needs a privilege on win32.
  it.skipIf(process.platform === "win32")(
    "posix-rename replaces a link, not what it points at",
    async () => {
      writeFileSync(join(base, "elsewhere"), "untouched\n");
      symlinkSync(join(base, "elsewhere"), join(root, "link"));
      writeFileSync(join(root, "source"), "new\n");
      const { sftp } = await session();

      await done((cb) => sftp.ext_openssh_rename("source", "link", cb));

      expect(lstatSync(join(root, "link")).isFile()).toBe(true);
      expect(readFileSync(join(root, "link"), "utf8")).toBe("new\n");
      expect(readFileSync(join(base, "elsewhere"), "utf8")).toBe("untouched\n");
    },
  );

  it.each<{ request: SftpRequestName; fault: SftpFault }>([
    { request: "OPEN", fault: "failure" },
    { request: "WRITE", fault: "permission" },
    { request: "FSTAT", fault: "close" },
    { request: "CLOSE", fault: "wrong-id" },
    { request: "OPENDIR", fault: "unknown-type" },
  ])("a fault per request type — $request $fault", async ({ request, fault }) => {
    const { server, channel, inbox } = await rawSession({ faults: { [request]: fault } });

    switch (request) {
      case "OPEN": {
        channel.write(packet(FXP.OPEN, u32(1), str("/f"), u32(PFLAGS_CREATE), NO_ATTRS));
        expect(status(await inbox.frame())).toStrictEqual({ type: FXP.STATUS, id: 1, code: 4 });
        expect(existsSync(join(root, "f"))).toBe(false);
        break;
      }
      case "WRITE": {
        const handle = await rawOpen(channel, inbox);
        channel.write(packet(FXP.WRITE, u32(2), str(handle), Buffer.alloc(8), str("abc")));
        expect(status(await inbox.frame())).toStrictEqual({ type: FXP.STATUS, id: 2, code: 3 });
        expect(readFileSync(join(root, "f"), "utf8")).toBe("");
        break;
      }
      case "FSTAT": {
        const handle = await rawOpen(channel, inbox);
        channel.write(packet(FXP.FSTAT, u32(2), str(handle)));
        await inbox.closed;
        expect(inbox.pending()).toBe(0);
        break;
      }
      case "CLOSE": {
        const handle = await rawOpen(channel, inbox);
        channel.write(packet(FXP.CLOSE, u32(2), str(handle)));
        expect(status(await inbox.frame())).toStrictEqual({ type: FXP.STATUS, id: 3, code: 0 });
        break;
      }
      default: {
        channel.write(packet(FXP.OPENDIR, u32(1), str("/")));
        const reply = await inbox.frame();
        expect([reply.length, reply[0], reply.readUInt32BE(1)]).toStrictEqual([5, 250, 1]);
      }
    }
    expect(server.seen.requests.at(-1)).toBe(request);
  });

  it("a silent fault answers nothing, and close ends the channel", async () => {
    const { server, channel, inbox } = await rawSession({ faults: { OPENDIR: "silent" } });
    channel.write(packet(FXP.OPENDIR, u32(1), str("/")));

    const first = await Promise.race([
      inbox.bytes(1).then(() => "a reply"),
      new Promise<string>((resolve) => setTimeout(() => resolve("silence"), SILENCE_MS)),
    ]);
    expect(first).toBe("silence");
    expect(server.seen.requests).toStrictEqual(["INIT", "OPENDIR"]);

    await server.close();
    await inbox.closed;
    expect(inbox.pending()).toBe(0);
  });

  it("an oversize fault's reply has a length field of 262 145", async () => {
    const { channel, inbox } = await rawSession({ faults: { OPENDIR: "oversize" } });
    channel.write(packet(FXP.OPENDIR, u32(1), str("/")));

    expect((await inbox.bytes(4)).readUInt32BE(0)).toBe(262_145);
  });

  it("READ is answered OP_UNSUPPORTED and recorded", async () => {
    writeFileSync(join(root, "r"), "readable\n");
    const { server, sftp } = await session();
    const handle = await done<Buffer>((cb) => sftp.open("r", "r", cb));

    const read = await refusal(
      done((cb) => sftp.read(handle, Buffer.alloc(4), 0, 4, 0, (err) => cb(err))),
    );

    expect(read?.code).toBe(8);
    expect(server.seen.requests).toContain("READ");
  });

  it("fstat answers the configured permissions", async () => {
    const { sftp } = await session({ fstat: { permissions: 0o100644 } });
    const handle = await done<Buffer>((cb) => sftp.open("f", "wx", { mode: 0o600 }, cb));

    const stats = await done<{ mode: number }>((cb) => sftp.fstat(handle, cb));

    expect(stats.mode).toBe(0o100644);
  });

  it("a path that leaves the root is NO_SUCH_FILE", async () => {
    writeFileSync(join(base, "x"), "outside\n");
    const { sftp } = await session();

    expect((await refusal(done((cb) => sftp.open("/../x", "r", cb))))?.code).toBe(2);
  });

  it("pause holds the next request of its type until released", async () => {
    const { server, sftp } = await session();
    const handle = await done<Buffer>((cb) => sftp.open("p", "w", cb));
    const first = randomBytes(16);
    const second = randomBytes(16);
    const held = server.pause("WRITE");
    let wrote = false;

    const writing = done((cb) => sftp.write(handle, first, 0, first.length, 0, cb)).then(() => {
      wrote = true;
    });
    await held.reached;

    expect(readFileSync(join(root, "p")).length).toBe(0);
    expect(wrote).toBe(false);
    held.release();
    await writing;
    await done((cb) => sftp.write(handle, second, 0, second.length, first.length, cb));
    expect(readFileSync(join(root, "p")).equals(Buffer.concat([first, second]))).toBe(true);
  });

  // Skipped where this host has no non-loopback IPv4 address.
  it.skipIf(HOST === null)("it listens on the address it is given", async () => {
    const server = await serve({ host: HOST as string });

    expect((await login(server, { host: HOST as string })).error).toBeNull();
    expect((await login(server)).error).toBeInstanceOf(Error);
    expect(server.seen.connections).toBe(1);
  });

  it("close ends a live channel and the server", async () => {
    const server = await serve();
    const client = await connected(server);
    const inbox = inboxOf(await subsys(client, "sftp"));
    const clientClosed = new Promise<void>((resolve) => client.once("close", () => resolve()));

    await server.close();

    await inbox.closed;
    await clientClosed;
    expect((await login(server)).error).toBeInstanceOf(Error);
  });

  it("close does not wait on a client that keeps its side open", async () => {
    const server = await serve();
    const socket: Socket = connect({ host: "127.0.0.1", port: server.port, allowHalfOpen: true });
    socket.on("error", () => undefined);
    // The server's greeting: it has taken the connection, so its close cannot beat its accept.
    const greeted = new Promise<void>((resolve) => socket.once("data", () => resolve()));
    socket.resume();
    await greeted;
    const ended = new Promise<void>((resolve) => socket.once("end", () => resolve()));

    try {
      await server.close();
      await ended;
    } finally {
      socket.destroy();
    }
    expect(server.seen.connections).toBe(1);
  });
});
