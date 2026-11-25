import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo, Socket } from "node:net";
import { networkInterfaces } from "node:os";
import { join } from "node:path";
import ssh2 from "ssh2";
import type { Connection, ParsedKey, ServerChannel } from "ssh2";
import { generateEd25519HostKeys } from "./ssh2-host-keys.js";

const { Server, utils } = ssh2;

export type SftpRequestName =
  | "INIT"
  | "OPEN"
  | "CLOSE"
  | "READ"
  | "WRITE"
  | "LSTAT"
  | "FSTAT"
  | "SETSTAT"
  | "FSETSTAT"
  | "OPENDIR"
  | "READDIR"
  | "REMOVE"
  | "MKDIR"
  | "RMDIR"
  | "REALPATH"
  | "STAT"
  | "RENAME"
  | "READLINK"
  | "SYMLINK"
  | "posix-rename@openssh.com"
  | "fsync@openssh.com"
  | "EXTENDED";

export type SftpFault =
  | "failure" // STATUS 4 (SSH_FX_FAILURE) in place of the reply
  | "permission" // STATUS 3 (SSH_FX_PERMISSION_DENIED)
  | "silent" // no reply, ever
  | "oversize" // a reply whose length field reads 262 145
  | "wrong-id" // the right reply under the request id plus one
  | "unknown-type" // a packet of type 250 carrying the request id
  | "close"; // the channel ends instead of the reply

export interface SftpServerOptions {
  user: string;
  authorizedKey: string; // "<type> <base64>"; publickey is the one method, its signature verified
  root: string; // the remote "/" is this directory
  host?: string; // listen address, default "127.0.0.1"
  version?: number; // VERSION's number, default 3
  extensions?: { posixRename?: boolean; fsync?: boolean }; // each default true
  preamble?: Buffer; // written on the channel before VERSION
  stderr?: string; // written on the channel's stderr when the subsystem starts
  faults?: Partial<Record<SftpRequestName, SftpFault>>;
  fstat?: { permissions?: number; size?: number }; // FSTAT answers these in place of the file's
  collideOnOpen?: boolean; // an exclusive OPEN finds its name created just before, holding "planted\n"
}

export interface SftpServer {
  port: number;
  hostKeyLine: string; // "<type> <base64>", no comment
  seen: {
    connections: number;
    methods: string[];
    subsystems: string[];
    execs: string[];
    requests: SftpRequestName[];
  };
  permissions(remotePath: string): number | undefined; // off win32 the file's mode on disk; on win32 the fixture's record
  pause(request: SftpRequestName): {
    reached: Promise<void>;
    release: () => void;
  }; // holds the next request of that type
  close(): Promise<void>; // releases every pause, ends every connection, closes the server
}

const FXP = {
  INIT: 1,
  VERSION: 2,
  OPEN: 3,
  CLOSE: 4,
  READ: 5,
  WRITE: 6,
  LSTAT: 7,
  FSTAT: 8,
  SETSTAT: 9,
  FSETSTAT: 10,
  OPENDIR: 11,
  READDIR: 12,
  REMOVE: 13,
  MKDIR: 14,
  RMDIR: 15,
  REALPATH: 16,
  STAT: 17,
  RENAME: 18,
  READLINK: 19,
  SYMLINK: 20,
  STATUS: 101,
  HANDLE: 102,
  NAME: 104,
  ATTRS: 105,
  EXTENDED: 200,
} as const;

const NAMES: Record<number, SftpRequestName> = {
  [FXP.INIT]: "INIT",
  [FXP.OPEN]: "OPEN",
  [FXP.CLOSE]: "CLOSE",
  [FXP.READ]: "READ",
  [FXP.WRITE]: "WRITE",
  [FXP.LSTAT]: "LSTAT",
  [FXP.FSTAT]: "FSTAT",
  [FXP.SETSTAT]: "SETSTAT",
  [FXP.FSETSTAT]: "FSETSTAT",
  [FXP.OPENDIR]: "OPENDIR",
  [FXP.READDIR]: "READDIR",
  [FXP.REMOVE]: "REMOVE",
  [FXP.MKDIR]: "MKDIR",
  [FXP.RMDIR]: "RMDIR",
  [FXP.REALPATH]: "REALPATH",
  [FXP.STAT]: "STAT",
  [FXP.RENAME]: "RENAME",
  [FXP.READLINK]: "READLINK",
  [FXP.SYMLINK]: "SYMLINK",
};

const FX = {
  OK: 0,
  EOF: 1,
  NO_SUCH_FILE: 2,
  PERMISSION_DENIED: 3,
  FAILURE: 4,
  OP_UNSUPPORTED: 8,
} as const;

const ATTR_SIZE = 0x1;
const ATTR_UIDGID = 0x2;
const ATTR_PERMISSIONS = 0x4;
const ATTR_ACMODTIME = 0x8;
const ATTR_EXTENDED = 0x80000000;

const PFLAG_READ = 0x1;
const PFLAG_WRITE = 0x2;
const PFLAG_APPEND = 0x4;
const PFLAG_CREAT = 0x8;
const PFLAG_TRUNC = 0x10;
const PFLAG_EXCL = 0x20;

const POSIX_RENAME = "posix-rename@openssh.com";
const FSYNC = "fsync@openssh.com";
const MAX_PACKET_BYTES = 262_144;
const OVERSIZE_PAYLOAD_BYTES = MAX_PACKET_BYTES + 1;
const UNKNOWN_TYPE = 250;
const S_IFMT = 0o170000;
const WIN32 = process.platform === "win32";

/** The first non-internal IPv4 address of this host outside 169.254/16, or null. */
export function hostAddress(): string | null {
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal && !entry.address.startsWith("169.254.")) {
        return entry.address;
      }
    }
  }
  return null;
}

class Reader {
  private offset = 1;

  constructor(private readonly payload: Buffer) {}

  u32(): number {
    const value = this.payload.readUInt32BE(this.offset);
    this.offset += 4;
    return value;
  }

  u64(): number {
    const value = this.payload.readBigUInt64BE(this.offset);
    this.offset += 8;
    return Number(value);
  }

  bytes(): Buffer {
    const length = this.u32();
    if (this.offset + length > this.payload.length)
      throw new RangeError("a string runs past the packet");
    const value = this.payload.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  text(): string {
    return this.bytes().toString("utf8");
  }

  attrs(): { permissions?: number } {
    const flags = this.u32();
    if (flags & ATTR_SIZE) this.u64();
    if (flags & ATTR_UIDGID) {
      this.u32();
      this.u32();
    }
    const permissions = flags & ATTR_PERMISSIONS ? this.u32() : undefined;
    if (flags & ATTR_ACMODTIME) {
      this.u32();
      this.u32();
    }
    if (flags & ATTR_EXTENDED) {
      const count = this.u32();
      for (let i = 0; i < count; i++) {
        this.bytes();
        this.bytes();
      }
    }
    return permissions === undefined ? {} : { permissions };
  }
}

function u32(value: number): Buffer {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value >>> 0);
  return out;
}

function u64(value: number): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value));
  return out;
}

function str(value: Buffer | string): Buffer {
  const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : value;
  return Buffer.concat([u32(bytes.length), bytes]);
}

function byte(value: number): Buffer {
  return Buffer.from([value]);
}

function statusPayload(id: number, code: number, message = ""): Buffer {
  return Buffer.concat([byte(FXP.STATUS), u32(id), u32(code), str(message), str("")]);
}

function attrsBytes(size: number, permissions: number): Buffer {
  return Buffer.concat([u32(ATTR_SIZE | ATTR_PERMISSIONS), u64(size), u32(permissions)]);
}

function framed(payload: Buffer): Buffer {
  return Buffer.concat([u32(payload.length), payload]);
}

function errorStatus(err: unknown): number {
  const code = (err as NodeJS.ErrnoException).code;
  if (code === "ENOENT") return FX.NO_SUCH_FILE;
  if (code === "EACCES" || code === "EPERM") return FX.PERMISSION_DENIED;
  return FX.FAILURE;
}

function openFlags(pflags: number): number {
  const access =
    pflags & PFLAG_READ && pflags & PFLAG_WRITE
      ? constants.O_RDWR
      : pflags & PFLAG_WRITE
        ? constants.O_WRONLY
        : constants.O_RDONLY;
  return (
    access |
    (pflags & PFLAG_APPEND ? constants.O_APPEND : 0) |
    (pflags & PFLAG_CREAT ? constants.O_CREAT : 0) |
    (pflags & PFLAG_TRUNC ? constants.O_TRUNC : 0) |
    (pflags & PFLAG_EXCL ? constants.O_EXCL : 0)
  );
}

type Handle =
  { kind: "file"; fd: number; path: string } | { kind: "dir"; path: string; listed: boolean };

interface ChannelState {
  channel: ServerChannel;
  handles: Map<string, Handle>;
  nextHandle: number;
  closed: boolean;
}

interface Hold {
  reach: () => void;
  released: Promise<void>;
  release: () => void;
}

/**
 * An `ssh2` server on `host` whose `subsystem` listener speaks its own SFTP version 3 on the raw
 * channel, with `root` on disk behind it: one user logs in by the one public key, every
 * request is recorded, a request type can be held or answered by a fault, and the extensions
 * can be switched off. On win32 the fixture keeps the permissions it was asked for, since the
 * file system keeps none; off win32 the modes are the disk's.
 */
export async function startSftpSshServer(options: SftpServerOptions): Promise<SftpServer> {
  const hostKeys = generateEd25519HostKeys();
  const parsed = utils.parseKey(options.authorizedKey);
  if (parsed instanceof Error) throw parsed;
  const authorized: ParsedKey = Array.isArray(parsed) ? (parsed[0] as ParsedKey) : parsed;
  const posixRename = options.extensions?.posixRename !== false;
  const fsync = options.extensions?.fsync !== false;
  const seen: SftpServer["seen"] = {
    connections: 0,
    methods: [],
    subsystems: [],
    execs: [],
    requests: [],
  };
  const records = new Map<string, number>();
  const holds = new Map<SftpRequestName, Hold[]>();
  const everyHold = new Set<Hold>();
  const sockets = new Set<Socket>();
  const connections = new Set<Connection>();
  const channels = new Set<ChannelState>();

  const local = (remote: string): string | null => {
    const segments = remote.split(WIN32 ? /[\\/]/ : "/").filter((s) => s !== "" && s !== ".");
    if (segments.includes("..")) return null;
    return join(options.root, ...segments);
  };

  const recordedMode = (path: string, mode: number): number => {
    const recorded = records.get(path);
    return recorded === undefined ? mode : (mode & S_IFMT) | recorded;
  };

  const closeHandles = (state: ChannelState): void => {
    for (const handle of state.handles.values()) {
      if (handle.kind === "file") {
        try {
          closeSync(handle.fd);
        } catch {
          // Already closed.
        }
      }
    }
    state.handles.clear();
  };

  const endChannel = (state: ChannelState): void => {
    if (state.closed) return;
    state.closed = true;
    closeHandles(state);
    state.channel.end();
  };

  const send = (state: ChannelState, payload: Buffer): void => {
    if (!state.closed) state.channel.write(framed(payload));
  };

  const newHandle = (state: ChannelState, handle: Handle): Buffer => {
    const bytes = u32(state.nextHandle);
    state.nextHandle += 1;
    state.handles.set(bytes.toString("hex"), handle);
    return bytes;
  };

  const fileOf = (
    state: ChannelState,
    bytes: Buffer,
  ): Extract<Handle, { kind: "file" }> | undefined => {
    const handle = state.handles.get(bytes.toString("hex"));
    return handle?.kind === "file" ? handle : undefined;
  };

  const requestName = (payload: Buffer): SftpRequestName | undefined => {
    const type = payload[0] as number;
    if (type !== FXP.EXTENDED) return NAMES[type];
    const name = new Reader(payload);
    name.u32();
    const extension = name.text();
    return extension === POSIX_RENAME || extension === FSYNC ? extension : "EXTENDED";
  };

  const fault = (state: ChannelState, kind: SftpFault, id: number): void => {
    switch (kind) {
      case "failure":
        send(state, statusPayload(id, FX.FAILURE));
        return;
      case "permission":
        send(state, statusPayload(id, FX.PERMISSION_DENIED));
        return;
      case "oversize": {
        const fill = OVERSIZE_PAYLOAD_BYTES - statusPayload(id, FX.OK).length;
        send(state, statusPayload(id, FX.OK, "x".repeat(fill)));
        return;
      }
      case "unknown-type":
        send(state, Buffer.concat([byte(UNKNOWN_TYPE), u32(id)]));
        return;
      case "close":
        endChannel(state);
        return;
      default:
        return;
    }
  };

  const answer = (state: ChannelState, payload: Buffer, id: number): Buffer => {
    const type = payload[0] as number;
    const read = new Reader(payload);
    if (type === FXP.INIT) {
      const pairs: Buffer[] = [];
      if (posixRename) pairs.push(str(POSIX_RENAME), str("1"));
      if (fsync) pairs.push(str(FSYNC), str("1"));
      return Buffer.concat([byte(FXP.VERSION), u32(options.version ?? 3), ...pairs]);
    }
    read.u32();
    try {
      switch (type) {
        case FXP.OPEN: {
          const path = local(read.text());
          const pflags = read.u32();
          const { permissions } = read.attrs();
          if (path === null) return statusPayload(id, FX.NO_SUCH_FILE);
          const mode = (permissions ?? 0o666) & 0o7777;
          if (pflags & PFLAG_EXCL && options.collideOnOpen === true) {
            try {
              writeFileSync(path, "planted\n", { flag: "wx" });
            } catch {
              // A name that already exists collides as it is.
            }
          }
          let existed = true;
          try {
            lstatSync(path);
          } catch {
            existed = false;
          }
          const fd = openSync(path, openFlags(pflags), mode);
          if (WIN32 && !existed) records.set(path, mode & ~0o022);
          const handle = newHandle(state, { kind: "file", fd, path });
          return Buffer.concat([byte(FXP.HANDLE), u32(id), str(handle)]);
        }
        case FXP.CLOSE: {
          const key = read.bytes().toString("hex");
          const handle = state.handles.get(key);
          if (handle === undefined) return statusPayload(id, FX.FAILURE);
          state.handles.delete(key);
          if (handle.kind === "file") closeSync(handle.fd);
          return statusPayload(id, FX.OK);
        }
        case FXP.WRITE: {
          const handle = fileOf(state, read.bytes());
          const offset = read.u64();
          const data = read.bytes();
          if (handle === undefined) return statusPayload(id, FX.FAILURE);
          writeSync(handle.fd, data, 0, data.length, offset);
          return statusPayload(id, FX.OK);
        }
        case FXP.FSTAT: {
          const handle = fileOf(state, read.bytes());
          if (handle === undefined) return statusPayload(id, FX.FAILURE);
          const stat = fstatSync(handle.fd);
          const size = options.fstat?.size ?? stat.size;
          const permissions =
            options.fstat?.permissions ??
            (WIN32 ? recordedMode(handle.path, stat.mode) : stat.mode);
          return Buffer.concat([byte(FXP.ATTRS), u32(id), attrsBytes(size, permissions)]);
        }
        case FXP.FSETSTAT: {
          const handle = fileOf(state, read.bytes());
          const { permissions } = read.attrs();
          if (handle === undefined) return statusPayload(id, FX.FAILURE);
          if (permissions !== undefined) {
            if (WIN32) records.set(handle.path, permissions & 0o7777);
            else fchmodSync(handle.fd, permissions & 0o7777);
          }
          return statusPayload(id, FX.OK);
        }
        case FXP.OPENDIR: {
          const path = local(read.text());
          if (path === null) return statusPayload(id, FX.NO_SUCH_FILE);
          readdirSync(path);
          const handle = newHandle(state, { kind: "dir", path, listed: false });
          return Buffer.concat([byte(FXP.HANDLE), u32(id), str(handle)]);
        }
        case FXP.READDIR: {
          const handle = state.handles.get(read.bytes().toString("hex"));
          if (handle?.kind !== "dir") return statusPayload(id, FX.FAILURE);
          if (handle.listed) return statusPayload(id, FX.EOF);
          handle.listed = true;
          const entries = readdirSync(handle.path).map((name) => {
            const path = join(handle.path, name);
            let attrs = u32(0);
            try {
              const stat = lstatSync(path);
              attrs = attrsBytes(stat.size, WIN32 ? recordedMode(path, stat.mode) : stat.mode);
            } catch {
              // A name that vanished since the listing is sent without attributes.
            }
            return Buffer.concat([str(name), str(name), attrs]);
          });
          return Buffer.concat([byte(FXP.NAME), u32(id), u32(entries.length), ...entries]);
        }
        case FXP.REMOVE: {
          const path = local(read.text());
          if (path === null) return statusPayload(id, FX.NO_SUCH_FILE);
          unlinkSync(path);
          records.delete(path);
          return statusPayload(id, FX.OK);
        }
        case FXP.EXTENDED: {
          const extension = read.text();
          if (extension === POSIX_RENAME && posixRename) {
            const from = local(read.text());
            const to = local(read.text());
            if (from === null || to === null) return statusPayload(id, FX.NO_SUCH_FILE);
            renameSync(from, to);
            const recorded = records.get(from);
            records.delete(from);
            if (recorded === undefined) records.delete(to);
            else records.set(to, recorded);
            return statusPayload(id, FX.OK);
          }
          if (extension === FSYNC && fsync) {
            const handle = fileOf(state, read.bytes());
            if (handle === undefined) return statusPayload(id, FX.FAILURE);
            fsyncSync(handle.fd);
            return statusPayload(id, FX.OK);
          }
          return statusPayload(id, FX.OP_UNSUPPORTED);
        }
        default:
          return statusPayload(id, FX.OP_UNSUPPORTED);
      }
    } catch (err) {
      if (err instanceof RangeError) throw err;
      return statusPayload(id, errorStatus(err));
    }
  };

  const serve = async (state: ChannelState, payload: Buffer): Promise<void> => {
    const type = payload[0] as number;
    const id = type === FXP.INIT ? 0 : payload.readUInt32BE(1);
    const name = requestName(payload);
    if (name !== undefined) {
      seen.requests.push(name);
      const hold = holds.get(name)?.shift();
      if (hold !== undefined) {
        hold.reach();
        await hold.released;
      }
    }
    if (state.closed) return;
    const kind = name === undefined ? undefined : options.faults?.[name];
    if (kind !== undefined && kind !== "wrong-id") {
      fault(state, kind, id);
      return;
    }
    const reply = answer(state, payload, id);
    if (kind === "wrong-id" && type !== FXP.INIT) reply.writeUInt32BE((id + 1) >>> 0, 1);
    send(state, reply);
  };

  const serveChannel = (channel: ServerChannel): void => {
    const state: ChannelState = { channel, handles: new Map(), nextHandle: 0, closed: false };
    channels.add(state);
    let pending = Buffer.alloc(0);
    let queue = Promise.resolve();
    channel.on("error", () => {});
    channel.on("close", () => {
      state.closed = true;
      closeHandles(state);
      channels.delete(state);
    });
    channel.on("end", () => {
      queue = queue.then(() => {
        if (state.closed) return;
        state.closed = true;
        closeHandles(state);
        channel.exit(0);
        channel.end();
      });
    });
    channel.on("data", (chunk: Buffer) => {
      if (state.closed) return;
      pending = Buffer.concat([pending, chunk]);
      while (pending.length >= 4) {
        const length = pending.readUInt32BE(0);
        if (length === 0 || length > MAX_PACKET_BYTES) {
          endChannel(state);
          return;
        }
        if (pending.length < 4 + length) return;
        const payload = pending.subarray(4, 4 + length);
        pending = pending.subarray(4 + length);
        queue = queue.then(() => serve(state, payload)).catch(() => endChannel(state));
      }
    });
    if (options.stderr !== undefined) channel.stderr.write(options.stderr);
    if (options.preamble !== undefined) channel.write(options.preamble);
  };

  const ssh = new Server({ hostKeys: [hostKeys.private] }, (connection) => {
    connections.add(connection);
    connection.once("close", () => connections.delete(connection));
    connection.on("error", () => {});
    connection.on("authentication", (ctx) => {
      seen.methods.push(ctx.method);
      if (ctx.username !== options.user || ctx.method !== "publickey") {
        ctx.reject(["publickey"]);
        return;
      }
      if (ctx.key.algo !== authorized.type || !ctx.key.data.equals(authorized.getPublicSSH())) {
        ctx.reject(["publickey"]);
        return;
      }
      if (ctx.signature === undefined) {
        ctx.accept();
        return;
      }
      if (authorized.verify(ctx.blob as Buffer, ctx.signature, ctx.hashAlgo) === true) ctx.accept();
      else ctx.reject(["publickey"]);
    });
    connection.on("ready", () => {
      connection.on("session", (acceptSession) => {
        const session = acceptSession();
        session.on("exec", (_accept, reject, info) => {
          seen.execs.push(info.command);
          reject();
        });
        session.on("shell", (_accept, reject) => {
          seen.execs.push("shell");
          reject();
        });
        session.on("subsystem", (accept, reject, info) => {
          if (info.name !== "sftp") {
            seen.subsystems.push(info.name);
            reject();
            return;
          }
          serveChannel(accept());
        });
      });
    });
  });

  const tcp = createServer((socket) => {
    seen.connections += 1;
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    ssh.injectSocket(socket);
  });
  await new Promise<void>((resolve, reject) => {
    tcp.once("error", reject);
    tcp.listen(0, options.host ?? "127.0.0.1", () => resolve());
  });
  const { port } = tcp.address() as AddressInfo;

  let closing: Promise<void> | undefined;
  return {
    port,
    hostKeyLine: hostKeys.public.split(/\s+/).slice(0, 2).join(" "),
    seen,
    permissions: (remotePath) => {
      const path = local(remotePath);
      if (path === null) return undefined;
      if (WIN32) return records.get(path);
      try {
        return lstatSync(path).mode & 0o7777;
      } catch {
        return undefined;
      }
    },
    pause: (request) => {
      let reach: () => void = () => undefined;
      let release: () => void = () => undefined;
      const reached = new Promise<void>((resolve) => {
        reach = resolve;
      });
      const released = new Promise<void>((resolve) => {
        release = resolve;
      });
      const hold: Hold = { reach, released, release };
      everyHold.add(hold);
      holds.set(request, [...(holds.get(request) ?? []), hold]);
      return { reached, release };
    },
    close: () => {
      closing ??= (async () => {
        for (const hold of everyHold) hold.release();
        for (const connection of connections) connection.end();
        // Once its own bytes are out, a socket is destroyed: a client that never closes its side
        // cannot hold the server's close.
        for (const socket of sockets) socket.destroySoon();
        await new Promise<void>((resolve) => tcp.close(() => resolve()));
        for (const state of channels) closeHandles(state);
      })();
      return closing;
    },
  };
}
