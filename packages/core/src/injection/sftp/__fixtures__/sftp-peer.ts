import type { SftpChannel } from "../sftp-writer.js";

/**
 * An in-memory SFTP version 3 server for the writer's rows. It writes and reads its own
 * frames and imports nothing of `sftp-wire.ts`, so a fault of the writer's codec reds.
 * Paths and names are `latin1` strings of their raw bytes. `/srv/app`, its parents and the
 * directories above every entry exist; a fault given as a function is asked with the
 * request's ordinal among its kind, counted over every session of the peer.
 */
export type SftpPeerRequest =
  | "init"
  | "opendir"
  | "readdir"
  | "close"
  | "remove"
  | "open"
  | "fsetstat"
  | "fstat"
  | "write"
  | "fsync"
  | "posix-rename";

export type SftpPeerFault =
  | { status: number }
  | { frame: Buffer }
  | { attrs: { flags: number; size?: bigint; permissions?: number } }
  | { hold: Promise<void> }
  | "silent";

export type SftpPeerFaults = Partial<
  Record<SftpPeerRequest, SftpPeerFault | ((ordinal: number) => SftpPeerFault | undefined)>
>;

export interface SftpPeerOptions {
  version?: number;
  extensions?: readonly (readonly [string, string])[];
  before?: Buffer;
  entries?: Readonly<Record<string, string | Buffer | "dir">>;
  faults?: SftpPeerFaults;
  nameBatch?: number;
  longname?: (name: string) => string;
  replyBeforeFlush?: boolean;
}

/** One request as the peer read it; `id` is the version for `INIT`, `request` an extension's name. */
export interface SftpPeerRecord {
  type: number;
  id: number;
  path?: string;
  newPath?: string;
  request?: string;
  offset?: number;
  length?: number;
  pflags?: number;
  attrs?: { flags: number; permissions?: number };
}

export interface SftpPeerSession extends SftpChannel {
  requests: SftpPeerRecord[];
  maxInFlight: number;
}

export interface SftpPeer {
  connect(): SftpPeerSession;
  entry(path: string): { kind: "file" | "dir"; mode: number; data: Buffer } | undefined;
  names(dir: string): string[];
}

const FX = { OK: 0, EOF: 1, NO_SUCH_FILE: 2, FAILURE: 4, BAD_MESSAGE: 5, OP_UNSUPPORTED: 8 };
const ATTR = { SIZE: 0x1, UIDGID: 0x2, PERMISSIONS: 0x4, ACMODTIME: 0x8, EXTENDED: 0x80000000 };
const PFLAG = { CREAT: 0x08, TRUNC: 0x10, EXCL: 0x20 };
const RENAME = "posix-rename@openssh.com";
const FSYNC = "fsync@openssh.com";
const DEFAULT_EXTENSIONS = [
  [RENAME, "1"],
  [FSYNC, "1"],
] as const;
const PRESENT_DIRECTORIES = ["/srv/app"];
const UMASK = 0o022;
const S_IFREG = 0o100000;
const S_IFDIR = 0o040000;

interface Inode {
  kind: "file" | "dir";
  mode: number;
  data: Buffer;
}

type OpenHandle =
  { kind: "file"; inode: Inode } | { kind: "dir"; listing: [string, Inode][]; next: number };

interface PeerAttrs {
  flags: number;
  size?: bigint;
  permissions?: number;
}

interface PeerRequest {
  record: SftpPeerRecord;
  kind: SftpPeerRequest | undefined;
  reply: () => Buffer[];
}

export function sftpString(data: string | Buffer): Buffer {
  const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

/** A whole frame: a number is a `uint32`, a bigint a `uint64`, a string an SSH `string`, a Buffer raw bytes. */
export function sftpFrame(type: number, ...fields: (number | bigint | string | Buffer)[]): Buffer {
  const parts = fields.map((field) => {
    if (typeof field === "string") return sftpString(field);
    if (Buffer.isBuffer(field)) return field;
    if (typeof field === "bigint") {
      const wide = Buffer.alloc(8);
      wide.writeBigUInt64BE(field);
      return wide;
    }
    const word = Buffer.alloc(4);
    word.writeUInt32BE(field >>> 0);
    return word;
  });
  const body = Buffer.concat([Buffer.from([type]), ...parts]);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(body.length);
  return Buffer.concat([length, body]);
}

function attrsFields(attrs: PeerAttrs): (number | bigint)[] {
  const fields: (number | bigint)[] = [attrs.flags];
  if ((attrs.flags & ATTR.SIZE) !== 0) fields.push(attrs.size ?? 0n);
  if ((attrs.flags & ATTR.UIDGID) !== 0) fields.push(0, 0);
  if ((attrs.flags & ATTR.PERMISSIONS) !== 0) fields.push(attrs.permissions ?? 0);
  if ((attrs.flags & ATTR.ACMODTIME) !== 0) fields.push(0, 0);
  if ((attrs.flags & ATTR.EXTENDED) !== 0) fields.push(0);
  return fields;
}

function statOf(inode: Inode): PeerAttrs {
  return {
    flags: ATTR.SIZE | ATTR.UIDGID | ATTR.PERMISSIONS | ATTR.ACMODTIME,
    size: BigInt(inode.data.length),
    permissions: (inode.kind === "dir" ? S_IFDIR : S_IFREG) | inode.mode,
  };
}

function parentOf(path: string): string {
  const cut = path.lastIndexOf("/");
  return cut <= 0 ? "/" : path.slice(0, cut);
}

function baseOf(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

class Cursor {
  private at = 0;

  constructor(private readonly frame: Buffer) {}

  u8(): number {
    const value = this.frame.readUInt8(this.at);
    this.at += 1;
    return value;
  }

  u32(): number {
    const value = this.frame.readUInt32BE(this.at);
    this.at += 4;
    return value;
  }

  u64(): bigint {
    const value = this.frame.readBigUInt64BE(this.at);
    this.at += 8;
    return value;
  }

  bytes(): Buffer {
    const length = this.u32();
    if (this.at + length > this.frame.length) throw new RangeError("sftp-peer: short string");
    const value = this.frame.subarray(this.at, this.at + length);
    this.at += length;
    return value;
  }

  text(): string {
    return this.bytes().toString("latin1");
  }

  attrs(): { flags: number; permissions?: number } {
    const flags = this.u32();
    const attrs: { flags: number; permissions?: number } = { flags };
    if ((flags & ATTR.SIZE) !== 0) this.u64();
    if ((flags & ATTR.UIDGID) !== 0) this.skip(8);
    if ((flags & ATTR.PERMISSIONS) !== 0) attrs.permissions = this.u32();
    if ((flags & ATTR.ACMODTIME) !== 0) this.skip(8);
    if ((flags & ATTR.EXTENDED) !== 0) {
      for (let count = this.u32(); count > 0; count--) {
        this.bytes();
        this.bytes();
      }
    }
    return attrs;
  }

  skip(length: number): void {
    if (this.at + length > this.frame.length) throw new RangeError("sftp-peer: short field");
    this.at += length;
  }

  end(): void {
    if (this.at !== this.frame.length) throw new RangeError("sftp-peer: trailing bytes");
  }
}

export function createSftpPeer(options: SftpPeerOptions = {}): SftpPeer {
  const directory = (): Inode => ({ kind: "dir", mode: 0o755, data: Buffer.alloc(0) });
  const store = new Map<string, Inode>([["/", directory()]]);
  const ordinals = new Map<SftpPeerRequest, number>();
  const extensions = options.extensions ?? DEFAULT_EXTENSIONS;
  const announced = (name: string): boolean => extensions.some(([known]) => known === name);
  let handleCount = 0;

  const makeDirectories = (path: string): void => {
    if (store.has(path)) return;
    makeDirectories(parentOf(path));
    store.set(path, directory());
  };
  for (const path of PRESENT_DIRECTORIES) makeDirectories(path);
  for (const [path, value] of Object.entries(options.entries ?? {})) {
    makeDirectories(parentOf(path));
    store.set(
      path,
      value === "dir"
        ? directory()
        : {
            kind: "file",
            mode: 0o666 & ~UMASK,
            data: typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value),
          },
    );
  }

  const faultFor = (kind: SftpPeerRequest): SftpPeerFault | undefined => {
    const ordinal = (ordinals.get(kind) ?? 0) + 1;
    ordinals.set(kind, ordinal);
    const fault = options.faults?.[kind];
    return typeof fault === "function" ? fault(ordinal) : fault;
  };

  const status = (id: number, code: number): Buffer => sftpFrame(101, id, code, "", "");

  const connect = (): SftpPeerSession => {
    const handles = new Map<string, OpenHandle>();
    const queued: Buffer[] = [];
    let consumer: ((chunk: Buffer) => void) | undefined;
    let unread = Buffer.alloc(0);
    let inFlight = 0;

    const deliver = (chunks: Buffer[]): void => {
      inFlight -= 1;
      for (const chunk of chunks) {
        if (consumer === undefined) queued.push(chunk);
        else consumer(chunk);
      }
    };
    const answer = (chunks: Buffer[]): void => {
      if (options.replyBeforeFlush === true) deliver(chunks);
      else setImmediate(() => deliver(chunks));
    };
    const handleFor = (open: OpenHandle): Buffer => {
      handleCount += 1;
      const name = String(handleCount);
      handles.set(name, open);
      return Buffer.from(name, "latin1");
    };
    const fileOf = (handle: Buffer): Inode | undefined => {
      const open = handles.get(handle.toString("latin1"));
      return open?.kind === "file" ? open.inode : undefined;
    };

    const open = (id: number, path: string, pflags: number, permissions?: number): Buffer => {
      if (store.get(parentOf(path))?.kind !== "dir") return status(id, FX.NO_SUCH_FILE);
      const existing = store.get(path);
      if (existing !== undefined) {
        if ((pflags & PFLAG.CREAT) !== 0 && (pflags & PFLAG.EXCL) !== 0) {
          return status(id, FX.FAILURE);
        }
        if (existing.kind === "dir") return status(id, FX.FAILURE);
        if ((pflags & PFLAG.TRUNC) !== 0) existing.data = Buffer.alloc(0);
        return sftpFrame(102, id, sftpString(handleFor({ kind: "file", inode: existing })));
      }
      if ((pflags & PFLAG.CREAT) === 0) return status(id, FX.NO_SUCH_FILE);
      const inode: Inode = {
        kind: "file",
        mode: (permissions ?? 0o666) & ~UMASK & 0o7777,
        data: Buffer.alloc(0),
      };
      store.set(path, inode);
      return sftpFrame(102, id, sftpString(handleFor({ kind: "file", inode })));
    };

    const write = (id: number, handle: Buffer, offset: number, data: Buffer): Buffer => {
      const inode = fileOf(handle);
      if (inode === undefined) return status(id, FX.FAILURE);
      const end = offset + data.length;
      if (inode.data.length < end) {
        const grown = Buffer.alloc(end);
        inode.data.copy(grown);
        inode.data = grown;
      }
      data.copy(inode.data, offset);
      return status(id, FX.OK);
    };

    const readdir = (id: number, handle: Buffer): Buffer => {
      const open = handles.get(handle.toString("latin1"));
      if (open?.kind !== "dir") return status(id, FX.FAILURE);
      if (open.next >= open.listing.length) return status(id, FX.EOF);
      const batch = open.listing.slice(open.next, open.next + (options.nameBatch ?? 100));
      open.next += batch.length;
      const longname = options.longname ?? (() => "");
      return sftpFrame(
        104,
        id,
        batch.length,
        ...batch.flatMap(([name, inode]) => [
          sftpString(Buffer.from(name, "latin1")),
          longname(name),
          ...attrsFields(statOf(inode)),
        ]),
      );
    };

    const remove = (id: number, path: string): Buffer => {
      const inode = store.get(path);
      if (inode === undefined) return status(id, FX.NO_SUCH_FILE);
      if (inode.kind === "dir") return status(id, FX.FAILURE);
      store.delete(path);
      return status(id, FX.OK);
    };

    const rename = (id: number, from: string, to: string): Buffer => {
      const inode = store.get(from);
      if (inode === undefined) return status(id, FX.NO_SUCH_FILE);
      if (store.get(parentOf(to))?.kind !== "dir") return status(id, FX.NO_SUCH_FILE);
      if (store.get(to)?.kind === "dir") return status(id, FX.FAILURE);
      store.delete(from);
      store.delete(to);
      store.set(to, inode);
      return status(id, FX.OK);
    };

    const parse = (cursor: Cursor): PeerRequest => {
      const type = cursor.u8();
      if (type === 1) {
        const version = cursor.u32();
        cursor.end();
        const fields = extensions.flatMap(([name, data]) => [name, data]);
        return {
          record: { type, id: version },
          kind: "init",
          reply: () => [
            ...(options.before === undefined ? [] : [options.before]),
            sftpFrame(2, options.version ?? 3, ...fields),
          ],
        };
      }
      const id = cursor.u32();
      const record: SftpPeerRecord = { type, id };
      const request = (kind: SftpPeerRequest | undefined, reply: () => Buffer): PeerRequest => {
        cursor.end();
        return { record, kind, reply: () => [reply()] };
      };
      switch (type) {
        case 3: {
          const path = cursor.text();
          const pflags = cursor.u32();
          const attrs = cursor.attrs();
          Object.assign(record, { path, pflags, attrs });
          return request("open", () => open(id, path, pflags, attrs.permissions));
        }
        case 4: {
          const handle = cursor.bytes().toString("latin1");
          return request("close", () => status(id, handles.delete(handle) ? FX.OK : FX.FAILURE));
        }
        case 6: {
          const handle = cursor.bytes();
          const offset = Number(cursor.u64());
          const data = cursor.bytes();
          Object.assign(record, { offset, length: data.length });
          return request("write", () => write(id, handle, offset, data));
        }
        case 8: {
          const handle = cursor.bytes();
          return request("fstat", () => {
            const inode = fileOf(handle);
            return inode === undefined
              ? status(id, FX.FAILURE)
              : sftpFrame(105, id, ...attrsFields(statOf(inode)));
          });
        }
        case 10: {
          const handle = cursor.bytes();
          const attrs = cursor.attrs();
          record.attrs = attrs;
          return request("fsetstat", () => {
            const inode = fileOf(handle);
            if (inode === undefined) return status(id, FX.FAILURE);
            if (attrs.permissions !== undefined) inode.mode = attrs.permissions & 0o7777;
            return status(id, FX.OK);
          });
        }
        case 11: {
          const path = cursor.text();
          record.path = path;
          return request("opendir", () => {
            if (store.get(path)?.kind !== "dir") return status(id, FX.NO_SUCH_FILE);
            const listing = [...store]
              .filter(([key]) => key !== "/" && parentOf(key) === path)
              .map(([key, inode]): [string, Inode] => [baseOf(key), inode]);
            return sftpFrame(102, id, sftpString(handleFor({ kind: "dir", listing, next: 0 })));
          });
        }
        case 12: {
          const handle = cursor.bytes();
          return request("readdir", () => readdir(id, handle));
        }
        case 13: {
          const path = cursor.text();
          record.path = path;
          return request("remove", () => remove(id, path));
        }
        case 200: {
          const name = cursor.bytes().toString("utf8");
          record.request = name;
          if (name === RENAME) {
            const from = cursor.text();
            const to = cursor.text();
            Object.assign(record, { path: from, newPath: to });
            return request("posix-rename", () =>
              announced(RENAME) ? rename(id, from, to) : status(id, FX.OP_UNSUPPORTED),
            );
          }
          if (name === FSYNC) {
            const handle = cursor.bytes();
            return request("fsync", () => {
              if (!announced(FSYNC)) return status(id, FX.OP_UNSUPPORTED);
              return status(id, fileOf(handle) === undefined ? FX.FAILURE : FX.OK);
            });
          }
          return { record, kind: undefined, reply: () => [status(id, FX.OP_UNSUPPORTED)] };
        }
        default:
          return { record, kind: undefined, reply: () => [status(id, FX.OP_UNSUPPORTED)] };
      }
    };

    const receive = (frame: Buffer, session: SftpPeerSession): void => {
      inFlight += 1;
      session.maxInFlight = Math.max(session.maxInFlight, inFlight);
      let request: PeerRequest;
      try {
        request = parse(new Cursor(frame));
      } catch {
        session.requests.push({ type: frame[0] ?? 0, id: -1 });
        answer([status(0, FX.BAD_MESSAGE)]);
        return;
      }
      session.requests.push(request.record);
      const fault = request.kind === undefined ? undefined : faultFor(request.kind);
      if (fault === "silent") return;
      if (fault === undefined) {
        answer(request.reply());
      } else if ("hold" in fault) {
        void fault.hold.then(() => answer(request.reply()));
      } else if ("status" in fault) {
        answer([status(request.record.id, fault.status)]);
      } else if ("frame" in fault) {
        answer([fault.frame]);
      } else {
        answer([sftpFrame(105, request.record.id, ...attrsFields(fault.attrs))]);
      }
    };

    const session: SftpPeerSession = {
      requests: [],
      maxInFlight: 0,
      write(chunk: Buffer): Promise<void> {
        return new Promise<void>((resolve) => {
          unread = Buffer.concat([unread, chunk]);
          while (unread.length >= 4 && unread.length >= 4 + unread.readUInt32BE(0)) {
            const length = unread.readUInt32BE(0);
            const frame = unread.subarray(4, 4 + length);
            unread = unread.subarray(4 + length);
            receive(frame, session);
          }
          resolve();
          chunk.fill(0);
        });
      },
      onData(next: (chunk: Buffer) => void): void {
        if (consumer !== undefined) throw new Error("the peer takes one consumer");
        consumer = next;
        for (const chunk of queued.splice(0)) next(chunk);
      },
    };
    return session;
  };

  return {
    connect,
    entry(path) {
      const inode = store.get(path);
      return inode === undefined
        ? undefined
        : { kind: inode.kind, mode: inode.mode, data: Buffer.from(inode.data) };
    },
    names(dir) {
      return [...store.keys()].filter((key) => key !== "/" && parentOf(key) === dir).map(baseOf);
    },
  };
}
