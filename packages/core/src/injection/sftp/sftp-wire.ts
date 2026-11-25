/**
 * The SFTP version 3 subset the sftp render speaks (draft-ietf-secsh-filexfer-02 and
 * OpenSSH's `PROTOCOL` extensions): the requests it sends, the five replies it reads, and a
 * reader that cuts the stream into frames under OpenSSH's bound. A frame is a `uint32`
 * length of what follows, a type byte and the payload.
 */
import { SshReader, writeByte, writeString, writeUint32 } from "../ssh-agent/ssh-wire.js";

export const SFTP_VERSION = 3;
export const SFTP_MAX_PACKET_BYTES = 262_144;
export const SFTP_MAX_HANDLE_BYTES = 256;
export const SFTP_WRITE_CHUNK_BYTES = 32_768;

export const SSH_FXP = {
  INIT: 1,
  VERSION: 2,
  OPEN: 3,
  CLOSE: 4,
  WRITE: 6,
  FSTAT: 8,
  FSETSTAT: 10,
  OPENDIR: 11,
  READDIR: 12,
  REMOVE: 13,
  STATUS: 101,
  HANDLE: 102,
  NAME: 104,
  ATTRS: 105,
  EXTENDED: 200,
} as const;

export const SSH_FX = {
  OK: 0,
  EOF: 1,
  NO_SUCH_FILE: 2,
  PERMISSION_DENIED: 3,
  FAILURE: 4,
  BAD_MESSAGE: 5,
  NO_CONNECTION: 6,
  CONNECTION_LOST: 7,
  OP_UNSUPPORTED: 8,
} as const;

export const SSH_FXF = { WRITE: 0x02, CREAT: 0x08, EXCL: 0x20 } as const;

export const SSH_FILEXFER_ATTR = {
  SIZE: 0x1,
  UIDGID: 0x2,
  PERMISSIONS: 0x4,
  ACMODTIME: 0x8,
  EXTENDED: 0x80000000,
} as const;

export const SFTP_EXT_POSIX_RENAME = "posix-rename@openssh.com";
export const SFTP_EXT_FSYNC = "fsync@openssh.com";
export const SFTP_EXT_VERSION = "1";

export interface SftpAttrs {
  flags: number;
  size?: bigint;
  uid?: number;
  gid?: number;
  permissions?: number;
  atime?: number;
  mtime?: number;
}

export type SftpReply =
  | { type: 2; version: number; extensions: [string, string][] }
  | { type: 101; id: number; code: number }
  | { type: 102; id: number; handle: Buffer }
  | { type: 104; id: number; names: Buffer[] }
  | { type: 105; id: number; attrs: SftpAttrs };

export interface PacketReader {
  push(chunk: Buffer): Buffer[] | null;
}

const KNOWN_ATTR_FLAGS =
  SSH_FILEXFER_ATTR.SIZE |
  SSH_FILEXFER_ATTR.UIDGID |
  SSH_FILEXFER_ATTR.PERMISSIONS |
  SSH_FILEXFER_ATTR.ACMODTIME |
  SSH_FILEXFER_ATTR.EXTENDED;
const NAME_ENTRY_MIN_BYTES = 12;
const EXTENDED_PAIR_MIN_BYTES = 8;

function frame(type: number, ...fields: Buffer[]): Buffer {
  const body = Buffer.concat([writeByte(type), ...fields]);
  return Buffer.concat([writeUint32(body.length), body]);
}

function permissionsAttrs(permissions: number): Buffer {
  return Buffer.concat([writeUint32(SSH_FILEXFER_ATTR.PERMISSIONS), writeUint32(permissions)]);
}

export function encodeInit(): Buffer {
  return frame(SSH_FXP.INIT, writeUint32(SFTP_VERSION));
}

export function encodeOpen(id: number, path: string, pflags: number, permissions: number): Buffer {
  return frame(
    SSH_FXP.OPEN,
    writeUint32(id),
    writeString(path),
    writeUint32(pflags),
    permissionsAttrs(permissions),
  );
}

export function encodeClose(id: number, handle: Buffer): Buffer {
  return frame(SSH_FXP.CLOSE, writeUint32(id), writeString(handle));
}

/** One allocation that `data` is copied into once: the frame is the chunk's only other copy. */
export function encodeWrite(id: number, handle: Buffer, offset: number, data: Buffer): Buffer {
  const length = 1 + 4 + 4 + handle.length + 8 + 4 + data.length;
  const out = Buffer.alloc(4 + length);
  let at = out.writeUInt32BE(length, 0);
  at = out.writeUInt8(SSH_FXP.WRITE, at);
  at = out.writeUInt32BE(id, at);
  at = out.writeUInt32BE(handle.length, at);
  at += handle.copy(out, at);
  at = out.writeBigUInt64BE(BigInt(offset), at);
  at = out.writeUInt32BE(data.length, at);
  data.copy(out, at);
  return out;
}

export function encodeFstat(id: number, handle: Buffer): Buffer {
  return frame(SSH_FXP.FSTAT, writeUint32(id), writeString(handle));
}

export function encodeFsetstat(id: number, handle: Buffer, permissions: number): Buffer {
  return frame(
    SSH_FXP.FSETSTAT,
    writeUint32(id),
    writeString(handle),
    permissionsAttrs(permissions),
  );
}

export function encodeOpendir(id: number, path: string): Buffer {
  return frame(SSH_FXP.OPENDIR, writeUint32(id), writeString(path));
}

export function encodeReaddir(id: number, handle: Buffer): Buffer {
  return frame(SSH_FXP.READDIR, writeUint32(id), writeString(handle));
}

export function encodeRemove(id: number, path: string): Buffer {
  return frame(SSH_FXP.REMOVE, writeUint32(id), writeString(path));
}

export function encodePosixRename(id: number, oldPath: string, newPath: string): Buffer {
  return frame(
    SSH_FXP.EXTENDED,
    writeUint32(id),
    writeString(SFTP_EXT_POSIX_RENAME),
    writeString(oldPath),
    writeString(newPath),
  );
}

export function encodeFsync(id: number, handle: Buffer): Buffer {
  return frame(SSH_FXP.EXTENDED, writeUint32(id), writeString(SFTP_EXT_FSYNC), writeString(handle));
}

function readUint64(reader: SshReader): bigint {
  const wide = Buffer.alloc(8);
  wide.writeUInt32BE(reader.readUint32(), 0);
  wide.writeUInt32BE(reader.readUint32(), 4);
  return wide.readBigUInt64BE(0);
}

function readAttrs(reader: SshReader): SftpAttrs {
  const flags = reader.readUint32();
  if ((flags & ~KNOWN_ATTR_FLAGS) !== 0) throw new Error("sftp-wire: unknown attribute flag");
  const attrs: SftpAttrs = { flags };
  if ((flags & SSH_FILEXFER_ATTR.SIZE) !== 0) attrs.size = readUint64(reader);
  if ((flags & SSH_FILEXFER_ATTR.UIDGID) !== 0) {
    attrs.uid = reader.readUint32();
    attrs.gid = reader.readUint32();
  }
  if ((flags & SSH_FILEXFER_ATTR.PERMISSIONS) !== 0) attrs.permissions = reader.readUint32();
  if ((flags & SSH_FILEXFER_ATTR.ACMODTIME) !== 0) {
    attrs.atime = reader.readUint32();
    attrs.mtime = reader.readUint32();
  }
  if ((flags & SSH_FILEXFER_ATTR.EXTENDED) !== 0) {
    const count = reader.readUint32();
    if (count > reader.remaining / EXTENDED_PAIR_MIN_BYTES) {
      throw new Error("sftp-wire: extended count exceeds the frame");
    }
    for (let pair = 0; pair < count; pair++) {
      reader.readString();
      reader.readString();
    }
  }
  return attrs;
}

function exact(reader: SshReader, reply: SftpReply): SftpReply | null {
  return reader.remaining === 0 ? reply : null;
}

function readReply(reader: SshReader): SftpReply | null {
  switch (reader.readByte()) {
    case SSH_FXP.VERSION: {
      const version = reader.readUint32();
      const extensions: [string, string][] = [];
      while (reader.remaining > 0) extensions.push([reader.readCString(), reader.readCString()]);
      return { type: SSH_FXP.VERSION, version, extensions };
    }
    case SSH_FXP.STATUS:
      return { type: SSH_FXP.STATUS, id: reader.readUint32(), code: reader.readUint32() };
    case SSH_FXP.HANDLE: {
      const id = reader.readUint32();
      const handle = reader.readString();
      if (handle.length > SFTP_MAX_HANDLE_BYTES) return null;
      return exact(reader, { type: SSH_FXP.HANDLE, id, handle: Buffer.from(handle) });
    }
    case SSH_FXP.NAME: {
      const id = reader.readUint32();
      const count = reader.readUint32();
      if (count > reader.remaining / NAME_ENTRY_MIN_BYTES) return null;
      const names: Buffer[] = [];
      for (let entry = 0; entry < count; entry++) {
        names.push(Buffer.from(reader.readString()));
        reader.readString();
        readAttrs(reader);
      }
      return exact(reader, { type: SSH_FXP.NAME, id, names });
    }
    case SSH_FXP.ATTRS: {
      const id = reader.readUint32();
      return exact(reader, { type: SSH_FXP.ATTRS, id, attrs: readAttrs(reader) });
    }
    default:
      return null;
  }
}

/**
 * A reply's type byte and payload, read strictly: `null` for a malformed frame, a frame not
 * consumed exactly (a `STATUS`'s message and language are not read), a handle over
 * `SFTP_MAX_HANDLE_BYTES`, an unknown attribute flag, or a type but `VERSION`, `STATUS`,
 * `HANDLE`, `NAME` and `ATTRS`.
 */
export function decodeReply(frame: Buffer): SftpReply | null {
  try {
    return readReply(new SshReader(frame));
  } catch {
    return null;
  }
}

/**
 * Cuts the stream into frames (the type byte and payload, each a copy). A length field of 0
 * or over `SFTP_MAX_PACKET_BYTES` answers `null` as soon as its four bytes are in, and every
 * push after it `null`. Pushed chunks are kept as copies and joined only once they hold the
 * next length field or the whole frame it announces.
 */
export function packetReader(): PacketReader {
  let parts: Buffer[] = [];
  let held = 0;
  let needed = 4;
  let spent = false;
  return {
    push(chunk) {
      if (spent) return null;
      if (chunk.length > 0) {
        parts.push(Buffer.from(chunk));
        held += chunk.length;
      }
      const frames: Buffer[] = [];
      while (held >= needed) {
        const unread = parts.length === 1 ? (parts[0] as Buffer) : Buffer.concat(parts, held);
        const length = unread.readUInt32BE(0);
        if (length === 0 || length > SFTP_MAX_PACKET_BYTES) {
          spent = true;
          parts = [];
          held = 0;
          return null;
        }
        if (held < 4 + length) {
          parts = [unread];
          needed = 4 + length;
          break;
        }
        frames.push(Buffer.from(unread.subarray(4, 4 + length)));
        const rest = unread.subarray(4 + length);
        parts = rest.length === 0 ? [] : [rest];
        held = rest.length;
        needed = 4;
      }
      return frames;
    },
  };
}
