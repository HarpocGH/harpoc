import { randomBytes } from "node:crypto";
import { isRenderTempName, renderTempName } from "@harpoc/shared";
import type { DuplexChild } from "../spawn-captured.js";
import {
  SFTP_EXT_FSYNC,
  SFTP_EXT_POSIX_RENAME,
  SFTP_EXT_VERSION,
  SFTP_VERSION,
  SFTP_WRITE_CHUNK_BYTES,
  SSH_FILEXFER_ATTR,
  SSH_FX,
  SSH_FXF,
  SSH_FXP,
  decodeReply,
  encodeClose,
  encodeFsetstat,
  encodeFstat,
  encodeFsync,
  encodeInit,
  encodeOpen,
  encodeOpendir,
  encodePosixRename,
  encodeReaddir,
  encodeRemove,
  encodeWrite,
  packetReader,
  type SftpAttrs,
  type SftpReply,
} from "./sftp-wire.js";

export type RenderFailureReason =
  | "connect"
  | "host_key"
  | "no_rename"
  | "protocol"
  | "open"
  | "mode"
  | "write"
  | "rename"
  | "timeout";

export type RenderWritten = "yes" | "no" | "unconfirmed";

export interface SftpWriteOutcome {
  written: RenderWritten;
  reason?: RenderFailureReason;
}

export type SftpChannel = Pick<DuplexChild, "write" | "onData">;

const LISTING_MAX_REPLIES = 64;
const LISTING_MAX_BYTES = 1_048_576;
const TEMP_FILE_MODE = 0o600;
const S_IFMT = 0o170000;
const S_IFREG = 0o100000;
const PERMISSION_BITS = 0o7777;
const OPEN_FLAGS = SSH_FXF.WRITE | SSH_FXF.CREAT | SSH_FXF.EXCL;

type ReplyType = SftpReply["type"];
type ReplyOf<T extends ReplyType> = Extract<SftpReply, { type: T }>;

interface Answer<R extends SftpReply = SftpReply> {
  reply: R;
  bytes: number;
}

interface Pending {
  id: number | undefined;
  types: readonly ReplyType[];
  settle: (answer: Answer | undefined) => void;
}

function isEmptyPrivateFile(attrs: SftpAttrs): boolean {
  if (
    (attrs.flags & SSH_FILEXFER_ATTR.SIZE) === 0 ||
    (attrs.flags & SSH_FILEXFER_ATTR.PERMISSIONS) === 0
  ) {
    return false;
  }
  const permissions = attrs.permissions as number;
  return (
    attrs.size === 0n &&
    (permissions & S_IFMT) === S_IFREG &&
    (permissions & PERMISSION_BITS) === TEMP_FILE_MODE
  );
}

/**
 * Writes `content` to `path` (a remote path in normal form) over an SFTP version 3 channel:
 * stale temporary names of the path are removed, a temporary name of the path's own
 * directory is opened `WRITE|CREAT|EXCL` with `0600` and must read back as an empty regular
 * file of exactly `0600`, the content is written in 32 768-byte requests, synced where the
 * server announces `fsync@openssh.com`, closed and renamed over the path with
 * `posix-rename@openssh.com`. One request is in flight at a time; a reply out of step ends
 * the call `protocol` with no cleanup, a step's failure removes the temporary name.
 *
 * Settles when the server answers the rename, at a failure, or when `signal` aborts (its
 * reason `"timeout"` reads as `timeout`), and sends nothing after that. `onWritten` hears
 * `unconfirmed` before the rename's frame is handed on, then `yes` or `no` from its answer.
 * The caller zeroes `content`; each frame handed to `channel.write` is the channel's.
 */
export function writeRemoteFile(
  channel: SftpChannel,
  path: string,
  content: Buffer,
  signal: AbortSignal,
  onWritten?: (written: RenderWritten) => void,
): Promise<SftpWriteOutcome> {
  if (signal.aborted) {
    return Promise.resolve({
      written: "no",
      reason: signal.reason === "timeout" ? "timeout" : "connect",
    });
  }
  const cut = path.lastIndexOf("/");
  const dir = cut === 0 ? "/" : path.slice(0, cut);
  const last = path.slice(cut + 1);
  const inDir = (name: string): string => (dir === "/" ? `/${name}` : `${dir}/${name}`);

  return new Promise<SftpWriteOutcome>((resolve) => {
    const reader = packetReader();
    let pending: Pending | undefined;
    let ended = false;
    let nextId = 1;
    let step: RenderFailureReason = "connect";
    let failure: RenderFailureReason | undefined;
    let renameId: number | undefined;
    let renameAnswered = false;

    const end = (outcome: SftpWriteOutcome): void => {
      if (ended) return;
      ended = true;
      signal.removeEventListener("abort", onAbort);
      const waiting = pending;
      pending = undefined;
      waiting?.settle(undefined);
      resolve(outcome);
    };
    const fail = (reason: RenderFailureReason): void => {
      const written = renameId !== undefined && !renameAnswered ? "unconfirmed" : "no";
      end({ written, reason: failure ?? reason });
    };
    const onAbort = (): void => {
      fail(signal.reason === "timeout" ? "timeout" : step);
    };
    const tell = (written: RenderWritten): void => {
      try {
        onWritten?.(written);
      } catch {
        // The callback is the caller's: its throw changes neither the outcome nor the stream.
      }
    };

    const receive = (frame: Buffer): void => {
      const reply = decodeReply(frame);
      if (reply === null) {
        fail("protocol");
        return;
      }
      const current = pending;
      if (current === undefined) {
        fail("protocol");
        return;
      }
      if (!current.types.includes(reply.type)) {
        fail("protocol");
        return;
      }
      if (reply.type !== SSH_FXP.VERSION && reply.id !== current.id) {
        fail("protocol");
        return;
      }
      pending = undefined;
      if (renameId !== undefined && current.id === renameId && reply.type === SSH_FXP.STATUS) {
        renameAnswered = true;
        if (reply.code === SSH_FX.OK) {
          end({ written: "yes" });
          tell("yes");
          current.settle(undefined);
          return;
        }
        tell("no");
      }
      current.settle({ reply, bytes: frame.length });
    };

    const exchange = async <T extends ReplyType>(
      types: readonly T[],
      id: number | undefined,
      frame: Buffer,
    ): Promise<Answer<ReplyOf<T>> | undefined> => {
      const answered = new Promise<Answer | undefined>((settle) => {
        pending = { id, types, settle };
      });
      const [, answer] = await Promise.all([channel.write(frame), answered]);
      return ended ? undefined : (answer as Answer<ReplyOf<T>> | undefined);
    };
    const request = <T extends ReplyType>(
      types: readonly T[],
      build: (id: number) => Buffer,
    ): Promise<Answer<ReplyOf<T>> | undefined> => {
      if (ended) return Promise.resolve(undefined);
      const id = nextId;
      nextId += 1;
      return exchange(types, id, build(id));
    };
    const status = (build: (id: number) => Buffer) => request([SSH_FXP.STATUS], build);

    const staleNames = (raw: Buffer): string[] => {
      const text = raw.toString("utf8");
      return Buffer.from(text, "utf8").equals(raw) && isRenderTempName(text, last) ? [text] : [];
    };

    const removeStale = async (): Promise<void> => {
      const opened = await request([SSH_FXP.STATUS, SSH_FXP.HANDLE], (id) =>
        encodeOpendir(id, dir),
      );
      if (opened === undefined || opened.reply.type !== SSH_FXP.HANDLE) return;
      const handle = opened.reply.handle;
      const stale: string[] = [];
      let complete = false;
      let bytes = 0;
      for (let replies = 0; replies < LISTING_MAX_REPLIES; replies++) {
        const read = await request([SSH_FXP.STATUS, SSH_FXP.NAME], (id) =>
          encodeReaddir(id, handle),
        );
        if (read === undefined) return;
        if (read.reply.type === SSH_FXP.STATUS) {
          complete = read.reply.code === SSH_FX.EOF;
          break;
        }
        bytes += read.bytes;
        if (bytes > LISTING_MAX_BYTES) break;
        stale.push(...read.reply.names.flatMap(staleNames));
      }
      if ((await status((id) => encodeClose(id, handle))) === undefined || !complete) return;
      for (const name of stale) {
        if ((await status((id) => encodeRemove(id, inDir(name)))) === undefined) return;
      }
    };

    const run = async (): Promise<void> => {
      const hello = await exchange([SSH_FXP.VERSION], undefined, encodeInit());
      if (hello === undefined) return;
      if (hello.reply.version !== SFTP_VERSION) {
        fail("protocol");
        return;
      }
      const announced = (name: string): boolean =>
        hello.reply.extensions.some(([key, data]) => key === name && data === SFTP_EXT_VERSION);
      if (!announced(SFTP_EXT_POSIX_RENAME)) {
        fail("no_rename");
        return;
      }
      const fsync = announced(SFTP_EXT_FSYNC);

      await removeStale();
      if (ended) return;

      const temp = inDir(renderTempName(last, randomBytes(16).toString("hex")));
      step = "open";
      const opened = await request([SSH_FXP.STATUS, SSH_FXP.HANDLE], (id) =>
        encodeOpen(id, temp, OPEN_FLAGS, TEMP_FILE_MODE),
      );
      if (opened === undefined) return;
      if (opened.reply.type !== SSH_FXP.HANDLE) {
        fail("open");
        return;
      }
      const handle = opened.reply.handle;
      let handleOpen = true;
      const cleanUp = async (reason: RenderFailureReason): Promise<void> => {
        failure = reason;
        if (handleOpen && (await status((id) => encodeClose(id, handle))) === undefined) return;
        if ((await status((id) => encodeRemove(id, temp))) === undefined) return;
        fail(reason);
      };

      step = "mode";
      const chmod = await status((id) => encodeFsetstat(id, handle, TEMP_FILE_MODE));
      if (chmod === undefined) return;
      if (chmod.reply.code !== SSH_FX.OK) return cleanUp("mode");
      const stat = await request([SSH_FXP.STATUS, SSH_FXP.ATTRS], (id) => encodeFstat(id, handle));
      if (stat === undefined) return;
      if (stat.reply.type !== SSH_FXP.ATTRS || !isEmptyPrivateFile(stat.reply.attrs)) {
        return cleanUp("mode");
      }

      step = "write";
      for (let offset = 0; offset < content.length; offset += SFTP_WRITE_CHUNK_BYTES) {
        const chunk = content.subarray(offset, offset + SFTP_WRITE_CHUNK_BYTES);
        const wrote = await status((id) => encodeWrite(id, handle, offset, chunk));
        if (wrote === undefined) return;
        if (wrote.reply.code !== SSH_FX.OK) return cleanUp("write");
      }
      if (fsync) {
        const synced = await status((id) => encodeFsync(id, handle));
        if (synced === undefined) return;
        if (synced.reply.code !== SSH_FX.OK) return cleanUp("write");
      }
      const closed = await status((id) => encodeClose(id, handle));
      if (closed === undefined) return;
      handleOpen = false;
      if (closed.reply.code !== SSH_FX.OK) return cleanUp("write");

      step = "rename";
      tell("unconfirmed");
      const renamed = await status((id) => {
        renameId = id;
        return encodePosixRename(id, temp, path);
      });
      if (renamed === undefined) return;
      return cleanUp("rename");
    };

    channel.onData((chunk) => {
      if (ended) return;
      const frames = reader.push(chunk);
      if (frames === null) {
        fail("protocol");
        return;
      }
      for (const frame of frames) {
        if (ended) return;
        receive(frame);
      }
    });
    signal.addEventListener("abort", onAbort, { once: true });
    run().catch(() => {
      fail("protocol");
    });
  });
}
