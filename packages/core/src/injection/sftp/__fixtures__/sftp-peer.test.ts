import { describe, expect, it } from "vitest";
import { createSftpPeer, sftpFrame, sftpString, type SftpPeerSession } from "./sftp-peer.js";

const FILE = "/srv/app/f";
const RENAME = "posix-rename@openssh.com";

/** Sends one request and resolves with the one chunk that answers it. */
function client(session: SftpPeerSession): (frame: Buffer) => Promise<Buffer> {
  const unread: Buffer[] = [];
  const waiting: ((chunk: Buffer) => void)[] = [];
  session.onData((chunk) => {
    const next = waiting.shift();
    if (next === undefined) unread.push(chunk);
    else next(chunk);
  });
  return async (frame) => {
    const answered = new Promise<Buffer>((resolve) => {
      const ready = unread.shift();
      if (ready === undefined) waiting.push(resolve);
      else resolve(ready);
    });
    await session.write(frame);
    return answered;
  };
}

function typeOf(reply: Buffer): number {
  return reply.readUInt8(4);
}

function codeOf(reply: Buffer): number {
  return reply.readUInt32BE(9);
}

function handleOf(reply: Buffer): Buffer {
  return reply.subarray(13, 13 + reply.readUInt32BE(9));
}

async function started(session: SftpPeerSession): Promise<(frame: Buffer) => Promise<Buffer>> {
  const ask = client(session);
  expect(typeOf(await ask(sftpFrame(1, 3)))).toBe(2);
  return ask;
}

describe("the SFTP peer", () => {
  it("an OPEN with EXCL on an existing name answers FAILURE", async () => {
    const peer = createSftpPeer({ entries: { [FILE]: "x" } });
    const ask = await started(peer.connect());
    const refused = await ask(sftpFrame(3, 1, FILE, 0x2a, 4, 0o600));
    expect([typeOf(refused), codeOf(refused)]).toEqual([101, 4]);
    expect(peer.entry(FILE)?.data.toString()).toBe("x");
    expect(typeOf(await ask(sftpFrame(3, 2, "/srv/app/g", 0x2a, 4, 0o600)))).toBe(102);
  });

  it("a REMOVE leaves an open handle writable", async () => {
    const peer = createSftpPeer();
    const ask = await started(peer.connect());
    const handle = handleOf(await ask(sftpFrame(3, 1, FILE, 0x2a, 4, 0o600)));
    expect(codeOf(await ask(sftpFrame(13, 2, FILE)))).toBe(0);
    expect(peer.names("/srv/app")).toEqual([]);
    const wrote = await ask(sftpFrame(6, 3, sftpString(handle), 0n, sftpString("abc")));
    expect([typeOf(wrote), codeOf(wrote)]).toEqual([101, 0]);
    const stat = await ask(sftpFrame(8, 4, sftpString(handle)));
    expect(typeOf(stat)).toBe(105);
    expect(stat.readBigUInt64BE(13)).toBe(3n);
  });

  it("a rename onto a directory answers FAILURE", async () => {
    const peer = createSftpPeer({ entries: { "/srv/app/d": "dir", [FILE]: "x" } });
    const ask = await started(peer.connect());
    const refused = await ask(sftpFrame(200, 1, RENAME, FILE, "/srv/app/d"));
    expect([typeOf(refused), codeOf(refused)]).toEqual([101, 4]);
    expect(peer.entry("/srv/app/d")?.kind).toBe("dir");
    expect(peer.entry(FILE)?.data.toString()).toBe("x");
    expect(codeOf(await ask(sftpFrame(200, 2, RENAME, FILE, "/srv/app/g")))).toBe(0);
    expect(peer.names("/srv/app")).toEqual(["d", "g"]);
  });

  it("write zeroes the chunk after resolving", async () => {
    const peer = createSftpPeer();
    const session = peer.connect();
    const ask = await started(session);
    const handle = handleOf(await ask(sftpFrame(3, 1, FILE, 0x2a, 4, 0o600)));
    const chunk = sftpFrame(6, 2, sftpString(handle), 0n, sftpString("abc"));
    const wrote = await ask(chunk);
    expect(codeOf(wrote)).toBe(0);
    expect(chunk.every((byte) => byte === 0)).toBe(true);
    expect(peer.entry(FILE)?.data.toString()).toBe("abc");
  });

  it("a function fault counts across sessions", async () => {
    const seen: number[] = [];
    const peer = createSftpPeer({
      faults: {
        opendir: (n) => {
          seen.push(n);
          return n === 2 ? { status: 3 } : undefined;
        },
      },
    });
    const first = await started(peer.connect());
    const second = await started(peer.connect());
    expect(typeOf(await first(sftpFrame(11, 1, "/srv/app")))).toBe(102);
    const refused = await second(sftpFrame(11, 1, "/srv/app"));
    expect([typeOf(refused), codeOf(refused)]).toEqual([101, 3]);
    expect(seen).toEqual([1, 2]);
  });
});
