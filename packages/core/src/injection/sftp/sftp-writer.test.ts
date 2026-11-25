import { randomBytes } from "node:crypto";
import { isRenderTempName } from "@harpoc/shared";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createSftpPeer,
  sftpFrame,
  sftpString,
  type SftpPeer,
  type SftpPeerFaults,
  type SftpPeerOptions,
  type SftpPeerRequest,
  type SftpPeerSession,
} from "./__fixtures__/sftp-peer.js";
import {
  writeRemoteFile,
  type RenderFailureReason,
  type RenderWritten,
  type SftpChannel,
} from "./sftp-writer.js";

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return { ...actual, randomBytes: vi.fn(actual.randomBytes) };
});

const { randomBytes: draw } = await vi.importActual<typeof import("node:crypto")>("node:crypto");

const PATH = "/srv/app/app.env";
const DIR = "/srv/app";
const RENAME = "posix-rename@openssh.com";
const FSYNC = "fsync@openssh.com";
const HEX_A = "0123456789abcdef".repeat(2);
const HEX_B = "fedcba9876543210".repeat(2);
const STALE = `${DIR}/.app.env.harpoc-${HEX_A}.tmp`;
const TYPE = {
  INIT: 1,
  OPEN: 3,
  CLOSE: 4,
  WRITE: 6,
  FSTAT: 8,
  FSETSTAT: 10,
  OPENDIR: 11,
  READDIR: 12,
  REMOVE: 13,
  EXTENDED: 200,
} as const;
const EVERY_REQUEST = [1, 11, 12, 4, 3, 10, 8, 6, 6, 6, 200, 4, 200];
const PENDING = Symbol("pending");
const SESSIONS: SftpPeerSession[] = [];

let content: Buffer;
let copy: Buffer;

beforeEach(() => {
  content = draw(70_000);
  copy = Buffer.from(content);
  vi.mocked(randomBytes).mockClear();
});

function connect(peer: SftpPeer): SftpPeerSession {
  const session = peer.connect();
  SESSIONS.push(session);
  return session;
}

/** Three turns of the event loop: whatever the writer would still send has been sent. */
async function flushed(): Promise<void> {
  for (let turn = 0; turn < 3; turn++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

/** The promise's value where it settled by the next turn of the event loop, else `PENDING`. */
function settledNow<T>(promise: Promise<T>): Promise<T | typeof PENDING> {
  return Promise.race([
    promise,
    new Promise<typeof PENDING>((resolve) => setImmediate(() => resolve(PENDING))),
  ]);
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

async function render(
  options: SftpPeerOptions = {},
  path = PATH,
  onWritten?: (written: RenderWritten) => void,
): Promise<{ peer: SftpPeer; session: SftpPeerSession; outcome: unknown }> {
  const peer = createSftpPeer(options);
  const session = connect(peer);
  const outcome = await writeRemoteFile(
    session,
    path,
    content,
    new AbortController().signal,
    onWritten,
  );
  await flushed();
  return { peer, session, outcome };
}

function types(session: SftpPeerSession): number[] {
  return session.requests.map((request) => request.type);
}

function pathsOf(session: SftpPeerSession, type: number): (string | undefined)[] {
  return session.requests.filter((request) => request.type === type).map((request) => request.path);
}

function tempOf(session: SftpPeerSession): string {
  return session.requests.find((request) => request.type === TYPE.OPEN)?.path as string;
}

function renamed(session: SftpPeerSession): boolean {
  return session.requests.some((request) => request.request === RENAME);
}

function leftovers(peer: SftpPeer): string[] {
  return peer.names(DIR).filter((name) => name.includes(".app.env.harpoc-"));
}

function status(id: number, code: number): Buffer {
  return sftpFrame(101, id, code, "", "");
}

/** Extensions whose `VERSION` frame has a length field of `bytes`, padded by a third pair. */
function paddedTo(bytes: number): [string, string][] {
  const pairs: [string, string][] = [
    [RENAME, "1"],
    [FSYNC, "1"],
  ];
  const pad = "pad@example.com";
  const used = pairs.reduce((sum, [name, data]) => sum + 8 + name.length + data.length, 5);
  return [...pairs, [pad, "x".repeat(bytes - used - 8 - pad.length)]];
}

/** Entries of `others` names that are no temporary name, then one stale name last. */
function listing(others: number): Record<string, string> {
  return Object.fromEntries([
    ...Array.from({ length: others }, (_, at) => [`${DIR}/n${String(at).padStart(2, "0")}`, "x"]),
    [STALE, "stale"],
  ]);
}

describe("the render", () => {
  it("writes through a temporary name and renames it over the path", async () => {
    const { peer, session, outcome } = await render();
    expect(outcome).toStrictEqual({ written: "yes" });
    const file = peer.entry(PATH);
    expect(file?.data.equals(copy)).toBe(true);
    expect(file?.mode).toBe(0o600);
    expect(content.equals(copy)).toBe(true);
    expect(leftovers(peer)).toEqual([]);
    expect(types(session)).toEqual(EVERY_REQUEST);
    const writes = session.requests.filter((request) => request.type === TYPE.WRITE);
    expect(writes.map((request) => request.offset)).toEqual([0, 32_768, 65_536]);
    expect(writes.map((request) => request.length)).toEqual([32_768, 32_768, 4_464]);
    expect(session.maxInFlight).toBe(1);
  });

  it("the temporary name", async () => {
    const { session } = await render();
    const temp = tempOf(session);
    expect(temp).toMatch(/^\/srv\/app\/\.app\.env\.harpoc-[0-9a-f]{32}\.tmp$/);
    expect(isRenderTempName(temp.slice(DIR.length + 1), "app.env")).toBe(true);
    const rename = session.requests.find((request) => request.request === RENAME);
    expect([rename?.path, rename?.newPath]).toEqual([temp, PATH]);

    const peer = createSftpPeer();
    const first = connect(peer);
    const second = connect(peer);
    vi.mocked(randomBytes).mockClear();
    await writeRemoteFile(first, PATH, content, new AbortController().signal);
    await writeRemoteFile(second, PATH, content, new AbortController().signal);
    expect(vi.mocked(randomBytes).mock.calls).toEqual([[16], [16]]);
    expect(tempOf(first)).not.toBe(tempOf(second));
  });

  it("a path in the root", async () => {
    const { session, outcome } = await render({}, "/app.env");
    expect(outcome).toEqual({ written: "yes" });
    expect(pathsOf(session, TYPE.OPENDIR)).toEqual(["/"]);
    expect(tempOf(session)).toMatch(/^\/\.app\.env\.harpoc-[0-9a-f]{32}\.tmp$/);
  });

  it("the open asks for a new file of its own, mode 0600", async () => {
    const { session } = await render();
    const open = session.requests.find((request) => request.type === TYPE.OPEN);
    expect(open?.pflags).toBe(0x2a);
    expect(open?.attrs).toEqual({ flags: 4, permissions: 0o600 });
    const fsetstat = session.requests.find((request) => request.type === TYPE.FSETSTAT);
    expect(fsetstat?.attrs).toEqual({ flags: 4, permissions: 0o600 });
  });

  it("a reply that arrives before its write is flushed is read", async () => {
    const { peer, outcome } = await render({ replyBeforeFlush: true });
    expect(outcome).toEqual({ written: "yes" });
    expect(peer.entry(PATH)?.data.equals(copy)).toBe(true);
  });

  it("an empty content", async () => {
    content = Buffer.alloc(0);
    const { peer, session, outcome } = await render();
    expect(outcome).toEqual({ written: "yes" });
    expect(types(session)).not.toContain(TYPE.WRITE);
    expect(peer.entry(PATH)?.data.length).toBe(0);
  });
});

describe("step 1: the version", () => {
  it.each([2, 4])("a VERSION other than 3 (%i)", async (version) => {
    const { session, outcome } = await render({ version });
    expect(outcome).toEqual({ written: "no", reason: "protocol" });
    expect(types(session)).toEqual([TYPE.INIT]);
  });

  it("no posix-rename", async () => {
    const { session, outcome } = await render({ extensions: [] });
    expect(outcome).toEqual({ written: "no", reason: "no_rename" });
    expect(types(session)).toEqual([TYPE.INIT]);
  });

  it("posix-rename announced with version 2", async () => {
    const { session, outcome } = await render({
      extensions: [
        [RENAME, "2"],
        [FSYNC, "1"],
      ],
    });
    expect(outcome).toEqual({ written: "no", reason: "no_rename" });
    expect(types(session)).toEqual([TYPE.INIT]);
  });

  it("fsync not announced", async () => {
    const { session, outcome } = await render({ extensions: [[RENAME, "1"]] });
    expect(outcome).toEqual({ written: "yes" });
    expect(session.requests.some((request) => request.request === FSYNC)).toBe(false);
  });

  it.each([
    ["a line of text", Buffer.from("Welcome\n")],
    ["a whole STATUS frame of id 0", status(0, 0)],
  ])("bytes before VERSION: %s", async (_case, before) => {
    const { session, outcome } = await render({ before });
    expect(outcome).toEqual({ written: "no", reason: "protocol" });
    expect(types(session)).toEqual([TYPE.INIT]);
  });

  it("a VERSION frame of 262 145 bytes", async () => {
    const { session, outcome } = await render({ extensions: paddedTo(262_145) });
    expect(outcome).toEqual({ written: "no", reason: "protocol" });
    expect(types(session)).toEqual([TYPE.INIT]);
  });

  it("a VERSION frame of 262 144 bytes", async () => {
    const { outcome } = await render({ extensions: paddedTo(262_144) });
    expect(outcome).toEqual({ written: "yes" });
  });
});

describe("step 2: stale temporary names", () => {
  it("stale files of this path are removed", async () => {
    const stale = [STALE, `${DIR}/.app.env.harpoc-${HEX_B}.tmp`];
    const kept = [
      `.app.env.harpoc-${HEX_A.slice(1)}.tmp`,
      `.app.env.harpoc-${HEX_A}.tmp.x`,
      `.other.env.harpoc-${HEX_A}.tmp`,
      `app.env.harpoc-${HEX_A}.tmp`,
      ".app.env",
    ];
    const entries = Object.fromEntries([
      ...stale.map((path) => [path, "stale"]),
      ...kept.map((name) => [`${DIR}/${name}`, "kept"]),
    ]);
    const { peer, session, outcome } = await render({ entries });
    expect(outcome).toEqual({ written: "yes" });
    expect(pathsOf(session, TYPE.REMOVE)).toEqual(stale);
    expect(peer.names(DIR)).toEqual([...kept, "app.env"]);
  });

  it("a directory that cannot be listed is passed over", async () => {
    const { session, outcome } = await render({
      entries: { [STALE]: "stale" },
      faults: { opendir: { status: 3 } },
    });
    expect(outcome).toEqual({ written: "yes" });
    expect(types(session)).toEqual([1, 11, 3, 10, 8, 6, 6, 6, 200, 4, 200]);
  });

  it("a stale file that cannot be removed is passed over", async () => {
    const { peer, session, outcome } = await render({
      entries: { [STALE]: "stale" },
      faults: { remove: { status: 3 } },
    });
    expect(outcome).toEqual({ written: "yes" });
    expect(pathsOf(session, TYPE.REMOVE)).toEqual([STALE]);
    expect(peer.entry(STALE)?.kind).toBe("file");
  });

  it("a listing that fails is given up", async () => {
    const { session, outcome } = await render({
      entries: { [STALE]: "stale" },
      faults: { readdir: { status: 4 } },
    });
    expect(outcome).toEqual({ written: "yes" });
    expect(types(session).slice(0, 5)).toEqual([1, 11, 12, 4, 3]);
    expect(types(session)).not.toContain(TYPE.REMOVE);
  });

  it("a listing of 64 replies is given up", async () => {
    const { session, outcome } = await render({ entries: listing(63), nameBatch: 1 });
    expect(outcome).toEqual({ written: "yes" });
    expect(types(session).filter((type) => type === TYPE.READDIR)).toHaveLength(64);
    expect(types(session)).not.toContain(TYPE.REMOVE);
  });

  it("a listing of 63 names and EOF is complete", async () => {
    const { session, outcome } = await render({ entries: listing(62), nameBatch: 1 });
    expect(outcome).toEqual({ written: "yes" });
    expect(types(session).filter((type) => type === TYPE.READDIR)).toHaveLength(64);
    expect(pathsOf(session, TYPE.REMOVE)).toEqual([STALE]);
  });

  it.each([
    ["over 1 MiB is given up", 10, []],
    ["under 1 MiB is complete", 9, [STALE]],
  ])("a listing %s", async (_case, others, removed) => {
    const { session, outcome } = await render({
      entries: listing(others),
      nameBatch: 1,
      longname: () => "x".repeat(100_000),
    });
    expect(outcome).toEqual({ written: "yes" });
    expect(pathsOf(session, TYPE.REMOVE)).toEqual(removed);
  });

  it("a name that is no UTF-8 is passed over", async () => {
    const raw = `/srv/.a\xffb.env.harpoc-${HEX_A}.tmp`;
    const { peer, session, outcome } = await render(
      { entries: { [raw]: "stale" } },
      "/srv/a\uFFFDb.env",
    );
    expect(outcome).toEqual({ written: "yes" });
    expect(types(session)).not.toContain(TYPE.REMOVE);
    expect(peer.entry(raw)?.kind).toBe("file");
  });
});

describe("step 3: the open", () => {
  it("an existing temporary name ends the render", async () => {
    vi.mocked(randomBytes).mockImplementationOnce(() => Buffer.alloc(16, 0xab));
    const existing = `${DIR}/.app.env.harpoc-${"ab".repeat(16)}.tmp`;
    const { peer, session, outcome } = await render({
      entries: { [existing]: "other" },
      faults: { opendir: { status: 3 } },
    });
    expect(outcome).toEqual({ written: "no", reason: "open" });
    expect(types(session)).toEqual([TYPE.INIT, TYPE.OPENDIR, TYPE.OPEN]);
    expect(pathsOf(session, TYPE.OPEN)).toEqual([existing]);
    expect(peer.entry(existing)?.data.toString()).toBe("other");
  });

  it.each([2, 3, 4, 8])("an OPEN answered %d", async (code) => {
    const { session, outcome } = await render({ faults: { open: { status: code } } });
    expect(outcome).toEqual({ written: "no", reason: "open" });
    expect(types(session)).toEqual([1, 11, 12, 4, 3]);
  });

  it("a handle over 256 bytes", async () => {
    const { session, outcome } = await render({
      faults: { open: { frame: sftpFrame(102, 4, sftpString(Buffer.alloc(257, 0x68))) } },
    });
    expect(outcome).toEqual({ written: "no", reason: "protocol" });
    expect(types(session)).toEqual([1, 11, 12, 4, 3]);
  });
});

describe("step 4: the mode", () => {
  it("FSETSTAT refused", async () => {
    const { peer, session, outcome } = await render({ faults: { fsetstat: { status: 3 } } });
    expect(outcome).toEqual({ written: "no", reason: "mode" });
    expect(types(session)).toEqual([1, 11, 12, 4, 3, 10, 4, 13]);
    expect(pathsOf(session, TYPE.REMOVE)).toEqual([tempOf(session)]);
    expect(leftovers(peer)).toEqual([]);
  });

  it.each([
    ["permissions 0o100644", { flags: 5, size: 0n, permissions: 0o100644 }],
    ["permissions 0o104600", { flags: 5, size: 0n, permissions: 0o104600 }],
    ["permissions 0o040600", { flags: 5, size: 0n, permissions: 0o040600 }],
    ["permissions 0o120600", { flags: 5, size: 0n, permissions: 0o120600 }],
    ["size 1", { flags: 5, size: 1n, permissions: 0o100600 }],
    ["flags without PERMISSIONS", { flags: 1, size: 0n }],
    ["flags without SIZE", { flags: 4, permissions: 0o100600 }],
  ])("a server that lies about the mode: %s", async (_case, attrs) => {
    const { peer, session, outcome } = await render({ faults: { fstat: { attrs } } });
    expect(outcome).toEqual({ written: "no", reason: "mode" });
    expect(types(session).slice(-3)).toEqual([TYPE.FSTAT, TYPE.CLOSE, TYPE.REMOVE]);
    expect(peer.entry(PATH)).toBeUndefined();
    expect(leftovers(peer)).toEqual([]);
  });

  it("FSTAT answered with a status", async () => {
    const { outcome } = await render({ faults: { fstat: { status: 4 } } });
    expect(outcome).toEqual({ written: "no", reason: "mode" });
  });
});

describe("step 5: the writes", () => {
  it("the second WRITE refused", async () => {
    const { peer, session, outcome } = await render({
      faults: { write: (n) => (n === 2 ? { status: 4 } : undefined) },
    });
    expect(outcome).toEqual({ written: "no", reason: "write" });
    expect(types(session).slice(-4)).toEqual([TYPE.WRITE, TYPE.WRITE, TYPE.CLOSE, TYPE.REMOVE]);
    expect(types(session).filter((type) => type === TYPE.WRITE)).toHaveLength(2);
    expect(peer.entry(PATH)).toBeUndefined();
    expect(leftovers(peer)).toEqual([]);
  });
});

describe("step 6: fsync", () => {
  it("fsync announced and answered OP_UNSUPPORTED", async () => {
    const { peer, session, outcome } = await render({ faults: { fsync: { status: 8 } } });
    expect(outcome).toEqual({ written: "no", reason: "write" });
    expect(types(session).slice(-3)).toEqual([TYPE.EXTENDED, TYPE.CLOSE, TYPE.REMOVE]);
    expect(renamed(session)).toBe(false);
    expect(leftovers(peer)).toEqual([]);
  });

  it("fsync refused", async () => {
    const { outcome } = await render({ faults: { fsync: { status: 4 } } });
    expect(outcome).toEqual({ written: "no", reason: "write" });
  });
});

describe("step 7: the close and the rename", () => {
  it("CLOSE refused", async () => {
    const { session, outcome } = await render({
      faults: { close: (n) => (n === 2 ? { status: 4 } : undefined) },
    });
    expect(outcome).toEqual({ written: "no", reason: "write" });
    expect(types(session).slice(-3)).toEqual([TYPE.EXTENDED, TYPE.CLOSE, TYPE.REMOVE]);
    expect(types(session).filter((type) => type === TYPE.CLOSE)).toHaveLength(2);
    expect(renamed(session)).toBe(false);
  });

  it.each([
    ["the rename refused", 4],
    ["the rename announced and answered OP_UNSUPPORTED", 8],
  ])("%s", async (_case, code) => {
    const { peer, session, outcome } = await render({
      faults: { "posix-rename": { status: code } },
    });
    expect(outcome).toEqual({ written: "no", reason: "rename" });
    expect(types(session).slice(-2)).toEqual([TYPE.EXTENDED, TYPE.REMOVE]);
    expect(pathsOf(session, TYPE.REMOVE)).toEqual([tempOf(session)]);
    expect(peer.entry(PATH)).toBeUndefined();
    expect(leftovers(peer)).toEqual([]);
  });

  it("a directory at the path", async () => {
    const { peer, outcome } = await render({ entries: { [PATH]: "dir" } });
    expect(outcome).toEqual({ written: "no", reason: "rename" });
    expect(peer.entry(PATH)?.kind).toBe("dir");
    expect(leftovers(peer)).toEqual([]);
  });

  it("onWritten says unconfirmed before the rename's frame and yes after its answer", async () => {
    const calls: [RenderWritten, number, number | undefined][] = [];
    const session = connect(createSftpPeer());
    const outcome = await writeRemoteFile(
      session,
      PATH,
      content,
      new AbortController().signal,
      (written) => {
        calls.push([written, session.requests.length, session.requests.at(-1)?.type]);
      },
    );
    expect(outcome).toEqual({ written: "yes" });
    expect(calls).toEqual([
      ["unconfirmed", 12, TYPE.CLOSE],
      ["yes", 13, TYPE.EXTENDED],
    ]);
  });

  it("a refused rename's last word to onWritten is no", async () => {
    const calls: RenderWritten[] = [];
    const { outcome } = await render(
      { faults: { "posix-rename": { status: 4 } } },
      PATH,
      (written) => {
        calls.push(written);
      },
    );
    expect(outcome).toEqual({ written: "no", reason: "rename" });
    expect(calls).toEqual(["unconfirmed", "no"]);
  });

  it("a second frame in the chunk of the rename's OK leaves the call written", async () => {
    const calls: RenderWritten[] = [];
    const { session, outcome } = await render(
      { faults: { "posix-rename": { frame: Buffer.concat([status(12, 0), status(12, 0)]) } } },
      PATH,
      (written) => {
        calls.push(written);
      },
    );
    expect(outcome).toStrictEqual({ written: "yes" });
    expect(calls).toEqual(["unconfirmed", "yes"]);
    expect(types(session)).toEqual(EVERY_REQUEST);
  });

  it("a callback that throws on yes leaves the call written", async () => {
    const calls: RenderWritten[] = [];
    const { peer, session, outcome } = await render({}, PATH, (written) => {
      calls.push(written);
      if (written === "yes") throw new Error("the caller's callback fails");
    });
    expect(outcome).toStrictEqual({ written: "yes" });
    expect(calls).toEqual(["unconfirmed", "yes"]);
    expect(types(session)).toEqual(EVERY_REQUEST);
    expect(peer.entry(PATH)?.data.equals(copy)).toBe(true);
  });

  it("an abort between CLOSE's answer and the rename hands on no rename frame", async () => {
    const peer = createSftpPeer();
    const session = connect(peer);
    const controller = new AbortController();
    const calls: RenderWritten[] = [];
    const channel: SftpChannel = {
      write: (chunk) => session.write(chunk),
      onData: (consumer) => {
        session.onData((chunk) => {
          consumer(chunk);
          if (types(session).filter((type) => type === TYPE.CLOSE).length === 2) {
            controller.abort("ended");
          }
        });
      },
    };
    const outcome = await writeRemoteFile(channel, PATH, content, controller.signal, (written) => {
      calls.push(written);
    });
    await flushed();
    expect(outcome).toEqual({ written: "no", reason: "write" });
    expect(types(session)).toEqual(EVERY_REQUEST.slice(0, -1));
    expect(calls).toEqual([]);
    expect(peer.entry(PATH)).toBeUndefined();
  });
});

describe("step 8: the cleanup", () => {
  it("a cleanup CLOSE that fails still removes", async () => {
    const { session, outcome } = await render({
      faults: {
        fsetstat: { status: 3 },
        close: (n) => (n === 2 ? { status: 4 } : undefined),
      },
    });
    expect(outcome).toEqual({ written: "no", reason: "mode" });
    expect(types(session).slice(-3)).toEqual([TYPE.FSETSTAT, TYPE.CLOSE, TYPE.REMOVE]);
  });

  it("a cleanup REMOVE that fails changes nothing", async () => {
    const { peer, session, outcome } = await render({
      faults: { fsetstat: { status: 3 }, remove: { status: 3 } },
    });
    expect(outcome).toEqual({ written: "no", reason: "mode" });
    expect(types(session).slice(-3)).toEqual([TYPE.FSETSTAT, TYPE.CLOSE, TYPE.REMOVE]);
    expect(leftovers(peer)).toHaveLength(1);
  });

  it("a protocol fault in the cleanup ends it", async () => {
    const { session, outcome } = await render({
      faults: {
        fsetstat: { status: 3 },
        close: (n) => (n === 2 ? { frame: status(999, 0) } : undefined),
      },
    });
    expect(outcome).toEqual({ written: "no", reason: "mode" });
    expect(types(session).slice(-2)).toEqual([TYPE.FSETSTAT, TYPE.CLOSE]);
  });
});

describe("the bounds", () => {
  it("an unknown reply type", async () => {
    const { session, outcome } = await render({ faults: { open: { frame: sftpFrame(99, 4) } } });
    expect(outcome).toEqual({ written: "no", reason: "protocol" });
    expect(types(session)).toEqual([1, 11, 12, 4, 3]);
  });

  it.each<[string, SftpPeerFaults, number]>([
    [
      "DATA to WRITE",
      { write: (n) => (n === 1 ? { frame: sftpFrame(103, 7, "data") } : undefined) },
      TYPE.WRITE,
    ],
    ["HANDLE to FSETSTAT", { fsetstat: { frame: sftpFrame(102, 5, "h") } }, TYPE.FSETSTAT],
    [
      "ATTRS to the file's CLOSE",
      { close: (n) => (n === 2 ? { frame: sftpFrame(105, 11, 0) } : undefined) },
      TYPE.CLOSE,
    ],
  ])("a type the request does not take: %s", async (_case, faults, last) => {
    const { session, outcome } = await render({ faults });
    expect(outcome).toEqual({ written: "no", reason: "protocol" });
    expect(types(session).at(-1)).toBe(last);
  });

  it("a wrong request id to FSTAT", async () => {
    const { session, outcome } = await render({
      faults: { fstat: { frame: sftpFrame(105, 999, 5, 0n, 0o100600) } },
    });
    expect(outcome).toEqual({ written: "no", reason: "protocol" });
    expect(types(session).at(-1)).toBe(TYPE.FSTAT);
  });

  it("a wrong request id to the rename", async () => {
    const { session, outcome } = await render({
      faults: { "posix-rename": { frame: status(999, 0) } },
    });
    expect(outcome).toEqual({ written: "unconfirmed", reason: "protocol" });
    expect(types(session)).toEqual(EVERY_REQUEST);
  });

  it("a second reply to one request", async () => {
    const { session, outcome } = await render({
      faults: {
        write: (n) =>
          n === 1 ? { frame: Buffer.concat([status(7, 0), status(7, 0)]) } : undefined,
      },
    });
    expect(outcome).toEqual({ written: "no", reason: "protocol" });
    expect(types(session).at(-1)).toBe(TYPE.WRITE);
    expect(types(session).filter((type) => type === TYPE.WRITE)).toHaveLength(1);
  });

  it("a reply over 262 144 bytes", async () => {
    const { session, outcome } = await render({
      faults: {
        write: (n) =>
          n === 1 ? { frame: sftpFrame(101, 7, 0, "x".repeat(262_128), "") } : undefined,
      },
    });
    expect(outcome).toEqual({ written: "no", reason: "protocol" });
    expect(types(session).at(-1)).toBe(TYPE.WRITE);
  });

  it("a channel whose write rejects ends the call", async () => {
    const session = connect(createSftpPeer());
    const handed: number[] = [];
    const channel: SftpChannel = {
      write: (chunk) => {
        const type = chunk.readUInt8(4);
        handed.push(type);
        if (type !== TYPE.WRITE) return session.write(chunk);
        chunk.fill(0);
        return Promise.reject(new Error("the pipe is gone"));
      },
      onData: (consumer) => {
        session.onData(consumer);
      },
    };
    const outcome = await writeRemoteFile(channel, PATH, content, new AbortController().signal);
    await flushed();
    expect(outcome).toEqual({ written: "no", reason: "protocol" });
    expect(handed).toEqual([1, 11, 12, 4, 3, 10, 8, 6]);
    expect(types(session)).toEqual([1, 11, 12, 4, 3, 10, 8]);
  });
});

describe("the signal", () => {
  it.each([
    ["ended", "connect"],
    ["timeout", "timeout"],
  ])("aborted before the call (%s)", async (why, reason) => {
    const peer = createSftpPeer();
    const session = connect(peer);
    const controller = new AbortController();
    controller.abort(why);
    const outcome = await writeRemoteFile(session, PATH, content, controller.signal);
    await flushed();
    expect(outcome).toEqual({ written: "no", reason });
    expect(session.requests).toEqual([]);
  });

  const WAITS: [string, SftpPeerRequest, number, RenderFailureReason, RenderWritten][] = [
    ["init", "init", 1, "connect", "no"],
    ["opendir", "opendir", 1, "connect", "no"],
    ["open", "open", 1, "open", "no"],
    ["fsetstat", "fsetstat", 1, "mode", "no"],
    ["write", "write", 1, "write", "no"],
    ["fsync", "fsync", 1, "write", "no"],
    ["the file's close", "close", 2, "write", "no"],
    ["posix-rename", "posix-rename", 1, "rename", "unconfirmed"],
  ];

  async function silentAt(
    kind: SftpPeerRequest,
    ordinal: number,
    why: "ended" | "timeout",
    extra: SftpPeerFaults = {},
  ): Promise<{ session: SftpPeerSession; outcome: unknown; after: number }> {
    const reached = deferred();
    const faults: SftpPeerFaults = { ...extra };
    faults[kind] = (n) => {
      if (n !== ordinal) return undefined;
      reached.resolve();
      return "silent";
    };
    const session = connect(createSftpPeer({ faults }));
    const controller = new AbortController();
    const pending = writeRemoteFile(session, PATH, content, controller.signal);
    await reached.promise;
    const before = session.requests.length;
    controller.abort(why);
    const outcome = await settledNow(pending);
    await flushed();
    return { session, outcome, after: session.requests.length - before };
  }

  it.each(WAITS)(
    "the wait at %s ends with the signal",
    async (_case, kind, at, reason, written) => {
      const { outcome, after } = await silentAt(kind, at, "ended");
      expect(outcome).toEqual({ written, reason });
      expect(after).toBe(0);
    },
  );

  it.each(WAITS)(
    "the wait at %s ends with the signal timeout",
    async (_case, kind, at, _r, written) => {
      const { outcome, after } = await silentAt(kind, at, "timeout");
      expect(outcome).toEqual({ written, reason: "timeout" });
      expect(after).toBe(0);
    },
  );

  it("a signal in the cleanup keeps the failure's reason", async () => {
    const { session, outcome, after } = await silentAt("close", 2, "timeout", {
      fsetstat: { status: 3 },
    });
    expect(outcome).toEqual({ written: "no", reason: "mode" });
    expect(after).toBe(0);
    expect(types(session).slice(-2)).toEqual([TYPE.FSETSTAT, TYPE.CLOSE]);
  });
});

describe("two writers", () => {
  it("two writers on one peer, neither publishes the other's bytes", async () => {
    const reached = deferred();
    const hold = deferred();
    const peer = createSftpPeer({
      faults: {
        write: (n) => {
          if (n !== 1) return undefined;
          reached.resolve();
          return { hold: hold.promise };
        },
      },
    });
    const sessionB = connect(peer);
    const contentB = draw(70_000);
    const b = writeRemoteFile(sessionB, PATH, contentB, new AbortController().signal);
    await reached.promise;
    const sessionA = connect(peer);
    const a = await writeRemoteFile(sessionA, PATH, content, new AbortController().signal);
    expect(a).toEqual({ written: "yes" });
    expect(pathsOf(sessionA, TYPE.REMOVE)).toEqual([tempOf(sessionB)]);
    hold.resolve();
    expect(await b).toEqual({ written: "no", reason: "rename" });
    expect(peer.entry(PATH)?.data.equals(copy)).toBe(true);
  });
});

it("the writer reads no file", () => {
  const sent = new Set([1, 3, 4, 6, 8, 10, 11, 12, 13, 200]);
  expect(SESSIONS.length).toBeGreaterThan(0);
  expect(SESSIONS.flatMap(types).filter((type) => !sent.has(type))).toEqual([]);
});
