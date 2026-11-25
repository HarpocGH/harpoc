import { describe, expect, it, vi } from "vitest";
import {
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
} from "./sftp-wire.js";

const H = Buffer.from("h");

function hex(text: string): string {
  return Buffer.from(text, "utf8").toString("hex");
}

function u32(value: number): Buffer {
  const word = Buffer.alloc(4);
  word.writeUInt32BE(value >>> 0);
  return word;
}

function u64(value: bigint): Buffer {
  const wide = Buffer.alloc(8);
  wide.writeBigUInt64BE(value);
  return wide;
}

function str(data: string | Buffer): Buffer {
  const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return Buffer.concat([u32(bytes.length), bytes]);
}

/** A reply as `decodeReply` takes it: the type byte and the payload. */
function reply(type: number, ...fields: Buffer[]): Buffer {
  return Buffer.concat([Buffer.from([type]), ...fields]);
}

/** A reply with its length field, as it arrives on the stream. */
function framed(body: Buffer): Buffer {
  return Buffer.concat([u32(body.length), body]);
}

describe("the request frames", () => {
  it("the request frames, letter for letter", () => {
    expect(encodeInit().toString("hex")).toBe("000000050100000003");
    expect(encodeOpen(1, "/x", 0x2a, 0o600).toString("hex")).toBe(
      "000000170300000001000000022f780000002a0000000400000180",
    );
    expect(encodeFsetstat(3, H, 0o600).toString("hex")).toBe(
      "000000120a0000000300000001680000000400000180",
    );
    expect(encodeFstat(4, H).toString("hex")).toBe("0000000a08000000040000000168");
    expect(encodeClose(6, H).toString("hex")).toBe("0000000a04000000060000000168");
    expect(encodeRemove(7, "/x").toString("hex")).toBe("0000000b0d00000007000000022f78");
    expect(encodeOpendir(8, "/").toString("hex")).toBe("0000000a0b00000008000000012f");
    expect(encodeReaddir(9, H).toString("hex")).toBe("0000000a0c000000090000000168");
    expect(encodePosixRename(10, "/a", "/b").toString("hex")).toBe(
      `0000002dc80000000a00000018${hex("posix-rename@openssh.com")}000000022f61000000022f62`,
    );
    expect(encodeFsync(11, H).toString("hex")).toBe(
      `0000001fc80000000b00000011${hex("fsync@openssh.com")}0000000168`,
    );
    expect(encodeWrite(5, H, 32_768, Buffer.from("ab")).toString("hex")).toBe(
      "00000018060000000500000001680000000000008000000000026162",
    );
  });

  it("encodeWrite holds the chunk in one frame it allocates", () => {
    const chunk = Buffer.alloc(32_768);
    for (let at = 0; at < chunk.length; at++) chunk[at] = at % 251;
    const concat = vi.spyOn(Buffer, "concat");
    let frame: Buffer;
    try {
      frame = encodeWrite(5, H, 0, chunk);
      expect(concat).not.toHaveBeenCalled();
    } finally {
      concat.mockRestore();
    }
    expect(frame.length).toBe(32_794);
    expect(frame.subarray(-32_768).equals(chunk)).toBe(true);
  });
});

describe("decodeReply", () => {
  it("decodes the five replies", () => {
    expect(
      decodeReply(
        reply(
          2,
          u32(3),
          str("posix-rename@openssh.com"),
          str("1"),
          str("fsync@openssh.com"),
          str("1"),
        ),
      ),
    ).toEqual({
      type: 2,
      version: 3,
      extensions: [
        ["posix-rename@openssh.com", "1"],
        ["fsync@openssh.com", "1"],
      ],
    });
    expect(decodeReply(reply(101, u32(7), u32(4), str("failure"), str("en")))).toEqual({
      type: 101,
      id: 7,
      code: 4,
    });
    expect(decodeReply(reply(101, u32(7), u32(1)))).toEqual({ type: 101, id: 7, code: 1 });
    const handle = Buffer.alloc(256, 0x68);
    expect(decodeReply(reply(102, u32(2), str(handle)))).toEqual({ type: 102, id: 2, handle });
    const everyFlag = Buffer.concat([
      u32(0x8000000f),
      u64(12n),
      u32(1000),
      u32(1000),
      u32(0o100600),
      u32(1),
      u32(2),
      u32(2),
      str("a@example.com"),
      str("x"),
      str("b@example.com"),
      str(""),
    ]);
    expect(
      decodeReply(
        reply(104, u32(3), u32(2), str("one"), str(""), u32(0), str("two"), str("-rw"), everyFlag),
      ),
    ).toEqual({ type: 104, id: 3, names: [Buffer.from("one"), Buffer.from("two")] });
    expect(decodeReply(reply(105, u32(4), u32(5), u64(0n), u32(0o100600)))).toEqual({
      type: 105,
      id: 4,
      attrs: { flags: 5, size: 0n, permissions: 0o100600 },
    });
  });

  it.each([
    ["a HANDLE of 257 bytes", reply(102, u32(1), str(Buffer.alloc(257, 0x68)))],
    ["a HANDLE with one byte more", reply(102, u32(1), str("h"), Buffer.from([0]))],
    ["a VERSION whose last pair has no data", reply(2, u32(3), str("a"), str("1"), str("b"))],
    [
      "a NAME whose count exceeds its entries",
      reply(104, u32(1), u32(2), str("a"), str(""), u32(0)),
    ],
    ["ATTRS with flag 0x10", reply(105, u32(1), u32(0x10), u32(0))],
    [
      "ATTRS whose extended count exceeds its pairs",
      reply(105, u32(1), u32(0x80000000), u32(2), str("t"), str("d")),
    ],
    ["a STATUS of 7 payload bytes", reply(101, u32(1), Buffer.from([0, 0, 0]))],
    ["type 1", reply(1, u32(3))],
    ["type 99", reply(99, u32(1))],
    ["type 103", reply(103, u32(1), str("data"))],
    ["type 201", reply(201, u32(1))],
    ["an empty frame", Buffer.alloc(0)],
  ])("refuses %s", (_case, frame) => {
    expect(decodeReply(frame)).toBeNull();
  });
});

describe("packetReader", () => {
  it("the reader reassembles", () => {
    const first = reply(101, u32(1), u32(0));
    const second = reply(102, u32(2), str("h"));
    const bytes = framed(first);

    const single = packetReader();
    for (let at = 0; at < bytes.length - 1; at++) {
      expect(single.push(bytes.subarray(at, at + 1))).toEqual([]);
    }
    expect(single.push(bytes.subarray(-1))).toEqual([first]);

    const both = Buffer.concat([framed(first), framed(second)]);
    expect(packetReader().push(both)).toEqual([first, second]);

    const split = packetReader();
    const cut = framed(first).length + 5;
    const head = Buffer.from(both.subarray(0, cut));
    const frames = split.push(head);
    expect(frames).toEqual([first]);
    head.fill(0);
    expect(frames).toEqual([first]);
    expect(split.push(both.subarray(cut))).toEqual([second]);
  });

  it("the reader joins a frame once, from copies of what was pushed", () => {
    const body = Buffer.alloc(4_096);
    for (let at = 0; at < body.length; at++) body[at] = at % 251;
    const bytes = framed(body);
    const reader = packetReader();
    const frames: Buffer[] = [];
    const joins = vi.spyOn(Buffer, "concat");
    try {
      for (let at = 0; at < bytes.length; at++) {
        const one = Buffer.from(bytes.subarray(at, at + 1));
        frames.push(...(reader.push(one) ?? []));
        one.fill(0);
      }
      expect(joins.mock.calls.length).toBeLessThanOrEqual(2);
    } finally {
      joins.mockRestore();
    }
    expect(frames).toHaveLength(1);
    expect((frames[0] as Buffer).equals(body)).toBe(true);
  });

  it("the reader's bound", () => {
    const largest = packetReader();
    expect(largest.push(u32(262_144))).toEqual([]);
    const body = Buffer.alloc(262_144, 0x61);
    expect(largest.push(body)).toEqual([body]);

    const over = packetReader();
    const length = u32(262_145);
    expect(over.push(length.subarray(0, 1))).toEqual([]);
    expect(over.push(length.subarray(1, 2))).toEqual([]);
    expect(over.push(length.subarray(2, 3))).toEqual([]);
    expect(over.push(length.subarray(3, 4))).toBeNull();
    expect(over.push(framed(reply(101, u32(1), u32(0))))).toBeNull();

    const empty = packetReader();
    expect(empty.push(u32(0))).toBeNull();
    expect(empty.push(framed(reply(101, u32(1), u32(0))))).toBeNull();
  });
});
