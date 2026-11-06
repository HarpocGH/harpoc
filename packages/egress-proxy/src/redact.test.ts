import { once } from "node:events";
import { describe, expect, it } from "vitest";
import { redactSecretEncodings } from "@harpoc/core";
import { REDACTION_MARKER, createRedactingTransform, redactBytes } from "./redact.js";

const NEEDLE = "ghp_S3cr3tValue-xyz";
const MARK = REDACTION_MARKER;

async function redact(
  chunks: readonly (Buffer | string)[],
  needles: readonly (Uint8Array | string)[],
): Promise<{ output: Buffer; changed: boolean }> {
  const transform = createRedactingTransform(
    needles.map((needle) => (typeof needle === "string" ? Buffer.from(needle) : needle)),
  );
  const pieces: Buffer[] = [];
  transform.on("data", (piece: Buffer) => pieces.push(piece));
  const ended = once(transform, "end");
  for (const chunk of chunks) {
    transform.write(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  transform.end();
  await ended;
  return { output: Buffer.concat(pieces), changed: transform.changed };
}

/** The whole-body reference: one leftmost-longest regex pass over the bytes (latin1 maps each byte to one code unit). */
function reference(body: Buffer, needles: readonly Buffer[]): Buffer {
  const alternatives = needles
    .filter((needle) => needle.length > 0)
    .map((needle) => needle.toString("latin1"))
    .sort((a, b) => b.length - a.length)
    .map((needle) => needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  if (alternatives.length === 0) return body;
  const pattern = new RegExp(alternatives.join("|"), "g");
  return Buffer.from(body.toString("latin1").replace(pattern, MARK), "latin1");
}

function xorshift(seed: number): () => number {
  let x = seed;
  return () => {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    return x >>> 0;
  };
}

describe("createRedactingTransform — exact-value redaction of a response stream (DB-8)", () => {
  it("replaces with the project's marker, the string core's redactSecretEncodings writes", () => {
    expect(redactSecretEncodings("s3cr3t-token", "s3cr3t-token")).toBe(MARK);
  });

  it("a needle wholly inside one chunk", async () => {
    const result = await redact([`{"token":"${NEEDLE}"}`], [NEEDLE]);
    expect(result.output.toString()).toBe(`{"token":"${MARK}"}`);
    expect(result.changed).toBe(true);
  });

  it.each(Array.from({ length: NEEDLE.length - 1 }, (_, i) => i + 1))(
    "a needle split across two chunks after byte %i",
    async (offset) => {
      const result = await redact(
        [`before ${NEEDLE.slice(0, offset)}`, `${NEEDLE.slice(offset)} after`],
        [NEEDLE],
      );
      expect(result.output.toString()).toBe(`before ${MARK} after`);
      expect(result.changed).toBe(true);
    },
  );

  it("a needle split across three chunks, each shorter than the needle", async () => {
    const body = `<${NEEDLE}>`;
    const chunks = [body.slice(0, 7), body.slice(7, 14), body.slice(14)];
    expect((await redact(chunks, [NEEDLE])).output.toString()).toBe(`<${MARK}>`);
  });

  it("a needle written one byte at a time", async () => {
    const body = `x${NEEDLE}y${NEEDLE}`;
    expect((await redact([...body], [NEEDLE])).output.toString()).toBe(`x${MARK}y${MARK}`);
  });

  it("two occurrences in one chunk", async () => {
    const result = await redact([`a ${NEEDLE} b ${NEEDLE} c`], [NEEDLE]);
    expect(result.output.toString()).toBe(`a ${MARK} b ${MARK} c`);
  });

  it("back-to-back occurrences are two markers", async () => {
    const result = await redact([`${NEEDLE}${NEEDLE}`], [NEEDLE]);
    expect(result.output.toString()).toBe(`${MARK}${MARK}`);
  });

  it("a needle at the very end is redacted by the flush", async () => {
    const result = await redact(["0123456789", `ok ${NEEDLE}`], [NEEDLE]);
    expect(result.output.toString()).toBe(`0123456789ok ${MARK}`);
  });

  it("a needle that is the whole body", async () => {
    expect((await redact([NEEDLE], [NEEDLE])).output.toString()).toBe(MARK);
  });

  it("a needle's prefix at the end of the body is flushed as sent", async () => {
    const body = `tail ${NEEDLE.slice(0, 12)}`;
    const result = await redact([body.slice(0, 8), body.slice(8)], [NEEDLE]);
    expect(result.output.toString()).toBe(body);
    expect(result.changed).toBe(false);
  });

  it("the basic-auth base64 needle beside the raw value in one body", async () => {
    const encoded = Buffer.from(`x-access-token:${NEEDLE}`).toString("base64");
    const result = await redact(
      [`{"echo":"Basic ${encoded}","raw":"`, `${NEEDLE}"}`],
      [NEEDLE, encoded],
    );
    expect(result.output.toString()).toBe(`{"echo":"Basic ${MARK}","raw":"${MARK}"}`);
  });

  it("no occurrence: the bytes pass unchanged and changed stays false", async () => {
    const body = Buffer.from(`{"login":"octocat","id":1}`);
    const result = await redact([body.subarray(0, 5), body.subarray(5)], [NEEDLE]);
    expect(result.output.equals(body)).toBe(true);
    expect(result.changed).toBe(false);
  });

  it("an empty body", async () => {
    const result = await redact([], [NEEDLE]);
    expect(result.output.length).toBe(0);
    expect(result.changed).toBe(false);
  });

  it("no needles: an identity pass-through", async () => {
    const result = await redact(["abc", NEEDLE], []);
    expect(result.output.toString()).toBe(`abc${NEEDLE}`);
    expect(result.changed).toBe(false);
  });

  it("an empty needle is dropped: a zero-length value redacts nothing", async () => {
    const result = await redact(["abc"], [new Uint8Array(0)]);
    expect(result.output.toString()).toBe("abc");
    expect(result.changed).toBe(false);
  });

  it("the marker itself in the body is left as sent", async () => {
    const result = await redact([`already ${MARK} here`], [NEEDLE]);
    expect(result.output.toString()).toBe(`already ${MARK} here`);
    expect(result.changed).toBe(false);
  });

  it.each([
    ["the longest needle at one position", ["ab", "abc"], "xabcx", `x${MARK}x`],
    ["the leftmost match first", ["abc", "cde"], "abcde", `${MARK}de`],
    ["a longer needle that starts earlier", ["bcd", "abcde"], "abcdef", `${MARK}f`],
    ["one needle overlapping itself", ["aa"], "aaaaa", `${MARK}${MARK}a`],
  ])("overlapping needles: %s", async (_label, needles, body, expected) => {
    const result = await redact([body.slice(0, 2), body.slice(2)], needles);
    expect(result.output.toString()).toBe(expected);
    expect(
      result.output.equals(
        reference(
          Buffer.from(body),
          needles.map((n) => Buffer.from(n)),
        ),
      ),
    ).toBe(true);
  });

  it("a multibyte UTF-8 needle split inside a code point", async () => {
    const needle = Buffer.from("pässwörd-🔑");
    const body = Buffer.concat([Buffer.from("«"), needle, Buffer.from("»")]);
    const result = await redact([body.subarray(0, 4), body.subarray(4)], [needle]);
    expect(result.output.toString()).toBe(`«${MARK}»`);
  });

  it("a needle among arbitrary binary bytes, split mid-needle", async () => {
    const needle = Buffer.from([0x00, 0xff, 0x10, 0x80, 0x7f]);
    const body = Buffer.from([0xfe, 0x00, 0xff, 0x10, 0x80, 0x7f, 0x01]);
    const result = await redact([body.subarray(0, 3), body.subarray(3)], [needle]);
    expect(
      result.output.equals(
        Buffer.concat([Buffer.from([0xfe]), Buffer.from(MARK), Buffer.from([0x01])]),
      ),
    ).toBe(true);
  });

  it("a 1 MiB body in random chunks equals the whole-body reference", async () => {
    const next = xorshift(0x5eed_b2);
    const encoded = Buffer.from(Buffer.from(`user:${NEEDLE}`).toString("base64"));
    const needles = [Buffer.from(NEEDLE), encoded];
    const body = Buffer.alloc(1024 * 1024);
    for (let i = 0; i < body.length; i++) body[i] = 0x20 + (next() % 95);
    for (let k = 0; k < 40; k++) {
      const needle = needles[k % 2] as Buffer;
      needle.copy(body, next() % (body.length - needle.length));
    }
    const chunks: Buffer[] = [];
    for (let at = 0; at < body.length;) {
      const size = 1 + (next() % 65_536);
      chunks.push(body.subarray(at, at + size));
      at += size;
    }
    const result = await redact(chunks, needles);
    expect(result.output.equals(reference(body, needles))).toBe(true);
    expect(result.changed).toBe(true);
  });

  it("streaming: each write emits all but the last maxNeedleLength − 1 bytes at once", async () => {
    const transform = createRedactingTransform([Buffer.from(NEEDLE), Buffer.from("short")]);
    const first = once(transform, "data");
    transform.write(Buffer.alloc(100, 0x61));
    const [piece] = (await first) as [Buffer];
    expect(piece.length).toBe(100 - (NEEDLE.length - 1));
    const ended = once(transform, "end");
    transform.end();
    await ended;
  });

  it("the caller may wipe its needles once the transform exists: it redacts with its own copies", async () => {
    const needle = Buffer.from(NEEDLE);
    const transform = createRedactingTransform([needle]);
    needle.fill(0);
    const pieces: Buffer[] = [];
    transform.on("data", (piece: Buffer) => pieces.push(piece));
    const ended = once(transform, "end");
    transform.end(Buffer.concat([Buffer.alloc(32), Buffer.from(NEEDLE)]));
    await ended;
    expect(Buffer.concat(pieces).equals(Buffer.concat([Buffer.alloc(32), Buffer.from(MARK)]))).toBe(
      true,
    );
  });
});

describe("redactBytes — the same match over one complete value (a response header)", () => {
  it.each([
    [`https://192.0.2.10/cb?token=${NEEDLE}`, `https://192.0.2.10/cb?token=${MARK}`, true],
    ["https://192.0.2.10/cb?token=other", "https://192.0.2.10/cb?token=other", false],
  ])("%s", (value, expected, changed) => {
    const result = redactBytes(Buffer.from(value), [Buffer.from(NEEDLE)]);
    expect(result.output.toString()).toBe(expected);
    expect(result.changed).toBe(changed);
  });
});
