import { once } from "node:events";
import { setImmediate } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import { redactSecretEncodings } from "@harpoc/core";
import { REDACTION_MARKER, createRedactingTransform, redactBytes } from "./redact.js";
import { expectAbsent } from "@harpoc/test-utils";

const NEEDLE = "ghp_S3cr3tValue-xyz";
const MARK = REDACTION_MARKER;
const SECRET_TOKEN = "s3cr3t-token";
const MULTIBYTE_NEEDLE = "pässwörd-🔑";
const SSE_NEEDLE = "SECRET";
const END = Symbol("end");

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

/** Writes each step, or ends the stream at `END`, and records the piece each step emits (`null`: none) and the whole output as text. */
async function stepwise(
  needles: readonly string[],
  steps: readonly (string | typeof END)[],
): Promise<{ pieces: (string | null)[]; text: string; changed: boolean }> {
  const transform = createRedactingTransform(needles.map((needle) => Buffer.from(needle)));
  const emitted: Buffer[] = [];
  const output: Buffer[] = [];
  transform.on("data", (piece: Buffer) => {
    emitted.push(piece);
    output.push(piece);
  });
  const pieces: (string | null)[] = [];
  for (const step of steps) {
    if (step === END) {
      const ended = once(transform, "end");
      transform.end();
      await ended;
    } else {
      await new Promise<void>((resolve, reject) => {
        transform.write(Buffer.from(step), (err) => (err ? reject(err) : resolve()));
      });
      await setImmediate();
    }
    expect(emitted.length).toBeLessThanOrEqual(1);
    pieces.push(emitted.length === 0 ? null : (emitted.shift() as Buffer).toString());
  }
  transform.destroy();
  return { pieces, text: Buffer.concat(output).toString(), changed: transform.changed };
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
    const redacted = redactSecretEncodings(SECRET_TOKEN, SECRET_TOKEN);
    expectAbsent(redacted, SECRET_TOKEN);
    expect(redacted).toBe(MARK);
  });

  it("a needle wholly inside one chunk", async () => {
    const result = await redact([`{"token":"${NEEDLE}"}`], [NEEDLE]);
    expectAbsent(result.output.toString(), NEEDLE);
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
      expectAbsent(result.output.toString(), NEEDLE);
      expect(result.output.toString()).toBe(`before ${MARK} after`);
      expect(result.changed).toBe(true);
    },
  );

  it("a needle split across three chunks, each shorter than the needle", async () => {
    const body = `<${NEEDLE}>`;
    const chunks = [body.slice(0, 7), body.slice(7, 14), body.slice(14)];
    const redacted = (await redact(chunks, [NEEDLE])).output.toString();
    expectAbsent(redacted, NEEDLE);
    expect(redacted).toBe(`<${MARK}>`);
  });

  it("a needle written one byte at a time", async () => {
    const body = `x${NEEDLE}y${NEEDLE}`;
    const redacted = (await redact([...body], [NEEDLE])).output.toString();
    expectAbsent(redacted, NEEDLE);
    expect(redacted).toBe(`x${MARK}y${MARK}`);
  });

  it("two occurrences in one chunk", async () => {
    const result = await redact([`a ${NEEDLE} b ${NEEDLE} c`], [NEEDLE]);
    expectAbsent(result.output.toString(), NEEDLE);
    expect(result.output.toString()).toBe(`a ${MARK} b ${MARK} c`);
  });

  it("back-to-back occurrences are two markers", async () => {
    const result = await redact([`${NEEDLE}${NEEDLE}`], [NEEDLE]);
    expectAbsent(result.output.toString(), NEEDLE);
    expect(result.output.toString()).toBe(`${MARK}${MARK}`);
  });

  it("a needle at the very end is redacted by the flush", async () => {
    const result = await redact(["0123456789", `ok ${NEEDLE}`], [NEEDLE]);
    expectAbsent(result.output.toString(), NEEDLE);
    expect(result.output.toString()).toBe(`0123456789ok ${MARK}`);
  });

  it("a needle that is the whole body", async () => {
    const redacted = (await redact([NEEDLE], [NEEDLE])).output.toString();
    expectAbsent(redacted, NEEDLE);
    expect(redacted).toBe(MARK);
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
    expectAbsent(result.output.toString(), NEEDLE);
    expectAbsent(result.output.toString(), encoded);
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
    const needle = Buffer.from(MULTIBYTE_NEEDLE);
    const body = Buffer.concat([Buffer.from("«"), needle, Buffer.from("»")]);
    const result = await redact([body.subarray(0, 4), body.subarray(4)], [needle]);
    expectAbsent(result.output.toString(), MULTIBYTE_NEEDLE);
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

  it("a 1 MiB body with line feeds in random splits equals the whole-body reference", async () => {
    const next = xorshift(0x0a_5eed_b2);
    const encoded = Buffer.from(Buffer.from(`user:${NEEDLE}`).toString("base64"));
    const needles = [Buffer.from(NEEDLE), encoded];
    const body = Buffer.alloc(1024 * 1024);
    for (let i = 0; i < body.length; i++) {
      body[i] = next() % 64 === 0 ? 0x0a : 0x20 + (next() % 95);
    }
    for (let k = 0; k < 400; k++) {
      const needle = needles[k % 2] as Buffer;
      needle.copy(body, next() % (body.length - needle.length));
    }
    const chunks: Buffer[] = [];
    for (let at = 0; at < body.length;) {
      const size = 1 + (next() % 1024);
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

  it.each<[string, string[], (string | typeof END)[], (string | null)[]]>([
    [
      "a needle split over three writes after a line feed",
      [SSE_NEEDLE],
      [`ab\n${SSE_NEEDLE.slice(0, 2)}`, SSE_NEEDLE.slice(2, 4), `${SSE_NEEDLE.slice(4)}\ncd`, END],
      ["ab\n", null, `${MARK}\n`, "cd"],
    ],
    [
      "a longer needle that starts earlier, held after the line feed",
      ["bcd", "abcde"],
      ["x\nabcd", "ef", END],
      ["x\n", MARK, "f"],
    ],
    [
      "a needle that is the beginning of another, ended by a line feed",
      ["tok", "token"],
      ["a\ntok", "en\n"],
      ["a\n", `${MARK}\n`],
    ],
    [
      "server-sent events leave whole, each with its blank line",
      [SSE_NEEDLE],
      ["data: 1\n\n", ": ping\n\n", `data: ${SSE_NEEDLE}\n\n`],
      ["data: 1\n\n", ": ping\n\n", `data: ${MARK}\n\n`],
    ],
    [
      "a match across the fixed carry's edge is replaced whole and none of it held",
      [SSE_NEEDLE],
      [`a\nxxxxx${SSE_NEEDLE}y`, END],
      [`a\nxxxxx${MARK}`, "y"],
    ],
    [
      "a needle that holds a line feed keeps the fixed carry",
      ["X\nY"],
      ["aX\n", "Yb", END],
      ["a", MARK, "b"],
    ],
    [
      "CRLF line ends: a needle before the last line feed is redacted and nothing held",
      [SSE_NEEDLE],
      [`a\r\n${SSE_NEEDLE}\r\n`],
      [`a\r\n${MARK}\r\n`],
    ],
    [
      "a carriage return releases nothing: a needle that holds one keeps the fixed carry across it",
      ["X\rY"],
      ["aX\r", "Yb", END],
      ["a", MARK, "b"],
    ],
  ])("release at the line feed: %s", async (_label, needles, steps, expected) => {
    const result = await stepwise(needles, steps);
    for (const needle of needles) expectAbsent(result.text, needle);
    expect(result.pieces).toEqual(expected);
    expect(result.changed).toBe(true);
  });

  it.each<[string, string[], (string | typeof END)[], (string | null)[]]>([
    [
      "a needle that holds a line feed keeps the fixed carry for every needle",
      [SSE_NEEDLE, "X\nY"],
      ["data: 1\n\n"],
      ["data"],
    ],
    [
      "a needle's prefix after the line feed is held, then flushed as sent",
      [SSE_NEEDLE],
      [`x\n${SSE_NEEDLE.slice(0, 5)}`, END],
      ["x\n", SSE_NEEDLE.slice(0, 5)],
    ],
    [
      "a body whose only line feed is its last byte leaves whole",
      [SSE_NEEDLE],
      ["abc\n"],
      ["abc\n"],
    ],
  ])(
    "release at the line feed, nothing to redact: %s",
    async (_label, needles, steps, expected) => {
      const result = await stepwise(needles, steps);
      expect(result.pieces).toEqual(expected);
      expect(result.changed).toBe(false);
    },
  );

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
    [
      "a URL whose token is the needle",
      `https://192.0.2.10/cb?token=${NEEDLE}`,
      `https://192.0.2.10/cb?token=${MARK}`,
      true,
    ],
    [
      "a URL whose token is another value",
      "https://192.0.2.10/cb?token=other",
      "https://192.0.2.10/cb?token=other",
      false,
    ],
  ])("%s", (_label, value, expected, changed) => {
    const result = redactBytes(Buffer.from(value), [Buffer.from(NEEDLE)]);
    expectAbsent(result.output.toString(), NEEDLE);
    expect(result.output.toString()).toBe(expected);
    expect(result.changed).toBe(changed);
  });
});
