import { describe, expect, it } from "vitest";
import { contentLengthExceeds, readBodyCapped } from "./http-body.js";

function streamOf(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
}

describe("contentLengthExceeds", () => {
  it("is false when the header is absent or unparseable", () => {
    expect(contentLengthExceeds(new Headers(), 10)).toBe(false);
    expect(contentLengthExceeds(new Headers({ "content-length": "abc" }), 10)).toBe(false);
  });

  it("is true only strictly past the cap", () => {
    expect(contentLengthExceeds(new Headers({ "content-length": "10" }), 10)).toBe(false);
    expect(contentLengthExceeds(new Headers({ "content-length": "11" }), 10)).toBe(true);
  });
});

describe("readBodyCapped", () => {
  it("reads a null body as zero bytes", async () => {
    expect(await readBodyCapped(null, 10)).toEqual({ ok: true, bytes: new Uint8Array(0) });
  });

  it("concatenates chunks up to and including the cap", async () => {
    const read = await readBodyCapped(
      streamOf([new Uint8Array([1, 2, 3]), new Uint8Array([4, 5])]),
      5,
    );
    expect(read).toEqual({ ok: true, bytes: new Uint8Array([1, 2, 3, 4, 5]) });
  });

  it("refuses one byte past the cap and cancels the stream", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(4));
      },
      cancel() {
        cancelled = true;
      },
    });
    const read = await readBodyCapped(body, 7);
    expect(read).toEqual({ ok: false, reason: "too_large" });
    expect(cancelled).toBe(true);
  });
});
