import { describe, expect, it } from "vitest";
import { generateRandomBytes, generateUUIDv7, wipeBuffer } from "./random.js";

describe("generateRandomBytes", () => {
  it("returns the requested number of bytes", () => {
    const bytes = generateRandomBytes(32);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(32);
  });

  it("returns different values on each call", () => {
    const a = generateRandomBytes(32);
    const b = generateRandomBytes(32);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("handles zero length", () => {
    const bytes = generateRandomBytes(0);
    expect(bytes.length).toBe(0);
  });
});

describe("generateUUIDv7", () => {
  it("produces valid UUID format", () => {
    const uuid = generateUUIDv7();
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it("has version 7 in the version nibble", () => {
    const uuid = generateUUIDv7();
    expect(uuid[14]).toBe("7");
  });

  it("has variant bits set (8, 9, a, or b)", () => {
    const uuid = generateUUIDv7();
    const variantChar = uuid[19];
    expect(["8", "9", "a", "b"]).toContain(variantChar);
  });

  it("produces time-ordered UUIDs across different milliseconds", async () => {
    const uuids: string[] = [];
    for (let i = 0; i < 5; i++) {
      uuids.push(generateUUIDv7());
      await new Promise((r) => setTimeout(r, 2));
    }
    const sorted = [...uuids].sort();
    expect(uuids).toEqual(sorted);
  });

  it("generates unique UUIDs", () => {
    const set = new Set<string>();
    for (let i = 0; i < 100; i++) {
      set.add(generateUUIDv7());
    }
    expect(set.size).toBe(100);
  });

  it("embeds a timestamp close to Date.now()", () => {
    const before = Date.now();
    const uuid = generateUUIDv7();
    const after = Date.now();

    // Extract timestamp from first 12 hex chars (48 bits)
    const timestampHex = uuid.replace(/-/g, "").slice(0, 12);
    const timestamp = parseInt(timestampHex, 16);

    expect(timestamp).toBeGreaterThanOrEqual(before);
    expect(timestamp).toBeLessThanOrEqual(after);
  });
});

describe("wipeBuffer", () => {
  it("overwrites the buffer contents", () => {
    const buf = new Uint8Array(32);
    buf.fill(0xaa);
    const original = new Uint8Array(buf);

    wipeBuffer(buf);

    // After wiping, it should be different from the original (with overwhelming probability)
    expect(Buffer.from(buf).equals(Buffer.from(original))).toBe(false);
  });

  it("does not change the buffer length", () => {
    const buf = new Uint8Array(64);
    wipeBuffer(buf);
    expect(buf.length).toBe(64);
  });
});
