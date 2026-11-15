import { chai, describe, expect, it } from "vitest";
import { expectAbsent } from "./expect-absent.js";

const MARKER = "SPIKE-MARKER-0123456789";

function failureOf(run: () => void): Error {
  let thrown: unknown;
  try {
    run();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(chai.AssertionError);
  return thrown as Error;
}

function firstFrame(error: Error): string | undefined {
  return String(error.stack)
    .split(/\r?\n/)
    .find((line) => line.trim().startsWith("at "));
}

describe("expectAbsent", () => {
  it("returns for a string and for an array that do not hold the needle", () => {
    expect(() => expectAbsent("a reply without it", MARKER)).not.toThrow();
    expect(() => expectAbsent(["a", "b"], MARKER)).not.toThrow();
  });

  it("fails on a string that holds the needle, naming the label, the index and the lengths", () => {
    const text = `HTTP/1.1 200 OK\r\n\r\n${MARKER}`;
    const error = failureOf(() => expectAbsent(text, MARKER, "the reply"));
    expect(error.message).toBe(
      "the reply: holds the secret at index 19 (42 chars; the secret 23 chars)",
    );
  });

  it("fails on an array with an entry equal to the needle, and not on a longer entry", () => {
    const error = failureOf(() => expectAbsent(["a", MARKER], MARKER));
    expect(error.message).toBe("the text: holds the secret as entry 1 of 2");
    expect(() => expectAbsent(["x" + MARKER], MARKER)).not.toThrow();
  });

  it("throws an error that carries neither the needle nor the text", () => {
    const text = `HTTP/1.1 200 OK\r\n\r\n${MARKER}`;
    const error = failureOf(() => expectAbsent(text, MARKER));
    expect(Object.keys(error)).toEqual(["message"]);
    const forms = [
      ["message", error.message],
      ["String(error)", String(error)],
      ["JSON.stringify(error)", JSON.stringify(error)],
      ["error.stack", error.stack],
    ];
    for (const [name, printed] of forms) {
      expect(String(printed).includes(MARKER), name).toBe(false);
      expect(String(printed).includes(text), name).toBe(false);
    }
  });

  it("refuses a needle that is no text and an empty needle", () => {
    const notText = failureOf(() => expectAbsent("a reply", undefined as unknown as string));
    expect(notText.message).toBe("the text: the secret to look for is not a text (undefined)");
    const empty = failureOf(() => expectAbsent("a reply", ""));
    expect(empty.message).toBe("the text: the secret to look for is empty");
  });

  it("refuses a haystack that is neither a string nor an array", () => {
    const missing = failureOf(() => expectAbsent(undefined, MARKER));
    expect(missing.message).toBe("the text: nothing to search (undefined)");
    const nothing = failureOf(() => expectAbsent(null, MARKER));
    expect(nothing.message).toBe("the text: nothing to search (object)");
  });

  it("starts the stack of a failure at the caller, not at the helper", () => {
    const failures = [
      failureOf(() => expectAbsent(`HTTP/1.1 200 OK\r\n\r\n${MARKER}`, MARKER, "the reply")),
      failureOf(() => expectAbsent("a reply", undefined as unknown as string)),
      failureOf(() => expectAbsent("a reply", "")),
    ];
    for (const error of failures) {
      const frame = firstFrame(error);
      expect(frame?.includes("expect-absent.test.ts")).toBe(true);
      expect(frame?.includes("expect-absent.ts:")).toBe(false);
    }
  });
});
