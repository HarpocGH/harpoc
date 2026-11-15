import { chai } from "vitest";

/**
 * Assert that `haystack` does not hold `needle` — a string as a substring, a
 * list as an entry equal to it; anything else fails, as `not.toContain` fails
 * on `undefined`.
 *
 * Replaces `expect(text).not.toContain(SECRET)`: a failing `not.toContain`
 * prints both operands — the secret and the text that holds it — in the log
 * and again in the CI annotation. Here a failure names only the label, the
 * position and the lengths, carries no `actual` or `expected`, and its stack
 * starts at the caller, so the red points at the row and not at this helper.
 */
export function expectAbsent(haystack: unknown, needle: string, label?: string): void {
  const name = label ?? "the text";
  const fail = (reason: string): never => {
    throw new chai.AssertionError(`${name}: ${reason}`, undefined, expectAbsent);
  };
  if (typeof needle !== "string") {
    fail(`the secret to look for is not a text (${typeof needle})`);
  }
  if (needle.length === 0) {
    fail("the secret to look for is empty");
  }
  if (typeof haystack === "string") {
    const index = haystack.indexOf(needle);
    if (index !== -1) {
      fail(
        `holds the secret at index ${index} (${haystack.length} chars; the secret ${needle.length} chars)`,
      );
    }
    return;
  }
  if (Array.isArray(haystack)) {
    const entry = haystack.indexOf(needle);
    if (entry !== -1) {
      fail(`holds the secret as entry ${entry} of ${haystack.length}`);
    }
    return;
  }
  fail(`nothing to search (${typeof haystack})`);
}
