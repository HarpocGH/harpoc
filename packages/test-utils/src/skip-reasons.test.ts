import { describe, expect, it } from "vitest";
import { isConnectionRefused, isIpv6BindUnavailable } from "./skip-reasons.js";

const errno = (code: string): NodeJS.ErrnoException => {
  const err = new Error(`${code}: injected`) as NodeJS.ErrnoException;
  err.code = code;
  return err;
};

/** undici's shape: `TypeError: fetch failed` with the errno on `cause`. */
const fetchFailed = (cause: unknown): TypeError => {
  const err = new TypeError("fetch failed") as TypeError & { cause?: unknown };
  err.cause = cause;
  return err;
};

/** A bind wrapper: an `Error` with the errno on `cause` (a listener's `error` re-thrown with context). */
const wrapped = (cause: unknown): Error => {
  const err = new Error("bind failed") as Error & { cause?: unknown };
  err.cause = cause;
  return err;
};

describe("isIpv6BindUnavailable (D7)", () => {
  it.each(["EAFNOSUPPORT", "EADDRNOTAVAIL"])("is true for a `::` bind refused with %s", (code) => {
    expect(isIpv6BindUnavailable(errno(code))).toBe(true);
  });

  it.each(["EADDRINUSE", "EACCES", "EPIPE", "ECONNREFUSED"])(
    "is false for %s — a failure to report, not a missing stack",
    (code) => {
      expect(isIpv6BindUnavailable(errno(code))).toBe(false);
    },
  );

  it("is false for an error without a code and for a non-error", () => {
    expect(isIpv6BindUnavailable(new Error("audit log unwritable"))).toBe(false);
    expect(isIpv6BindUnavailable(null)).toBe(false);
    expect(isIpv6BindUnavailable(undefined)).toBe(false);
    expect(isIpv6BindUnavailable("EAFNOSUPPORT")).toBe(false);
  });

  it("is true for a wrapped bind failure whose cause carries EADDRNOTAVAIL", () => {
    expect(isIpv6BindUnavailable(wrapped(errno("EADDRNOTAVAIL")))).toBe(true);
  });

  it("is true for an AggregateError carrying EAFNOSUPPORT beside another code", () => {
    expect(
      isIpv6BindUnavailable(
        new AggregateError([errno("EADDRINUSE"), errno("EAFNOSUPPORT")], "all failed"),
      ),
    ).toBe(true);
  });
});

describe("isConnectionRefused (D7)", () => {
  it("is true for a bare ECONNREFUSED", () => {
    expect(isConnectionRefused(errno("ECONNREFUSED"))).toBe(true);
  });

  it("is true for a fetch failure whose cause carries ECONNREFUSED", () => {
    expect(isConnectionRefused(fetchFailed(errno("ECONNREFUSED")))).toBe(true);
  });

  it("is true for a fetch failure whose cause is an AggregateError carrying ECONNREFUSED", () => {
    expect(
      isConnectionRefused(fetchFailed(new AggregateError([errno("ECONNREFUSED")], "all failed"))),
    ).toBe(true);
  });

  it("is false for a refused bind, a handshake rejection and a non-error", () => {
    expect(isConnectionRefused(errno("EAFNOSUPPORT"))).toBe(false);
    expect(isConnectionRefused(new Error("HTTP 401 Unauthorized"))).toBe(false);
    expect(isConnectionRefused(fetchFailed(new Error("no code here")))).toBe(false);
    expect(isConnectionRefused(null)).toBe(false);
  });

  it("does not loop on a cyclic cause chain", () => {
    const a = new Error("a") as Error & { cause?: unknown };
    const b = new Error("b") as Error & { cause?: unknown };
    a.cause = b;
    b.cause = a;
    expect(isConnectionRefused(a)).toBe(false);
  });
});

// One walk under both predicates; its cycle guard covers the `errors[]`
// branch as well as `cause` (2026-09-07 — the previous cases cycled through
// `cause` only).
describe("errnoCodes walk — cycles through errors[]", () => {
  it("does not loop on an AggregateError that contains itself, and still reads the code beside the loop", () => {
    const loop = new AggregateError([], "loop");
    loop.errors.push(loop, errno("ECONNREFUSED"));
    expect(isConnectionRefused(loop)).toBe(true);
    expect(isIpv6BindUnavailable(loop)).toBe(false);
  });

  it("does not loop on a cause that points back through errors[]", () => {
    const outer = new Error("outer") as Error & { cause?: unknown };
    const inner = new AggregateError([outer], "inner");
    outer.cause = inner;
    expect(isConnectionRefused(outer)).toBe(false);
    expect(isIpv6BindUnavailable(outer)).toBe(false);
  });
});
