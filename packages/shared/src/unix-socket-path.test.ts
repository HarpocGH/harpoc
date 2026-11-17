import { describe, expect, it } from "vitest";
import { maxUnixSocketPathBytes } from "./unix-socket-path.js";

describe("maxUnixSocketPathBytes", () => {
  it("darwin's bound is 103 — its sun_path's 104 bytes less the NUL", () => {
    expect(maxUnixSocketPathBytes("darwin")).toBe(103);
  });

  it("linux's bound is 107 — its sun_path's 108 bytes less the NUL", () => {
    expect(maxUnixSocketPathBytes("linux")).toBe(107);
  });

  it.each(["win32", "aix", "sunos", "android", "cygwin", ""])(
    "%j takes Linux's 107",
    (platform) => {
      expect(maxUnixSocketPathBytes(platform)).toBe(107);
    },
  );

  it.each(["freebsd", "openbsd", "netbsd"])(
    "%j takes darwin's 103 — its sun_path is 104 bytes too",
    (platform) => {
      expect(maxUnixSocketPathBytes(platform)).toBe(103);
    },
  );
});
