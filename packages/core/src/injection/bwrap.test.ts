import { describe, expect, it } from "vitest";
import {
  BWRAP_COMBINED_PREFIX_ARGS,
  BWRAP_FS_PREFIX_ARGS,
  BWRAP_NETWORK_PREFIX_ARGS,
  LINUX_BWRAP_CANDIDATES,
} from "./bwrap.js";

describe("bwrap wrapper constants", () => {
  it("pins the candidates to absolute paths, /usr/bin first", () => {
    expect(LINUX_BWRAP_CANDIDATES).toEqual(["/usr/bin/bwrap", "/bin/bwrap"]);
  });

  it("pins the network prefix one token per element, the payload separator last", () => {
    expect(BWRAP_NETWORK_PREFIX_ARGS).toEqual([
      "--bind",
      "/",
      "/",
      "--unshare-net",
      "--die-with-parent",
      "--",
    ]);
  });

  it("pins the filesystem prefix: read-only root, a fresh /dev, no tmpfs", () => {
    expect(BWRAP_FS_PREFIX_ARGS).toEqual([
      "--ro-bind",
      "/",
      "/",
      "--dev",
      "/dev",
      "--die-with-parent",
      "--",
    ]);
    expect(BWRAP_FS_PREFIX_ARGS).not.toContain("--tmpfs");
  });

  it("pins the combined prefix: the filesystem form plus the network namespace", () => {
    expect(BWRAP_COMBINED_PREFIX_ARGS).toEqual([
      "--ro-bind",
      "/",
      "/",
      "--dev",
      "/dev",
      "--unshare-net",
      "--die-with-parent",
      "--",
    ]);
  });

  it("every form arms the kill chain and ends in the payload separator", () => {
    for (const prefix of [
      BWRAP_NETWORK_PREFIX_ARGS,
      BWRAP_FS_PREFIX_ARGS,
      BWRAP_COMBINED_PREFIX_ARGS,
    ]) {
      expect(prefix).toContain("--die-with-parent");
      expect(prefix.at(-1)).toBe("--");
    }
  });
});
