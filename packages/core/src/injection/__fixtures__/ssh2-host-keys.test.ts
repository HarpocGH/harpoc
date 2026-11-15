import ssh2 from "ssh2";
import { describe, expect, it, vi } from "vitest";
import { generateEd25519HostKeys } from "./ssh2-host-keys.js";
import type { Ssh2KeyPair } from "./ssh2-host-keys.js";

const { utils } = ssh2;

const UNPARSEABLE: Ssh2KeyPair = { private: "unparseable", public: "unparseable" };

describe("generateEd25519HostKeys", () => {
  it("returns an ed25519 pair ssh2 parses back", () => {
    const pair = generateEd25519HostKeys();
    expect(utils.parseKey(pair.private) instanceof Error).toBe(false);
    expect(pair.public.startsWith("ssh-ed25519 ")).toBe(true);
  });

  it("generates again when ssh2 cannot parse the pair back", () => {
    const parseable = generateEd25519HostKeys();
    const generate = vi
      .fn<() => Ssh2KeyPair>()
      .mockReturnValueOnce(UNPARSEABLE)
      .mockReturnValue(parseable);
    const returned = generateEd25519HostKeys(generate);
    expect(returned === parseable).toBe(true);
    expect(generate).toHaveBeenCalledTimes(2);
  });

  it("gives up after sixteen pairs ssh2 cannot parse back", () => {
    const generate = vi.fn<() => Ssh2KeyPair>().mockReturnValue(UNPARSEABLE);
    expect(() => generateEd25519HostKeys(generate)).toThrow(
      "ssh2 generated no ed25519 key pair it can parse back in 16 attempts",
    );
    expect(generate).toHaveBeenCalledTimes(16);
  });
});
