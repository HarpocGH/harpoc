import { describe, expect, it } from "vitest";
import { normalizeSocketPeer } from "./socket-peer.js";

describe("normalizeSocketPeer", () => {
  it.each([
    ["::ffff:127.0.0.1", "127.0.0.1"],
    ["::ffff:10.1.2.3", "10.1.2.3"],
    ["::ffff:0.0.0.0", "0.0.0.0"],
    ["::FFFF:192.168.1.5", "192.168.1.5"],
  ] as const)("strips the v4-mapped prefix from %j", (address, expected) => {
    expect(normalizeSocketPeer(address)).toBe(expected);
  });

  it.each([
    "127.0.0.1",
    "::1",
    "fe80::1%eth0",
    "2001:db8::1",
    "::ffff:999.1.1.1",
    "::ffff:1.2.3.4.5",
    "::ffff:0:127.0.0.1",
    "",
  ])("records %j verbatim", (address) => {
    expect(normalizeSocketPeer(address)).toBe(address);
  });
});
