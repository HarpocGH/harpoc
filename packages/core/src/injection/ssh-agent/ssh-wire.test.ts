import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  SshReader,
  ecdsaPublicKeyBlob,
  ed25519PublicKeyBlob,
  encodeEcdsaSignature,
  rsaPublicKeyBlob,
  writeMpint,
  writeString,
  writeUint32,
} from "./ssh-wire.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "__fixtures__", "ssh");

/** The base64 key blob from an OpenSSH `.pub` line: "<type> <base64> <comment>". */
function pubBlob(name: string): Buffer {
  const line = readFileSync(join(FIXTURES, `${name}.pub`), "utf8").trim();
  return Buffer.from(line.split(/\s+/)[1] as string, "base64");
}

describe("ssh-wire primitives", () => {
  it("round-trips string and uint32", () => {
    const r = new SshReader(Buffer.concat([writeString("hello"), writeUint32(0xdeadbeef)]));
    expect(r.readCString()).toBe("hello");
    expect(r.readUint32()).toBe(0xdeadbeef);
    expect(r.remaining).toBe(0);
  });

  it("prepends a sign byte when the high bit is set and strips it on read", () => {
    const highBit = Buffer.from([0x80, 0x01]);
    const encoded = writeMpint(highBit);
    // string length 3 (0x00 0x80 0x01) => 4 length bytes + 3 body
    expect(encoded.length).toBe(4 + 3);
    expect(new SshReader(encoded).readMpint()).toEqual(highBit);
  });

  it("does not prepend a sign byte when the high bit is clear", () => {
    const lowBit = Buffer.from([0x7f, 0x01]);
    const encoded = writeMpint(lowBit);
    expect(encoded.length).toBe(4 + 2);
    expect(new SshReader(encoded).readMpint()).toEqual(lowBit);
  });

  it("throws on a truncated string rather than reading past the buffer", () => {
    const claimsFive = Buffer.concat([writeUint32(5), Buffer.from("hi")]);
    expect(() => new SshReader(claimsFive).readString()).toThrow(/truncated/);
  });

  it("caps an implausibly large string length", () => {
    const huge = writeUint32(0x7fffffff);
    expect(() => new SshReader(huge).readString()).toThrow(/cap/);
  });
});

describe("public-key blob codecs (known answers from ssh-keygen)", () => {
  it("reconstructs the ssh-ed25519 blob", () => {
    const blob = pubBlob("ed25519_openssh");
    const r = new SshReader(blob);
    expect(r.readCString()).toBe("ssh-ed25519");
    const a = r.readString();
    expect(a.length).toBe(32);
    expect(ed25519PublicKeyBlob(a)).toEqual(blob);
  });

  it("reconstructs the ssh-rsa blob", () => {
    const blob = pubBlob("rsa_openssh");
    const r = new SshReader(blob);
    expect(r.readCString()).toBe("ssh-rsa");
    const e = r.readMpint();
    const n = r.readMpint();
    expect(rsaPublicKeyBlob(e, n)).toEqual(blob);
  });

  it.each([
    ["ecdsa256_openssh", "nistp256"],
    ["ecdsa384_openssh", "nistp384"],
    ["ecdsa521_openssh", "nistp521"],
  ])("reconstructs the %s blob", (name, curve) => {
    const blob = pubBlob(name);
    const r = new SshReader(blob);
    expect(r.readCString()).toBe(`ecdsa-sha2-${curve}`);
    expect(r.readCString()).toBe(curve);
    const q = r.readString();
    expect(q[0]).toBe(0x04); // uncompressed point
    expect(ecdsaPublicKeyBlob(curve, q)).toEqual(blob);
  });
});

describe("ECDSA signature encoding", () => {
  it("splits ieee-p1363 r‖s into mpint r ‖ mpint s inside the signature blob", () => {
    const r = Buffer.alloc(32, 0x11);
    const s = Buffer.alloc(32, 0x22);
    const blob = encodeEcdsaSignature("ecdsa-sha2-nistp256", Buffer.concat([r, s]));
    const reader = new SshReader(blob);
    expect(reader.readCString()).toBe("ecdsa-sha2-nistp256");
    const inner = new SshReader(reader.readString());
    expect(inner.readMpint()).toEqual(r);
    expect(inner.readMpint()).toEqual(s);
  });
});
