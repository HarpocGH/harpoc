import { createHash, createPrivateKey, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  fixtureKey,
  fixturePublicBlob,
  hostKeyBinding,
  readSshFixture,
  sessionBindBody,
} from "../__fixtures__/agent-client.js";
import type { SessionBindFields } from "../__fixtures__/agent-client.js";
import {
  CAPTURED_HOST_KEY_FIXTURE,
  CAPTURED_SESSION_BIND,
} from "../__fixtures__/ssh-agent-capture.js";
import { MAX_SESSION_ID_BYTES, parseSessionBind, verifyHostKeySignature } from "./session-bind.js";
import {
  SshReader,
  encodeSignature,
  rsaPublicKeyBlob,
  writeByte,
  writeString,
} from "./ssh-wire.js";

const SID = createHash("sha256").update("lane P session identifier").digest();

/** The extension's contents: the request body after the type byte and the extension name. */
const contentsOf = (fields: SessionBindFields): Buffer =>
  sessionBindBody(fields).subarray(1 + 4 + "session-bind@openssh.com".length);

const authBind = (fixture = "ed25519_openssh", sessionId = SID): SessionBindFields => ({
  ...hostKeyBinding(fixture, sessionId),
  isForwarding: false,
});

/** The body of an SSH signature blob (`string algorithm · string body`). */
const signatureBody = (blob: Buffer): Buffer => {
  const r = new SshReader(blob);
  r.readCString();
  return r.readString();
};

const flipLastByte = (buf: Buffer): Buffer => {
  const copy = Buffer.from(buf);
  copy[copy.length - 1] = (copy[copy.length - 1] as number) ^ 0x01;
  return copy;
};

describe("parseSessionBind", () => {
  it("reads the host key, the session identifier, the signature and is_forwarding", () => {
    const fields = authBind("ecdsa256_openssh");
    expect(parseSessionBind(contentsOf(fields))).toEqual(fields);
  });

  it("reads is_forwarding 1 as a forwarding bind", () => {
    expect(parseSessionBind(contentsOf({ ...authBind(), isForwarding: true }))?.isForwarding).toBe(
      true,
    );
  });

  it("accepts a session identifier of 128 bytes (OpenSSH's AGENT_MAX_SID_LEN)", () => {
    expect(MAX_SESSION_ID_BYTES).toBe(128);
    const sid = Buffer.alloc(128, 7);
    expect(parseSessionBind(contentsOf(authBind("ed25519_openssh", sid)))?.sessionId).toEqual(sid);
  });

  it("reads the bind Win32-OpenSSH 9.5p2 sent on this host: the fixture host key, a 32-byte sid, not forwarding", () => {
    const name = new SshReader(CAPTURED_SESSION_BIND.subarray(1)).readCString();
    expect(name).toBe("session-bind@openssh.com");
    const bind = parseSessionBind(CAPTURED_SESSION_BIND.subarray(1 + 4 + name.length));
    expect(bind?.hostKeyBlob).toEqual(fixturePublicBlob(CAPTURED_HOST_KEY_FIXTURE));
    expect(bind?.sessionId.length).toBe(32);
    expect(bind?.isForwarding).toBe(false);
  });

  const good = contentsOf(authBind());
  it.each([
    ["a truncated request", good.subarray(0, good.length - 1)],
    ["a trailing byte", Buffer.concat([good, writeByte(0)])],
    ["a flag byte of 2", Buffer.concat([good.subarray(0, good.length - 1), writeByte(2)])],
    ["an empty session identifier", contentsOf(authBind("ed25519_openssh", Buffer.alloc(0)))],
    [
      "a session identifier past 128 bytes",
      contentsOf(authBind("ed25519_openssh", Buffer.alloc(129, 7))),
    ],
    ["an empty signature", contentsOf({ ...authBind(), signature: Buffer.alloc(0) })],
    ["an empty host key", contentsOf({ ...authBind(), hostKeyBlob: Buffer.alloc(0) })],
    ["no bytes at all", Buffer.alloc(0)],
  ])("refuses %s", (_label, contents) => {
    expect(parseSessionBind(contents)).toBeNull();
  });
});

describe("verifyHostKeySignature — the host key's signature over the session identifier, on node:crypto", () => {
  it.each([
    ["ed25519_openssh", 4, "ssh-ed25519"],
    ["ecdsa256_openssh", 4, "ecdsa-sha2-nistp256"],
    ["ecdsa256_pem", 4, "ecdsa-sha2-nistp256"],
    ["ecdsa384_openssh", 4, "ecdsa-sha2-nistp384"],
    ["ecdsa521_openssh", 4, "ecdsa-sha2-nistp521"],
    ["rsa_openssh", 4, "rsa-sha2-512"],
    ["rsa_openssh", 2, "rsa-sha2-256"],
    ["rsa_pem", 2, "rsa-sha2-256"],
  ])("verifies %s signing with flags %i (%s)", (fixture, flags, algorithm) => {
    const bind = hostKeyBinding(fixture, SID, flags);
    expect(new SshReader(bind.signature).readCString()).toBe(algorithm);
    expect(verifyHostKeySignature(bind.hostKeyBlob, bind.signature, SID)).toBe(true);
  });

  it("verifies the bind Win32-OpenSSH 9.5p2 relayed from the ssh2 server's ecdsa-sha2-nistp256 KEX reply", () => {
    const name = new SshReader(CAPTURED_SESSION_BIND.subarray(1)).readCString();
    const bind = parseSessionBind(CAPTURED_SESSION_BIND.subarray(1 + 4 + name.length));
    expect(bind).not.toBeNull();
    const { hostKeyBlob, signature, sessionId } = bind as NonNullable<typeof bind>;
    expect(verifyHostKeySignature(hostKeyBlob, signature, sessionId)).toBe(true);
    expect(verifyHostKeySignature(hostKeyBlob, signature, flipLastByte(sessionId))).toBe(false);
  });

  it.each([
    "ed25519_openssh",
    "ecdsa256_openssh",
    "ecdsa384_openssh",
    "ecdsa521_openssh",
    "rsa_openssh",
  ])("refuses %s's signature over another session identifier (one bit flipped)", (fixture) => {
    const bind = hostKeyBinding(fixture, SID);
    expect(verifyHostKeySignature(bind.hostKeyBlob, bind.signature, flipLastByte(SID))).toBe(false);
  });

  it.each([
    ["another key of the same type", "ecdsa256_openssh", "ecdsa256_pem"],
    ["a key of another type", "ecdsa256_openssh", "ed25519_openssh"],
    ["an RSA key's signature under another RSA host key", "rsa_openssh", "rsa_pem"],
  ])("refuses the signature of %s", (_label, hostFixture, signerFixture) => {
    const hostKeyBlob = fixturePublicBlob(hostFixture);
    const signature = fixtureKey(signerFixture).sign(SID, 4);
    expect(verifyHostKeySignature(hostKeyBlob, signature, SID)).toBe(false);
  });

  it("refuses an ssh-rsa (SHA-1) signature that node:crypto itself verifies — OpenSSH 8.8 disabled the algorithm", () => {
    const privateKey = createPrivateKey(readSshFixture("rsa_pem"));
    const raw = cryptoSign("sha1", SID, privateKey);
    const hostKeyBlob = fixturePublicBlob("rsa_pem");
    expect(verifyHostKeySignature(hostKeyBlob, encodeSignature("ssh-rsa", raw), SID)).toBe(false);
    const sha256 = cryptoSign("sha256", SID, privateKey);
    expect(verifyHostKeySignature(hostKeyBlob, encodeSignature("rsa-sha2-256", sha256), SID)).toBe(
      true,
    );
  });

  it.each([
    ["an ed25519 signature labelled ssh-rsa", "ed25519_openssh", "ssh-rsa"],
    ["an ecdsa P-256 signature labelled nistp384", "ecdsa256_openssh", "ecdsa-sha2-nistp384"],
    ["an rsa-sha2-512 signature labelled rsa-sha2-256", "rsa_openssh", "rsa-sha2-256"],
  ])("refuses %s", (_label, fixture, label) => {
    const bind = hostKeyBinding(fixture, SID, 4);
    const relabelled = encodeSignature(label, signatureBody(bind.signature));
    expect(verifyHostKeySignature(bind.hostKeyBlob, relabelled, SID)).toBe(false);
  });

  it("left-pads an RSA signature shorter than the modulus, as OpenSSH's ssh_rsa_verify does", () => {
    const key = fixtureKey("rsa_openssh");
    let sid = SID;
    let raw: Buffer = Buffer.alloc(0);
    for (let i = 0; i < 4096; i++) {
      sid = createHash("sha256").update(`short rsa signature ${i}`).digest();
      raw = signatureBody(key.sign(sid, 2));
      if (raw[0] === 0) break;
    }
    expect(raw[0]).toBe(0);
    const stripped = encodeSignature("rsa-sha2-256", raw.subarray(1));
    expect(verifyHostKeySignature(key.publicKeyBlob, stripped, sid)).toBe(true);
    const long = encodeSignature("rsa-sha2-256", Buffer.concat([Buffer.alloc(1), raw]));
    expect(verifyHostKeySignature(key.publicKeyBlob, long, sid)).toBe(false);
  });

  it("refuses an RSA host key below OpenSSH's 1024-bit minimum", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 768 });
    const jwk = publicKey.export({ format: "jwk" });
    const blob = rsaPublicKeyBlob(
      Buffer.from(jwk.e as string, "base64url"),
      Buffer.from(jwk.n as string, "base64url"),
    );
    const signature = encodeSignature("rsa-sha2-256", cryptoSign("sha256", SID, privateKey));
    expect(verifyHostKeySignature(blob, signature, SID)).toBe(false);
  });

  it("refuses an RSA host key past OpenSSH's 16384-bit bignum bound (SSHBUF_MAX_BIGNUM)", () => {
    const blob = rsaPublicKeyBlob(Buffer.from([1, 0, 1]), Buffer.alloc(2049, 0xff));
    const signature = encodeSignature("rsa-sha2-256", Buffer.alloc(2049, 1));
    expect(verifyHostKeySignature(blob, signature, SID)).toBe(false);
  });

  const ed = hostKeyBinding("ed25519_openssh", SID);
  const ec = hostKeyBinding("ecdsa256_openssh", SID);
  const ecPoint = (() => {
    const r = new SshReader(ec.hostKeyBlob);
    r.readCString();
    r.readCString();
    return r.readString();
  })();
  const ecInner = signatureBody(ec.signature);
  const ecS = ecInner.subarray(4 + ecInner.readUInt32BE(0));
  it.each([
    [
      "a truncated host key blob",
      ed.hostKeyBlob.subarray(0, ed.hostKeyBlob.length - 1),
      ed.signature,
    ],
    [
      "a host key blob with a trailing byte",
      Buffer.concat([ed.hostKeyBlob, writeByte(0)]),
      ed.signature,
    ],
    [
      "a signature blob with a trailing byte",
      ed.hostKeyBlob,
      Buffer.concat([ed.signature, writeByte(0)]),
    ],
    [
      "an unknown key type (ssh-dss)",
      Buffer.concat([writeString("ssh-dss"), writeString(Buffer.alloc(32))]),
      ed.signature,
    ],
    [
      "a host certificate type",
      Buffer.concat([
        writeString("ssh-ed25519-cert-v01@openssh.com"),
        writeString(Buffer.alloc(32)),
      ]),
      ed.signature,
    ],
    [
      "a 300 KiB host key blob",
      Buffer.concat([writeString("ssh-ed25519"), writeString(Buffer.alloc(300 * 1024))]),
      ed.signature,
    ],
    [
      "an ECDSA point off the curve",
      Buffer.concat([
        writeString("ecdsa-sha2-nistp256"),
        writeString("nistp256"),
        writeString(flipLastByte(ecPoint)),
      ]),
      ec.signature,
    ],
    [
      "an ECDSA blob whose curve does not match its type",
      Buffer.concat([
        writeString("ecdsa-sha2-nistp256"),
        writeString("nistp384"),
        writeString(ecPoint),
      ]),
      ec.signature,
    ],
    [
      "an ECDSA signature with a negative r",
      ec.hostKeyBlob,
      encodeSignature(
        "ecdsa-sha2-nistp256",
        Buffer.concat([writeString(Buffer.from([0x80, 1])), ecS]),
      ),
    ],
    ["an empty signature blob", ed.hostKeyBlob, Buffer.alloc(0)],
  ])("refuses %s, without throwing", (_label, hostKeyBlob, signature) => {
    expect(verifyHostKeySignature(hostKeyBlob, signature, SID)).toBe(false);
  });
});
