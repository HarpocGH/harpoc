import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildUserauthRequest, fixturePublicBlob } from "../__fixtures__/agent-client.js";
import type { UserauthFields } from "../__fixtures__/agent-client.js";
import {
  CAPTURED_SESSION_BIND,
  CAPTURED_SIGN_DATA,
  CAPTURED_USER_KEY_FIXTURE,
} from "../__fixtures__/ssh-agent-capture.js";
import { parseSessionBind } from "./session-bind.js";
import { SshReader, writeByte, writeString } from "./ssh-wire.js";
import { parseUserauthRequest } from "./userauth-request.js";

const SID = createHash("sha256").update("lane P userauth session").digest();
const USER_KEY = fixturePublicBlob("ed25519_openssh");
const HOST_KEY = fixturePublicBlob("ecdsa256_openssh");

const request = (over: Partial<UserauthFields> = {}): UserauthFields => ({
  sessionId: SID,
  algorithm: "ssh-ed25519",
  publicKeyBlob: USER_KEY,
  ...over,
});

describe("parseUserauthRequest", () => {
  it("reads a publickey request (RFC 4252 § 7)", () => {
    expect(parseUserauthRequest(buildUserauthRequest(request()))).toEqual({
      sessionId: SID,
      user: "git",
      service: "ssh-connection",
      method: "publickey",
      algorithm: "ssh-ed25519",
      publicKeyBlob: USER_KEY,
    });
  });

  it("reads the publickey-hostbound-v00@openssh.com variant and its trailing host key", () => {
    const parsed = parseUserauthRequest(buildUserauthRequest(request({ hostKeyBlob: HOST_KEY })));
    expect(parsed?.method).toBe("publickey-hostbound-v00@openssh.com");
    expect(parsed?.hostKeyBlob).toEqual(HOST_KEY);
  });

  it("reads the request Win32-OpenSSH 9.5p2 asked the stand-in agent to sign, under the session it bound", () => {
    const parsed = parseUserauthRequest(CAPTURED_SIGN_DATA);
    expect(parsed).toMatchObject({
      user: "testuser",
      service: "ssh-connection",
      method: "publickey",
      algorithm: "ssh-ed25519",
      publicKeyBlob: fixturePublicBlob(CAPTURED_USER_KEY_FIXTURE),
    });
    const name = new SshReader(CAPTURED_SESSION_BIND.subarray(1)).readCString();
    const bind = parseSessionBind(CAPTURED_SESSION_BIND.subarray(1 + 4 + name.length));
    expect(parsed?.sessionId).toEqual(bind?.sessionId);
  });

  it.each(["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"])(
    "accepts the RSA algorithm %s for an ssh-rsa key",
    (algorithm) => {
      const blob = fixturePublicBlob("rsa_openssh");
      const parsed = parseUserauthRequest(
        buildUserauthRequest(request({ algorithm, publicKeyBlob: blob })),
      );
      expect(parsed?.algorithm).toBe(algorithm);
    },
  );

  const good = buildUserauthRequest(request());
  const hostbound = buildUserauthRequest(request({ hostKeyBlob: HOST_KEY }));
  const sshsig = Buffer.concat([
    Buffer.from("SSHSIG"),
    writeString("file"),
    writeString(""),
    writeString("sha512"),
    writeString(createHash("sha512").update("a file").digest()),
  ]);
  it.each([
    ["an empty session identifier", buildUserauthRequest(request({ sessionId: Buffer.alloc(0) }))],
    [
      "another message number (51)",
      Buffer.concat([writeString(SID), writeByte(51), good.subarray(4 + SID.length + 1)]),
    ],
    ["the ssh-userauth service", buildUserauthRequest(request({ service: "ssh-userauth" }))],
    ["the password method", buildUserauthRequest(request({ method: "password" }))],
    ["the hostbased method", buildUserauthRequest(request({ method: "hostbased" }))],
    ["a FALSE signature flag (a query)", buildUserauthRequest(request({ signatureFollows: 0 }))],
    ["a signature flag of 2", buildUserauthRequest(request({ signatureFollows: 2 }))],
    [
      "an RSA algorithm for an ed25519 key",
      buildUserauthRequest(request({ algorithm: "rsa-sha2-256" })),
    ],
    [
      "nistp384 for a nistp256 key",
      buildUserauthRequest(request({ algorithm: "ecdsa-sha2-nistp384", publicKeyBlob: HOST_KEY })),
    ],
    ["a trailing byte", Buffer.concat([good, writeByte(0)])],
    [
      "a hostbound request without its host key",
      buildUserauthRequest(request({ method: "publickey-hostbound-v00@openssh.com" })),
    ],
    ["a hostbound request with a trailing byte", Buffer.concat([hostbound, writeByte(0)])],
    ["a truncated request", good.subarray(0, good.length - 1)],
    ["random bytes", createHash("sha512").update("not a userauth request").digest()],
    ["an SSHSIG blob (ssh-keygen -Y sign)", sshsig],
    ["no bytes", Buffer.alloc(0)],
  ])("is null for %s", (_label, data) => {
    expect(parseUserauthRequest(data)).toBeNull();
  });
});
