/**
 * One agent conversation of the native Win32-OpenSSH client, recorded on 2026-11-06 by a
 * stand-in agent on a named pipe (B3 research, lane P): `OpenSSH_for_Windows_9.5p2,
 * LibreSSL 3.8.2` authenticating as `testuser` to an `ssh2` 1.17.0 test server on
 * loopback that held the fixture `ecdsa256_openssh` as its host key, with
 * `IdentitiesOnly=yes` and `-i ed25519_openssh.pub`. On one agent connection the client
 * sent the bind below, `REQUEST_IDENTITIES`, then the sign request below. Public material
 * only: a finished test session's identifier, the fixture host key and its signature over
 * it, the fixture user key's public blob.
 */
export const CAPTURED_CLIENT = "OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2";
export const CAPTURED_HOST_KEY_FIXTURE = "ecdsa256_openssh";
export const CAPTURED_USER_KEY_FIXTURE = "ed25519_openssh";

/** The client's `session-bind@openssh.com` request: the message body, type byte included. */
export const CAPTURED_SESSION_BIND = Buffer.from(
  [
    "1b0000001873657373696f6e2d62696e64406f70656e7373682e636f6d000000",
    "680000001365636473612d736861322d6e69737470323536000000086e697374",
    "7032353600000041049fd014fdc6e05e316650ff4fe023e39f45c9d04ef8e32c",
    "81210413d7a3fd9be450fe0a6a04077324924416366c914844fe2e2fa8a381c1",
    "b6388647a30d788717000000206770a843c5b99445247640ce1c1d2b8b3f1456",
    "2a4e0ebf5f58a3159bb51c48a1000000650000001365636473612d736861322d",
    "6e697374703235360000004a0000002100d92f6431a526b104e99e707782dac3",
    "772889e43ce6b278cf1aa979db71662d770000002100e90f044c541f79122011",
    "a7b067e7ffcecc25827d82045a964e2b2ca001d18df400",
  ].join(""),
  "hex",
);

/** The `data` of the client's `SSH_AGENTC_SIGN_REQUEST`. */
export const CAPTURED_SIGN_DATA = Buffer.from(
  [
    "000000206770a843c5b99445247640ce1c1d2b8b3f14562a4e0ebf5f58a3159b",
    "b51c48a1320000000874657374757365720000000e7373682d636f6e6e656374",
    "696f6e000000097075626c69636b6579010000000b7373682d65643235353139",
    "000000330000000b7373682d6564323535313900000020e0abc088fafa89c64f",
    "a6a69f5d56684ec3043254fd97229b7199927180030cb0",
  ].join(""),
  "hex",
);

export const CAPTURED_SIGN_FLAGS = 0;
