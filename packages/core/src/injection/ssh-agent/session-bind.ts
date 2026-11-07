import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { SshReader } from "./ssh-wire.js";

/**
 * The `session-bind@openssh.com` agent extension (OpenSSH `PROTOCOL.agent` § 1): before
 * it lists identities, an OpenSSH ≥ 8.9 client binds its agent connection to the SSH
 * session it is authenticating — the server's host key, the session identifier (the
 * exchange hash of the initial key exchange) and the host key's signature over it, as the
 * server sent it in its final KEX reply. Verifying that signature proves the connection
 * talks to the holder of that host key. Parsing and verification run on `node:crypto`
 * only; neither function throws, and nothing here names key material.
 */
export const SESSION_BIND_EXTENSION = "session-bind@openssh.com";

/** OpenSSH's `AGENT_MAX_SID_LEN` (`ssh-agent.c`): a longer session identifier is refused. */
export const MAX_SESSION_ID_BYTES = 128;

/** The fields of one `session-bind@openssh.com` request, as the client sent them. */
export interface SessionBind {
  hostKeyBlob: Buffer;
  sessionId: Buffer;
  signature: Buffer;
  isForwarding: boolean;
}

/** What a verified authentication bind records on its connection. */
export interface AgentBinding {
  hostKeyBlob: Buffer;
  sessionId: Buffer;
}

/**
 * Parse the extension's contents (the bytes after the extension name): `string hostkey ·
 * string session identifier · string signature · bool is_forwarding`. Null for a
 * truncated or over-long request, an empty field, a session identifier past
 * {@link MAX_SESSION_ID_BYTES}, a flag byte other than 0 or 1, or trailing bytes.
 */
export function parseSessionBind(contents: Buffer): SessionBind | null {
  try {
    const r = new SshReader(contents);
    const hostKeyBlob = r.readString();
    const sessionId = r.readString();
    const signature = r.readString();
    const flag = r.readByte();
    if (r.remaining !== 0 || (flag !== 0 && flag !== 1)) return null;
    if (hostKeyBlob.length === 0 || signature.length === 0) return null;
    if (sessionId.length === 0 || sessionId.length > MAX_SESSION_ID_BYTES) return null;
    return { hostKeyBlob, sessionId, signature, isForwarding: flag === 1 };
  } catch {
    return null;
  }
}

/**
 * Whether `signature` (an SSH signature blob, RFC 4253 § 6.6: `string algorithm · string
 * body`) is the host key's signature over `sessionId`. Host keys: `ssh-ed25519`,
 * `ecdsa-sha2-nistp256` / `-nistp384` / `-nistp521` (RFC 5656 § 3.1.2) and `ssh-rsa` of at
 * least 1024 bits signing `rsa-sha2-256` / `rsa-sha2-512` (RFC 8332). The SHA-1
 * `ssh-rsa` signature algorithm is refused — OpenSSH 8.8 disabled it by default. Any other
 * key type, a malformed blob, an algorithm the key type does not sign with, trailing
 * bytes or a failed check is `false`.
 */
export function verifyHostKeySignature(
  hostKeyBlob: Buffer,
  signature: Buffer,
  sessionId: Buffer,
): boolean {
  try {
    const key = hostPublicKey(hostKeyBlob);
    if (key === null) return false;
    const r = new SshReader(signature);
    const algorithm = r.readCString();
    const body = r.readString();
    if (r.remaining !== 0) return false;
    return key.verify(algorithm, body, sessionId);
  } catch {
    return false;
  }
}

interface HostPublicKey {
  verify(algorithm: string, body: Buffer, data: Buffer): boolean;
}

interface EcdsaCurve {
  crv: string;
  hash: string;
  size: number;
}

const ECDSA_CURVES = new Map<string, EcdsaCurve>([
  ["nistp256", { crv: "P-256", hash: "sha256", size: 32 }],
  ["nistp384", { crv: "P-384", hash: "sha384", size: 48 }],
  ["nistp521", { crv: "P-521", hash: "sha512", size: 66 }],
]);

const RSA_SIGNATURE_HASHES = new Map<string, string>([
  ["rsa-sha2-256", "sha256"],
  ["rsa-sha2-512", "sha512"],
]);

/** OpenSSH's `SSH_RSA_MINIMUM_MODULUS_SIZE` (`sshkey.h`). */
const MIN_RSA_MODULUS_BITS = 1024;

function hostPublicKey(blob: Buffer): HostPublicKey | null {
  const r = new SshReader(blob);
  const type = r.readCString();

  if (type === "ssh-ed25519") {
    const a = r.readString();
    if (r.remaining !== 0 || a.length !== 32) return null;
    const key = jwkPublicKey({ kty: "OKP", crv: "Ed25519", x: a.toString("base64url") });
    return {
      verify: (algorithm, body, data) =>
        algorithm === type && body.length === 64 && cryptoVerify(null, data, key, body),
    };
  }

  if (type.startsWith("ecdsa-sha2-")) {
    const curveId = r.readCString();
    const q = r.readString();
    const curve = ECDSA_CURVES.get(curveId);
    if (curve === undefined || type !== `ecdsa-sha2-${curveId}` || r.remaining !== 0) return null;
    if (q.length !== 1 + 2 * curve.size || q[0] !== 0x04) return null;
    const key = jwkPublicKey({
      kty: "EC",
      crv: curve.crv,
      x: q.subarray(1, 1 + curve.size).toString("base64url"),
      y: q.subarray(1 + curve.size).toString("base64url"),
    });
    return {
      verify: (algorithm, body, data) => {
        if (algorithm !== type) return false;
        const rs = ecdsaP1363(body, curve.size);
        return (
          rs !== null && cryptoVerify(curve.hash, data, { key, dsaEncoding: "ieee-p1363" }, rs)
        );
      },
    };
  }

  if (type === "ssh-rsa") {
    const e = unsignedMpint(r);
    const n = unsignedMpint(r);
    if (e === null || n === null || r.remaining !== 0) return null;
    const key = jwkPublicKey({
      kty: "RSA",
      e: e.toString("base64url"),
      n: n.toString("base64url"),
    });
    const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
    if (bits < MIN_RSA_MODULUS_BITS) return null;
    const size = Math.ceil(bits / 8);
    return {
      verify: (algorithm, body, data) => {
        const hash = RSA_SIGNATURE_HASHES.get(algorithm);
        if (hash === undefined || body.length > size) return false;
        return cryptoVerify(hash, data, key, leftPad(body, size));
      },
    };
  }

  return null;
}

function jwkPublicKey(jwk: Record<string, string>): KeyObject {
  return createPublicKey({ key: jwk, format: "jwk" });
}

/** An mpint read as a non-negative magnitude without leading zeros; null when negative. */
function unsignedMpint(r: SshReader): Buffer | null {
  const raw = r.readString();
  if (raw.length > 0 && ((raw[0] as number) & 0x80) !== 0) return null;
  let i = 0;
  while (i < raw.length && raw[i] === 0) i++;
  return raw.subarray(i);
}

/** The SSH ECDSA signature body `mpint r · mpint s` as fixed-width `r ‖ s`; null if malformed. */
function ecdsaP1363(body: Buffer, size: number): Buffer | null {
  const r = new SshReader(body);
  const sigR = unsignedMpint(r);
  const sigS = unsignedMpint(r);
  if (sigR === null || sigS === null || r.remaining !== 0) return null;
  if (sigR.length === 0 || sigS.length === 0 || sigR.length > size || sigS.length > size) {
    return null;
  }
  return Buffer.concat([leftPad(sigR, size), leftPad(sigS, size)]);
}

function leftPad(buf: Buffer, size: number): Buffer {
  return buf.length >= size ? buf : Buffer.concat([Buffer.alloc(size - buf.length), buf]);
}
