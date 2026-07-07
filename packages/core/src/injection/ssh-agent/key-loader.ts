import { createPrivateKey, createPublicKey, sign as cryptoSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { VaultError } from "@harpoc/shared";
import {
  SshReader,
  ecdsaPublicKeyBlob,
  ed25519PublicKeyBlob,
  encodeEcdsaSignature,
  encodeSignature,
  rsaPublicKeyBlob,
} from "./ssh-wire.js";

const OPENSSH_MAGIC = "openssh-key-v1\0";

// RSA sign-request flags (OpenSSH PROTOCOL.agent).
const SSH_AGENT_RSA_SHA2_256 = 2;
const SSH_AGENT_RSA_SHA2_512 = 4;

interface EcParams {
  curve: string; // SSH curve id, e.g. "nistp256"
  hash: string; // node digest, e.g. "sha256"
  size: number; // coordinate byte length
}

const EC_BY_JWK_CRV: Record<string, EcParams> = {
  "P-256": { curve: "nistp256", hash: "sha256", size: 32 },
  "P-384": { curve: "nistp384", hash: "sha384", size: 48 },
  "P-521": { curve: "nistp521", hash: "sha512", size: 66 },
};

const EC_BY_NAMED_CURVE: Record<string, string> = {
  prime256v1: "P-256",
  secp384r1: "P-384",
  secp521r1: "P-521",
};

/** A private key ready to serve: its SSH public-key blob and a signer. */
export interface LoadedKey {
  publicKeyBlob: Buffer;
  /** Sign `data` honoring the agent sign-request flags; returns an SSH signature blob. */
  sign(data: Buffer, flags: number): Buffer;
}

/**
 * Parse an unencrypted SSH private key (traditional PEM or the OpenSSH
 * `openssh-key-v1` container) into a node:crypto KeyObject and derive its SSH
 * public-key blob. All key math and signing are node:crypto; only the OpenSSH
 * container is walked by hand, and only to reach a JWK the platform ingests.
 * No third-party crypto, and no secret material in any thrown message.
 */
export function loadPrivateKey(pem: string): LoadedKey {
  const trimmed = pem.trim();
  const keyObject = trimmed.includes("BEGIN OPENSSH PRIVATE KEY")
    ? keyObjectFromOpenssh(trimmed)
    : keyObjectFromPem(trimmed);

  const publicKeyBlob = publicKeyBlobFor(keyObject);
  return { publicKeyBlob, sign: signerFor(keyObject) };
}

function keyObjectFromPem(pem: string): KeyObject {
  try {
    return createPrivateKey(pem);
  } catch (err) {
    throw VaultError.sshAgentFailed(
      `unsupported or malformed private key (${err instanceof Error ? err.name : "parse error"})`,
    );
  }
}

// --- OpenSSH container → JWK → KeyObject ------------------------------------

function keyObjectFromOpenssh(pem: string): KeyObject {
  const body = pem
    .replace(/-----BEGIN OPENSSH PRIVATE KEY-----/, "")
    .replace(/-----END OPENSSH PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const raw = Buffer.from(body, "base64");

  const magic = raw.subarray(0, OPENSSH_MAGIC.length).toString("binary");
  if (magic !== OPENSSH_MAGIC) {
    throw VaultError.sshAgentFailed("malformed OpenSSH private key (bad magic)");
  }

  const r = new SshReader(raw.subarray(OPENSSH_MAGIC.length));
  const cipher = r.readCString();
  r.readString(); // kdfname
  r.readString(); // kdfoptions
  const nkeys = r.readUint32();

  if (cipher !== "none") {
    throw VaultError.sshAgentFailed(
      "encrypted private keys are not supported; provide an unencrypted key (the vault provides encryption at rest)",
    );
  }
  if (nkeys !== 1) {
    throw VaultError.sshAgentFailed("OpenSSH keys with multiple identities are not supported");
  }

  r.readString(); // public key blob — re-derived from the private JWK below
  const priv = new SshReader(r.readString());

  const check1 = priv.readUint32();
  const check2 = priv.readUint32();
  if (check1 !== check2) {
    throw VaultError.sshAgentFailed("malformed OpenSSH private key (check mismatch)");
  }

  const keyType = priv.readCString();
  try {
    const jwk = privateJwkFromOpenssh(keyType, priv);
    return createPrivateKey({ key: jwk, format: "jwk" });
  } catch (err) {
    if (err instanceof VaultError) throw err;
    throw VaultError.sshAgentFailed(
      `malformed OpenSSH private key (${err instanceof Error ? err.message : "parse error"})`,
    );
  }
}

function privateJwkFromOpenssh(keyType: string, r: SshReader): Record<string, string> {
  if (keyType === "ssh-ed25519") {
    const pub = r.readString(); // 32-byte A
    const priv = r.readString(); // 64 bytes = seed(32) ‖ A(32)
    return {
      kty: "OKP",
      crv: "Ed25519",
      x: b64url(pub),
      d: b64url(priv.subarray(0, 32)),
    };
  }

  if (keyType === "ssh-rsa") {
    const n = r.readMpint();
    const e = r.readMpint();
    const d = r.readMpint();
    const iqmp = r.readMpint();
    const p = r.readMpint();
    const q = r.readMpint();
    const dBig = toBig(d);
    const dp = bigToBuf(dBig % (toBig(p) - 1n));
    const dq = bigToBuf(dBig % (toBig(q) - 1n));
    return {
      kty: "RSA",
      n: b64url(n),
      e: b64url(e),
      d: b64url(d),
      p: b64url(p),
      q: b64url(q),
      dp: b64url(dp),
      dq: b64url(dq),
      qi: b64url(iqmp),
    };
  }

  if (keyType.startsWith("ecdsa-sha2-")) {
    const curveId = r.readCString(); // "nistp256" etc.
    const point = r.readString(); // 0x04 ‖ x ‖ y
    const d = r.readMpint();
    const jwkCrv = Object.keys(EC_BY_JWK_CRV).find((c) => EC_BY_JWK_CRV[c]?.curve === curveId);
    const ec = jwkCrv ? EC_BY_JWK_CRV[jwkCrv] : undefined;
    if (!jwkCrv || !ec) {
      throw VaultError.sshAgentFailed(`unsupported ECDSA curve: ${curveId}`);
    }
    if (point[0] !== 0x04) {
      throw VaultError.sshAgentFailed("unsupported ECDSA point encoding (not uncompressed)");
    }
    const coord = ec.size;
    return {
      kty: "EC",
      crv: jwkCrv,
      x: b64url(point.subarray(1, 1 + coord)),
      y: b64url(point.subarray(1 + coord, 1 + 2 * coord)),
      d: b64url(leftPad(d, coord)),
    };
  }

  throw VaultError.sshAgentFailed(`unsupported key type: ${keyType}`);
}

// --- Public-key blob + signer from a KeyObject ------------------------------

function publicKeyBlobFor(key: KeyObject): Buffer {
  const jwk = createPublicKey(key).export({ format: "jwk" }) as Record<string, string>;

  if (key.asymmetricKeyType === "ed25519") {
    return ed25519PublicKeyBlob(fromB64url(jwk.x as string));
  }
  if (key.asymmetricKeyType === "rsa") {
    return rsaPublicKeyBlob(fromB64url(jwk.e as string), fromB64url(jwk.n as string));
  }
  if (key.asymmetricKeyType === "ec") {
    const ec = EC_BY_JWK_CRV[jwk.crv as string];
    if (!ec) throw VaultError.sshAgentFailed(`unsupported ECDSA curve: ${jwk.crv}`);
    const x = leftPad(fromB64url(jwk.x as string), ec.size);
    const y = leftPad(fromB64url(jwk.y as string), ec.size);
    const point = Buffer.concat([Buffer.from([0x04]), x, y]);
    return ecdsaPublicKeyBlob(ec.curve, point);
  }
  throw VaultError.sshAgentFailed(`unsupported key type: ${key.asymmetricKeyType ?? "unknown"}`);
}

function signerFor(key: KeyObject): (data: Buffer, flags: number) => Buffer {
  if (key.asymmetricKeyType === "ed25519") {
    return (data) => encodeSignature("ssh-ed25519", cryptoSign(null, data, key));
  }

  if (key.asymmetricKeyType === "rsa") {
    return (data, flags) => {
      const useSha512 = (flags & SSH_AGENT_RSA_SHA2_512) !== 0;
      const useSha256 = (flags & SSH_AGENT_RSA_SHA2_256) !== 0;
      // The vault always drives a modern ssh, which sets a SHA-2 flag; default
      // to sha256 if none is set (legacy ssh-rsa/SHA-1 is intentionally unused).
      const [digest, formatId] = useSha512
        ? ["sha512", "rsa-sha2-512"]
        : useSha256
          ? ["sha256", "rsa-sha2-256"]
          : ["sha256", "rsa-sha2-256"];
      return encodeSignature(formatId, cryptoSign(digest, data, key));
    };
  }

  if (key.asymmetricKeyType === "ec") {
    const named = key.asymmetricKeyDetails?.namedCurve ?? "";
    const jwkCrv = EC_BY_NAMED_CURVE[named];
    const ec = jwkCrv ? EC_BY_JWK_CRV[jwkCrv] : undefined;
    if (!ec) throw VaultError.sshAgentFailed(`unsupported ECDSA curve: ${named}`);
    return (data) => {
      const rs = cryptoSign(ec.hash, data, { key, dsaEncoding: "ieee-p1363" });
      return encodeEcdsaSignature(`ecdsa-sha2-${ec.curve}`, rs);
    };
  }

  throw VaultError.sshAgentFailed(`unsupported key type: ${key.asymmetricKeyType ?? "unknown"}`);
}

// --- small helpers ----------------------------------------------------------

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function fromB64url(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

function leftPad(buf: Buffer, len: number): Buffer {
  if (buf.length >= len) return buf.subarray(buf.length - len);
  return Buffer.concat([Buffer.alloc(len - buf.length), buf]);
}

function toBig(buf: Buffer): bigint {
  return buf.length ? BigInt(`0x${buf.toString("hex")}`) : 0n;
}

function bigToBuf(x: bigint): Buffer {
  let hex = x.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return Buffer.from(hex, "hex");
}
