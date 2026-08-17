import { createHash, createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";
import { VaultError } from "@harpoc/shared";

export interface JwsOptions {
  payload: object | "";
  protectedHeader: Record<string, unknown>;
  privateKeyPem: string;
}

export interface FlattenedJws {
  protected: string;
  payload: string;
  signature: string;
}

/* RFC 7638 §3.2: the thumbprint covers these members and nothing else — any
 * alg/kid/use the JWK also carries must be stripped before hashing. */
const CANONICAL_JWK_MEMBERS = new Map<string, readonly string[]>([
  ["EC", ["crv", "kty", "x", "y"]],
  ["RSA", ["e", "kty", "n"]],
]);

const EC_ALGORITHMS = new Map<string, JwsAlgorithm>([
  ["P-256", { alg: "ES256", hash: "sha256" }],
  ["P-384", { alg: "ES384", hash: "sha384" }],
  ["P-521", { alg: "ES512", hash: "sha512" }],
]);

const RSA_ALGORITHM: JwsAlgorithm = { alg: "RS256", hash: "sha256" };

interface JwsAlgorithm {
  alg: string;
  hash: string;
}

export function signJws(options: JwsOptions): FlattenedJws {
  const key = loadKey(options.privateKeyPem);
  const { alg, hash } = keyAlgorithm(key);
  const declared = options.protectedHeader["alg"];
  if (declared !== undefined && declared !== alg) {
    throw VaultError.certAcmeFailed(
      `protected header alg does not match the signing key (expected ${alg})`,
    );
  }
  const protectedPart = base64url(serialize(options.protectedHeader, "protected header"));
  const payloadPart =
    options.payload === "" ? "" : base64url(serialize(options.payload, "payload"));
  const signingInput = Buffer.from(`${protectedPart}.${payloadPart}`, "ascii");
  /* JWS carries an ECDSA signature as the raw r||s pair (RFC 7515 §3.4), not as
   * the DER SEQUENCE node emits by default — the opposite of the PKCS#10
   * signature in ../csr-generator.ts, which must stay DER. */
  const signature =
    key.asymmetricKeyType === "ec"
      ? sign(hash, signingInput, { key, dsaEncoding: "ieee-p1363" })
      : sign(hash, signingInput, key);
  return {
    protected: protectedPart,
    payload: payloadPart,
    signature: signature.toString("base64url"),
  };
}

export function publicJwk(privateKeyPem: string): Record<string, string> {
  const exported = createPublicKey(loadKey(privateKeyPem)).export({ format: "jwk" });
  return canonicalJwk(exported as Record<string, unknown>);
}

export function jwkThumbprint(jwk: Record<string, string>): string {
  const canonical = JSON.stringify(canonicalJwk(jwk));
  return createHash("sha256").update(canonical).digest("base64url");
}

function canonicalJwk(jwk: Record<string, unknown>): Record<string, string> {
  const kty = ownString(jwk, "kty");
  const members = CANONICAL_JWK_MEMBERS.get(kty ?? "");
  if (!members) {
    throw VaultError.certAcmeFailed(`unsupported JWK key type: ${kty ?? "(absent)"}`);
  }
  const canonical: Record<string, string> = {};
  for (const member of members) {
    const value = ownString(jwk, member);
    if (value === undefined) {
      throw VaultError.certAcmeFailed(`JWK is missing the required member: ${member}`);
    }
    canonical[member] = value;
  }
  return canonical;
}

function ownString(source: Record<string, unknown>, member: string): string | undefined {
  if (!Object.hasOwn(source, member)) return undefined;
  const value = source[member];
  return typeof value === "string" ? value : undefined;
}

function keyAlgorithm(key: KeyObject): JwsAlgorithm {
  if (key.asymmetricKeyType === "rsa") return RSA_ALGORITHM;
  const curve = createPublicKey(key).export({ format: "jwk" }).crv;
  const algorithm = EC_ALGORITHMS.get(curve ?? "");
  if (!algorithm) {
    throw VaultError.certAcmeFailed(`unsupported EC curve: ${curve ?? "(absent)"}`);
  }
  return algorithm;
}

function loadKey(privateKeyPem: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch {
    throw VaultError.certAcmeFailed("private key PEM is not parseable");
  }
  if (key.asymmetricKeyType !== "ec" && key.asymmetricKeyType !== "rsa") {
    throw VaultError.certAcmeFailed(`unsupported key type: ${String(key.asymmetricKeyType)}`);
  }
  return key;
}

function serialize(value: unknown, what: string): string {
  const detail = `${what} is not JSON-serializable`;
  let json: unknown;
  try {
    json = JSON.stringify(value);
  } catch {
    throw VaultError.certAcmeFailed(detail);
  }
  if (typeof json !== "string") throw VaultError.certAcmeFailed(detail);
  return json;
}

function base64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}
