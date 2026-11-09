import {
  createHash,
  createPrivateKey,
  createSign,
  generateKeyPairSync,
  randomBytes,
  X509Certificate,
} from "node:crypto";
import type { KeyObject } from "node:crypto";
import { isIP } from "node:net";
import { VaultError } from "@harpoc/shared";
import {
  derBitString,
  derBoolean,
  derContext,
  derIntegerFromBytes,
  derInteger,
  derNamedBitString,
  derOctetString,
  derOid,
  derSequence,
  derSet,
  derTime,
  derUtf8String,
} from "./der.js";

/*
 * Production X.509 issuance for the egress proxy's CONNECT mode: a two-tier CA
 * name-constrained to the allowlisted hosts (RFC 5280 4.2.1.10) -- a root whose
 * key is discarded once it has signed one intermediate, which signs the
 * per-host server leaves -- ECDSA P-256 keys and ecdsa-with-SHA256 signatures
 * (no algorithm parameters, RFC 5758 3.2). Both CA certificates carry the
 * constraints: Java's PKIX validator ignores a trust anchor's own
 * constraints and enforces an intermediate's. A permittedSubtrees entry
 * restricts only its own name form, so a host list without an IP literal
 * also excludes every IPv4 and IPv6 address, and one without a DNS name
 * excludes every DNS name through the zero-length dNSName -- otherwise a leaked
 * CA would still sign for any address (or any name) a client dials. An IP
 * leaf carries no commonName: OpenSSL 3.0-3.5 check a leaf's multi-label
 * commonName against the dNSName constraints, so `CN=127.0.0.1` fails under
 * every CA this module builds.
 */

const OID_COMMON_NAME = "2.5.4.3";
const OID_ORGANIZATION_NAME = "2.5.4.10";
const OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
const OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
const OID_KEY_USAGE = "2.5.29.15";
const OID_SUBJECT_ALT_NAME = "2.5.29.17";
const OID_BASIC_CONSTRAINTS = "2.5.29.19";
const OID_NAME_CONSTRAINTS = "2.5.29.30";
const OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
const OID_EXT_KEY_USAGE = "2.5.29.37";
const OID_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

const KEY_USAGE_DIGITAL_SIGNATURE = 0;
const KEY_USAGE_KEY_CERT_SIGN = 5;
const KEY_USAGE_CRL_SIGN = 6;
const GENERAL_NAME_DNS = 2;
const GENERAL_NAME_IP = 7;
const TAG_SEQUENCE = 0x30;

const SERIAL_BYTES = 16;
const BACKDATE_MS = 5 * 60_000;
const DAY_MS = 86_400_000;
const MAX_COMMON_NAME_LENGTH = 64;
const MAX_DNS_NAME_LENGTH = 253;
const DNS_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV6_GROUPS = 8;
const LEAF_ORGANIZATION = "Harpoc Egress Proxy";
const ENCODER = new TextEncoder();

/** The fallback CA's lifetime cap (design decision 2: short-lived). */
export const MAX_UNCONSTRAINED_CA_DAYS = 30;

export interface CreateCaOptions {
  /** DNS names and IPv4/IPv6 literals; a DNS entry permits itself and every subdomain. */
  permittedHosts: readonly string[];
  /** The fallback CA: no nameConstraints extension, `permittedHosts` empty. */
  unconstrained?: boolean;
  validityDays: number;
  /** The intermediate's; defaults to `Harpoc Egress Proxy CA <the first 8 hex digits of its key identifier>`. */
  commonName?: string;
  now?: Date;
}

export interface CaMaterial {
  /** The intermediate: the CA that signs leaves, served after each leaf. */
  certPem: string;
  /** The intermediate's PKCS#8 PEM. */
  keyPem: string;
  /** The root: what a consumer trusts. Its private key is in no field. */
  rootPem: string;
}

/** A CA ready to sign leaves: its certificate and its private key as a `KeyObject`. */
export interface CaSigner {
  readonly certPem: string;
  readonly notAfter: Date;
  readonly key: KeyObject;
  readonly issuerName: Uint8Array;
  readonly keyIdentifier: Uint8Array;
}

export interface LeafOptions {
  /** A DNS name or an IPv4/IPv6 literal (no brackets, no zone id). */
  host: string;
  validityMs: number;
  now?: Date;
}

export interface LeafCertificate {
  certPem: string;
  /**
   * PKCS#8 PEM. `tls.createSecureContext` takes a key only as PEM (a string or
   * a Buffer -- a `KeyObject` and PKCS#8 DER are refused) and `KeyObject.export`
   * returns PEM only as a string, so the holder keeps the secure context built
   * from it and drops this string; a JS string cannot be wiped.
   */
  keyPem: string;
  notAfter: Date;
}

type HostName = { kind: "dns"; value: string } | { kind: "ip"; value: string; bytes: Uint8Array };

export function createCa(options: CreateCaOptions): CaMaterial {
  const now = options.now ?? new Date();
  const unconstrained = options.unconstrained === true;
  if (!Number.isInteger(options.validityDays) || options.validityDays < 1) {
    throw VaultError.invalidInput("CA validity must be a whole number of days, at least 1");
  }
  if (unconstrained && options.validityDays > MAX_UNCONSTRAINED_CA_DAYS) {
    throw VaultError.invalidInput(
      `an unconstrained CA is valid for at most ${MAX_UNCONSTRAINED_CA_DAYS} days`,
    );
  }
  if (unconstrained && options.permittedHosts.length > 0) {
    throw VaultError.invalidInput("an unconstrained CA takes no permitted hosts");
  }
  if (!unconstrained && options.permittedHosts.length === 0) {
    throw VaultError.invalidInput("a name-constrained CA needs at least one permitted host");
  }
  if (
    options.commonName !== undefined &&
    (options.commonName.length === 0 || options.commonName.length > MAX_COMMON_NAME_LENGTH)
  ) {
    throw VaultError.invalidInput(`CA common name must be 1-${MAX_COMMON_NAME_LENGTH} characters`);
  }
  const constraints = unconstrained
    ? null
    : nameConstraints(dedupe(options.permittedHosts.map(parseHost)));
  const notBefore = new Date(now.getTime() - BACKDATE_MS);
  const notAfter = new Date(now.getTime() + options.validityDays * DAY_MS);

  const root = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const rootSpki = new Uint8Array(root.publicKey.export({ type: "spki", format: "der" }));
  const rootId = keyIdentifierOf(rootSpki);
  const rootName = nameOf(`Harpoc Egress Proxy Root ${shortId(rootId)}`);
  const rootPem = signCertificate({
    issuerName: rootName,
    subjectName: rootName,
    spki: rootSpki,
    notBefore,
    notAfter,
    extensions: caExtensions(1, rootId, null, constraints),
    key: root.privateKey,
  });

  const intermediate = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = new Uint8Array(intermediate.publicKey.export({ type: "spki", format: "der" }));
  const keyIdentifier = keyIdentifierOf(spki);
  const certPem = signCertificate({
    issuerName: rootName,
    subjectName: nameOf(options.commonName ?? `Harpoc Egress Proxy CA ${shortId(keyIdentifier)}`),
    spki,
    notBefore,
    notAfter,
    extensions: caExtensions(0, keyIdentifier, rootId, constraints),
    key: root.privateKey,
  });
  // The root's KeyObject is never exported and cannot be wiped; it is dropped here.
  return {
    certPem,
    keyPem: intermediate.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    rootPem,
  };
}

function caExtensions(
  pathLength: number,
  keyIdentifier: Uint8Array,
  authorityKeyIdentifier: Uint8Array | null,
  constraints: Uint8Array | null,
): Uint8Array[] {
  const extensions = [
    extension(OID_BASIC_CONSTRAINTS, true, derSequence([derBoolean(true), derInteger(pathLength)])),
    extension(
      OID_KEY_USAGE,
      true,
      derNamedBitString([KEY_USAGE_KEY_CERT_SIGN, KEY_USAGE_CRL_SIGN]),
    ),
    extension(OID_SUBJECT_KEY_IDENTIFIER, false, derOctetString(keyIdentifier)),
  ];
  if (authorityKeyIdentifier !== null) {
    extensions.push(
      extension(
        OID_AUTHORITY_KEY_IDENTIFIER,
        false,
        derSequence([derContext(0, false, authorityKeyIdentifier)]),
      ),
    );
  }
  if (constraints !== null) extensions.push(extension(OID_NAME_CONSTRAINTS, true, constraints));
  return extensions;
}

function shortId(keyIdentifier: Uint8Array): string {
  return Buffer.from(keyIdentifier.subarray(0, 4)).toString("hex");
}

/**
 * Parses a CA once for every leaf it will sign: the certificate must be a CA
 * whose public key matches `keyPem`. Takes the key as bytes so the caller can
 * wipe its buffer after the call; a string PEM cannot be wiped.
 */
export function caSigner(material: { certPem: string; keyPem: string | Buffer }): CaSigner {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(material.certPem);
  } catch {
    throw VaultError.certInvalid("CA certificate PEM is not parseable");
  }
  let key: KeyObject;
  try {
    key = createPrivateKey(material.keyPem);
  } catch {
    throw VaultError.certInvalid("CA private key PEM is not parseable");
  }
  if (!cert.ca) throw VaultError.certInvalid("certificate is not a CA");
  if (key.asymmetricKeyType !== "ec") throw VaultError.certInvalid("CA key is not an EC key");
  if (!cert.checkPrivateKey(key)) throw VaultError.certPrivateKeyMismatch();
  const spki = new Uint8Array(cert.publicKey.export({ type: "spki", format: "der" }));
  return {
    certPem: cert.toString(),
    notAfter: new Date(cert.validTo),
    key,
    issuerName: subjectNameOf(new Uint8Array(cert.raw)),
    keyIdentifier: keyIdentifierOf(spki),
  };
}

export function issueLeaf(ca: CaSigner, options: LeafOptions): LeafCertificate {
  const now = options.now ?? new Date();
  if (!Number.isSafeInteger(options.validityMs) || options.validityMs < 1) {
    throw VaultError.invalidInput("leaf validity must be a positive whole number of milliseconds");
  }
  if (now.getTime() >= ca.notAfter.getTime()) {
    throw VaultError.certExpired("the egress proxy CA");
  }
  const host = parseHost(options.host);
  const notAfter = new Date(Math.min(now.getTime() + options.validityMs, ca.notAfter.getTime()));

  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
  const extensions = [
    extension(OID_BASIC_CONSTRAINTS, true, derSequence([])),
    extension(OID_KEY_USAGE, true, derNamedBitString([KEY_USAGE_DIGITAL_SIGNATURE])),
    extension(OID_EXT_KEY_USAGE, false, derSequence([derOid(OID_KP_SERVER_AUTH)])),
    extension(OID_SUBJECT_ALT_NAME, false, derSequence([generalName(host)])),
    extension(
      OID_AUTHORITY_KEY_IDENTIFIER,
      false,
      derSequence([derContext(0, false, ca.keyIdentifier)]),
    ),
  ];
  const certPem = signCertificate({
    issuerName: ca.issuerName,
    subjectName: host.kind === "dns" ? nameOf(host.value) : organizationOf(LEAF_ORGANIZATION),
    spki,
    notBefore: new Date(now.getTime() - BACKDATE_MS),
    notAfter,
    extensions,
    key: ca.key,
  });
  return {
    certPem,
    keyPem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    notAfter,
  };
}

/**
 * The rule the CA's nameConstraints encode: a DNS host is permitted when it
 * equals a DNS entry or is a subdomain of one, an IP host when it equals an IP
 * entry; case-insensitive. Unparseable hosts are not permitted.
 */
export function hostPermitted(permittedHosts: readonly string[], host: string): boolean {
  let candidate: HostName;
  try {
    candidate = parseHost(host);
  } catch {
    return false;
  }
  return permittedHosts.some((entry) => {
    let base: HostName;
    try {
      base = parseHost(entry);
    } catch {
      return false;
    }
    if (base.kind !== candidate.kind) return false;
    if (base.kind === "ip") return base.value === candidate.value;
    return candidate.value === base.value || candidate.value.endsWith(`.${base.value}`);
  });
}

/** A host as the issuer encodes it: DNS names lowercased LDH ASCII, IP literals canonical. */
export function normalizeHost(host: string): string {
  return parseHost(host).value;
}

function parseHost(input: string): HostName {
  if (!/^[\x21-\x7e]+$/.test(input))
    throw VaultError.invalidInput("host must be an ASCII DNS name or an IP literal");
  const host = input.toLowerCase();
  const family = isIP(host);
  if (family !== 0) {
    if (host.includes("%")) throw VaultError.invalidInput("an IP host must not carry a zone id");
    const bytes = family === 4 ? ipv4Bytes(host) : ipv6Bytes(host);
    return { kind: "ip", value: ipText(bytes), bytes };
  }
  if (
    host.length === 0 ||
    host.length > MAX_DNS_NAME_LENGTH ||
    !host.split(".").every((label) => DNS_LABEL_RE.test(label))
  ) {
    throw VaultError.invalidInput("host must be an ASCII DNS name or an IP literal");
  }
  return { kind: "dns", value: host };
}

function dedupe(hosts: HostName[]): HostName[] {
  const seen = new Set<string>();
  return hosts.filter((host) => {
    const key = `${host.kind}:${host.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function nameConstraints(hosts: HostName[]): Uint8Array {
  const permitted = hosts.map((host) => derSequence([generalSubtreeBase(host)]));
  const excluded: Uint8Array[] = [];
  if (!hosts.some((host) => host.kind === "ip")) {
    excluded.push(derSequence([derContext(GENERAL_NAME_IP, false, new Uint8Array(8))]));
    excluded.push(derSequence([derContext(GENERAL_NAME_IP, false, new Uint8Array(32))]));
  }
  if (!hosts.some((host) => host.kind === "dns")) {
    excluded.push(derSequence([derContext(GENERAL_NAME_DNS, false, new Uint8Array(0))]));
  }
  const fields = [derContext(0, true, concatBytes(permitted))];
  if (excluded.length > 0) fields.push(derContext(1, true, concatBytes(excluded)));
  return derSequence(fields);
}

function generalSubtreeBase(host: HostName): Uint8Array {
  if (host.kind === "dns") return derContext(GENERAL_NAME_DNS, false, ENCODER.encode(host.value));
  const mask = new Uint8Array(host.bytes.length).fill(0xff);
  return derContext(GENERAL_NAME_IP, false, concatBytes([host.bytes, mask]));
}

function generalName(host: HostName): Uint8Array {
  return host.kind === "dns"
    ? derContext(GENERAL_NAME_DNS, false, ENCODER.encode(host.value))
    : derContext(GENERAL_NAME_IP, false, host.bytes);
}

function extension(oid: string, critical: boolean, value: Uint8Array): Uint8Array {
  return derSequence(
    critical
      ? [derOid(oid), derBoolean(true), derOctetString(value)]
      : [derOid(oid), derOctetString(value)],
  );
}

function nameOf(commonName: string): Uint8Array {
  return derSequence([derSet([derSequence([derOid(OID_COMMON_NAME), derUtf8String(commonName)])])]);
}

function organizationOf(organization: string): Uint8Array {
  return derSequence([
    derSet([derSequence([derOid(OID_ORGANIZATION_NAME), derUtf8String(organization)])]),
  ]);
}

function signCertificate(fields: {
  issuerName: Uint8Array;
  subjectName: Uint8Array;
  spki: Uint8Array;
  notBefore: Date;
  notAfter: Date;
  extensions: Uint8Array[];
  key: KeyObject;
}): string {
  const algorithm = derSequence([derOid(OID_ECDSA_WITH_SHA256)]);
  const serial = randomBytes(SERIAL_BYTES);
  serial[0] = ((serial[0] ?? 0) & 0x7f) | 0x40;
  const tbs = derSequence([
    derContext(0, true, derInteger(2)),
    derIntegerFromBytes(serial),
    algorithm,
    fields.issuerName,
    derSequence([derTime(fields.notBefore), derTime(fields.notAfter)]),
    fields.subjectName,
    fields.spki,
    derContext(3, true, derSequence(fields.extensions)),
  ]);
  const signature = createSign("sha256").update(tbs).sign(fields.key);
  const der = derSequence([tbs, algorithm, derBitString(new Uint8Array(signature))]);
  const body = Buffer.from(der)
    .toString("base64")
    .replace(/(.{64})/g, "$1\n")
    .trimEnd();
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

/** RFC 5280 4.2.1.2 method 1: the SHA-1 of the subjectPublicKey BIT STRING's value. */
function keyIdentifierOf(spki: Uint8Array): Uint8Array {
  const [, subjectPublicKey] = childrenOf(spki, 0);
  if (subjectPublicKey === undefined) throw VaultError.certInvalid("SubjectPublicKeyInfo");
  const publicKeyBits = spki.subarray(subjectPublicKey.contentStart + 1, subjectPublicKey.end);
  return new Uint8Array(createHash("sha1").update(publicKeyBits).digest());
}

/** The subject Name of a certificate's TBS, byte for byte (the leaf's issuer). */
function subjectNameOf(certificate: Uint8Array): Uint8Array {
  const [tbs] = childrenOf(certificate, 0);
  const fields = tbs === undefined ? [] : childrenOf(certificate, tbs.start);
  const subject = fields[5];
  if (subject === undefined || certificate[subject.start] !== TAG_SEQUENCE) {
    throw VaultError.certInvalid("CA certificate has no subject");
  }
  return certificate.slice(subject.start, subject.end);
}

interface Tlv {
  start: number;
  contentStart: number;
  end: number;
}

function tlvAt(der: Uint8Array, start: number): Tlv {
  const first = der[start + 1] ?? 0;
  if (first < 0x80) return { start, contentStart: start + 2, end: start + 2 + first };
  const count = first & 0x7f;
  let length = 0;
  for (let i = 0; i < count; i += 1) length = length * 256 + (der[start + 2 + i] ?? 0);
  const contentStart = start + 2 + count;
  return { start, contentStart, end: contentStart + length };
}

function childrenOf(der: Uint8Array, start: number): Tlv[] {
  const parent = tlvAt(der, start);
  if (parent.end > der.length) throw VaultError.certInvalid("truncated DER");
  const out: Tlv[] = [];
  for (let offset = parent.contentStart; offset < parent.end;) {
    const child = tlvAt(der, offset);
    if (child.end > parent.end) throw VaultError.certInvalid("truncated DER");
    out.push(child);
    offset = child.end;
  }
  return out;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function ipv4Bytes(ip: string): Uint8Array {
  return Uint8Array.from(ip.split(".").map((octet) => Number.parseInt(octet, 10)));
}

function ipv6Bytes(ip: string): Uint8Array {
  let text = ip;
  if (text.includes(".")) {
    const cut = text.lastIndexOf(":") + 1;
    const [a = 0, b = 0, c = 0, d = 0] = ipv4Bytes(text.slice(cut));
    text = `${text.slice(0, cut)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const parse = (part: string): number[] =>
    part === "" ? [] : part.split(":").map((group) => Number.parseInt(group, 16));
  const [head = "", tail] = text.split("::");
  const headGroups = parse(head);
  const tailGroups = tail === undefined ? [] : parse(tail);
  const fill = tail === undefined ? 0 : IPV6_GROUPS - headGroups.length - tailGroups.length;
  const groups = [...headGroups, ...new Array<number>(fill).fill(0), ...tailGroups];
  const bytes = new Uint8Array(16);
  groups.forEach((group, i) => {
    bytes[2 * i] = (group >> 8) & 0xff;
    bytes[2 * i + 1] = group & 0xff;
  });
  return bytes;
}

function ipText(bytes: Uint8Array): string {
  if (bytes.length === 4) return Array.from(bytes).join(".");
  const groups: string[] = [];
  for (let i = 0; i < bytes.length; i += 2) {
    groups.push((((bytes[i] ?? 0) << 8) | (bytes[i + 1] ?? 0)).toString(16));
  }
  return new URL(`http://[${groups.join(":")}]/`).hostname.slice(1, -1);
}
