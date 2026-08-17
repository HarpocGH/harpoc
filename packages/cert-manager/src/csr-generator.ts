import { createPrivateKey, createPublicKey, createSign } from "node:crypto";
import { isIP } from "node:net";
import { VaultError } from "@harpoc/shared";
import {
  derBitString,
  derContext,
  derInteger,
  derNull,
  derOctetString,
  derOid,
  derSequence,
  derSet,
  derUtf8String,
} from "./der.js";

/*
 * PKCS#10 (RFC 2986) CertificationRequest over the der.ts writer. Two spec
 * details the shape below encodes deliberately: the attributes field is an
 * IMPLICIT [0] SET OF Attribute, so the context tag replaces the SET tag rather
 * than wrapping one; and ecdsa-with-SHA256 takes NO algorithm parameters at all
 * (RFC 5758 §3.2), unlike sha256WithRSAEncryption which takes an explicit NULL.
 */

const OID_COMMON_NAME = "2.5.4.3";
const OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14";
const OID_SUBJECT_ALT_NAME = "2.5.29.17";
const OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
const OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";

const GENERAL_NAME_DNS = 2;
const GENERAL_NAME_IP = 7;
const IPV6_GROUPS = 8;

const TEXT_ENCODER = new TextEncoder();

export interface CsrOptions {
  privateKeyPem: string;
  commonName: string;
  sans?: string[];
}

export function buildCsr(options: CsrOptions): { pem: string; der: Uint8Array } {
  let key: ReturnType<typeof createPrivateKey>;
  try {
    key = createPrivateKey(options.privateKeyPem);
  } catch {
    throw VaultError.certCsrFailed("private key PEM is not parseable");
  }
  const isRsa = key.asymmetricKeyType === "rsa";
  if (!isRsa && key.asymmetricKeyType !== "ec") {
    throw VaultError.certCsrFailed(`unsupported key type: ${String(key.asymmetricKeyType)}`);
  }

  const spki = new Uint8Array(createPublicKey(key).export({ type: "spki", format: "der" }));

  const subject = derSequence([
    derSet([derSequence([derOid(OID_COMMON_NAME), derUtf8String(options.commonName)])]),
  ]);

  const sans = options.sans ?? [];
  let attributes = derContext(0, true, new Uint8Array(0));
  if (sans.length > 0) {
    const generalNames = derSequence(
      sans.map((san) =>
        isIP(san) !== 0
          ? derContext(GENERAL_NAME_IP, false, ipToBytes(san))
          : derContext(GENERAL_NAME_DNS, false, dnsNameBytes(san)),
      ),
    );
    const sanExtension = derSequence([derOid(OID_SUBJECT_ALT_NAME), derOctetString(generalNames)]);
    const extensions = derSequence([sanExtension]);
    attributes = derContext(
      0,
      true,
      derSequence([derOid(OID_EXTENSION_REQUEST), derSet([extensions])]),
    );
  }

  const tbs = derSequence([derInteger(0), subject, spki, attributes]);

  const algId = isRsa
    ? derSequence([derOid(OID_SHA256_WITH_RSA), derNull()])
    : derSequence([derOid(OID_ECDSA_WITH_SHA256)]);

  const signature = new Uint8Array(createSign("sha256").update(tbs).sign(key));
  const der = derSequence([tbs, algId, derBitString(signature)]);
  const body = Buffer.from(der)
    .toString("base64")
    .replace(/(.{64})/g, "$1\n")
    .trimEnd();
  return {
    der,
    pem: `-----BEGIN CERTIFICATE REQUEST-----\n${body}\n-----END CERTIFICATE REQUEST-----\n`,
  };
}

function dnsNameBytes(name: string): Uint8Array {
  for (let i = 0; i < name.length; i += 1) {
    if (name.charCodeAt(i) > 0x7f) {
      throw VaultError.certCsrFailed("dNSName SAN contains a non-ASCII character");
    }
  }
  return TEXT_ENCODER.encode(name);
}

function ipToBytes(ip: string): Uint8Array {
  if (isIP(ip) === 4) return Uint8Array.from(ip.split(".").map((o) => Number.parseInt(o, 10)));
  const groups = expandIpv6(ip);
  if (groups.length !== IPV6_GROUPS || groups.some((g) => !Number.isInteger(g) || g > 0xffff)) {
    throw VaultError.certCsrFailed("iPAddress SAN is not a representable IPv6 address");
  }
  const bytes: number[] = [];
  for (const group of groups) {
    bytes.push((group >> 8) & 0xff, group & 0xff);
  }
  return Uint8Array.from(bytes);
}

function expandIpv6(ip: string): number[] {
  const text = foldEmbeddedIpv4(ip);
  const parse = (part: string): number[] =>
    part === "" ? [] : part.split(":").map((g) => Number.parseInt(g, 16));
  if (!text.includes("::")) return parse(text);
  const [head = "", tail = ""] = text.split("::");
  const headGroups = parse(head);
  const tailGroups = parse(tail);
  const fill = new Array<number>(IPV6_GROUPS - headGroups.length - tailGroups.length).fill(0);
  return [...headGroups, ...fill, ...tailGroups];
}

function foldEmbeddedIpv4(ip: string): string {
  if (!ip.includes(".")) return ip;
  const cut = ip.lastIndexOf(":") + 1;
  const [a = 0, b = 0, c = 0, d = 0] = ip
    .slice(cut)
    .split(".")
    .map((o) => Number.parseInt(o, 10));
  return `${ip.slice(0, cut)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
}
