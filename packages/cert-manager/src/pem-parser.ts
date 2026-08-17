import { createPrivateKey, X509Certificate } from "node:crypto";
import { VaultError } from "@harpoc/shared";

export interface ParsedCertificate {
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: number;
  notAfter: number;
  sans: string[];
}

const PEM_CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

export function parseCertificate(pem: string): ParsedCertificate {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(pem);
  } catch {
    throw VaultError.certInvalid("certificate PEM is not parseable");
  }
  const sans = (cert.subjectAltName ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.startsWith("DNS:") || s.startsWith("IP Address:"))
    .map((s) => s.replace(/^DNS:|^IP Address:/, ""));
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    notBefore: new Date(cert.validFrom).getTime(),
    notAfter: new Date(cert.validTo).getTime(),
    sans,
  };
}

export function splitChain(bundlePem: string): { leaf: string; chain: string | null } {
  const blocks = bundlePem.match(PEM_CERT_RE);
  if (!blocks || blocks.length === 0) {
    throw VaultError.certInvalid("no certificate block found");
  }
  const [leaf, ...rest] = blocks;
  return { leaf, chain: rest.length > 0 ? rest.join("\n") : null };
}

export function assertKeyMatchesCert(privateKeyPem: string, certPem: string): void {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(certPem);
  } catch {
    throw VaultError.certInvalid("certificate PEM is not parseable");
  }
  let key: ReturnType<typeof createPrivateKey>;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch {
    throw VaultError.certInvalid("private key PEM is not parseable");
  }
  if (!cert.checkPrivateKey(key)) throw VaultError.certPrivateKeyMismatch();
}
