import { VaultError } from "@harpoc/shared";
/* CallerContext lives in @harpoc/shared; @harpoc/core neither defines nor
 * re-exports it, and the engine imports it from there too. */
import type { CallerContext, CertificateStatus } from "@harpoc/shared";
import type { VaultEngine } from "@harpoc/core";
import { AcmeClient } from "./acme/acme-client.js";
import type { AcmeAuthorization, AcmeChallenge } from "./acme/acme-client.js";
import { dns01TxtValue, Http01Solver } from "./acme/challenge-solver.js";
import {
  LETS_ENCRYPT_PRODUCTION,
  LETS_ENCRYPT_STAGING,
  validateAcmeUrl,
} from "./acme/directory.js";
import { buildCsr } from "./csr-generator.js";
import { generateCertKeyPair } from "./key-pair.js";
import { parseCertificate, splitChain } from "./pem-parser.js";

const MAX_COMMON_NAME_CHARS = 64; // X.520 ub-common-name
const DEFAULT_HTTP_PORT = 80;
const MAX_PORT = 65_535;
const HTTP_01 = "http-01";
const DNS_01 = "dns-01";
const AUTHORIZATION_VALID = "valid";
const BASE64_BODY = /^[A-Za-z0-9+/]+={0,2}$/;
const PEM_ARMOR = /-----(?:BEGIN|END)[^-]*-----/g;

/** The only directories an account URL alone identifies. */
const DIRECTORY_BY_ACCOUNT_ORIGIN = new Map<string, string>([
  [new URL(LETS_ENCRYPT_PRODUCTION).origin, LETS_ENCRYPT_PRODUCTION],
  [new URL(LETS_ENCRYPT_STAGING).origin, LETS_ENCRYPT_STAGING],
]);

/**
 * The engine surface a certificate manager needs, kept structural like the
 * renewal scheduler's: a full `VaultEngine` satisfies it, and nothing wider is
 * reachable from here.
 */
export type CertificateEngine = Pick<
  VaultEngine,
  | "importCertificate"
  | "updateCertificate"
  | "getCertificatePem"
  | "getCertificateStatus"
  | "getAcmeAccount"
>;

export interface CertManagerOptions {
  fetchImpl?: typeof fetch;
  /** Overrides the staging/production selection for issuance and renewal. */
  directoryUrl?: string;
}

/**
 * `caller` on the three creation inputs is attribution only, the same contract
 * `RenewOptions.caller` carries for renewal and `createSecret` carries for every
 * other create: `create` is not grantable per secret, so token scope governs
 * the call, but the audit rows must still name the principal that made it.
 * Omitting it is the trusted local path.
 */
export interface ImportCertificateInput {
  privateKeyPem: string;
  certificatePem: string;
  chainPem?: string;
  project?: string;
  autoRenew?: boolean;
  renewBeforeDays?: number;
  caller?: CallerContext;
}

export interface GenerateCsrInput {
  commonName: string;
  sans?: string[];
  algorithm?: "rsa" | "ec";
  /** RSA key size; ignored when `algorithm` is `ec`. */
  modulusLength?: 2048 | 4096;
  /** EC named curve; ignored when `algorithm` is `rsa`. */
  namedCurve?: "P-256" | "P-384";
  project?: string;
  caller?: CallerContext;
}

export interface IssueOptions {
  domains: string[];
  email: string;
  staging?: boolean;
  httpPort?: number;
  /** Present = dns-01 mode; the callback publishes the TXT record. */
  dns01?: (domain: string, txtValue: string) => Promise<void>;
  project?: string;
  autoRenew?: boolean;
  renewBeforeDays?: number;
  algorithm?: "rsa" | "ec";
  /** RSA modulus length for the certificate key; only meaningful with algorithm "rsa". Default 2048. */
  modulusLength?: 2048 | 4096;
  /** EC named curve for the certificate key; only meaningful with algorithm "ec". Default "P-256". */
  namedCurve?: "P-256" | "P-384";
  caller?: CallerContext;
}

/**
 * Renewal knobs. The caller rides here rather than in a third parameter so the
 * scheduler's one-argument `renewCertificate(secretId)` stays the trusted local
 * path and a token-bearing interface passes exactly one options object.
 */
export interface RenewOptions {
  httpPort?: number;
  caller?: CallerContext;
  /**
   * The handle the interface resolved `secretId` from. Threaded into every
   * engine read and the write so a policy refusal names it exactly as an
   * unknown handle would (R5).
   */
  handle?: string;
}

export interface CertificateRef {
  handle: string;
  secretId: string;
}

export interface GeneratedCsr extends CertificateRef {
  csrPem: string;
}

export interface IssuedCertificate extends CertificateRef {
  status: CertificateStatus;
}

export class CertManager {
  private readonly engine: CertificateEngine;
  private readonly fetchImpl: typeof fetch | undefined;
  private readonly directoryUrl: string | undefined;

  constructor(engine: CertificateEngine, options?: CertManagerOptions) {
    if (options?.directoryUrl !== undefined) validateAcmeUrl(options.directoryUrl);
    this.engine = engine;
    this.fetchImpl = options?.fetchImpl;
    this.directoryUrl = options?.directoryUrl;
  }

  /**
   * Import an externally issued certificate and its key. A bundle is split so
   * the leaf lands on the certificate row and the intermediates on the chain;
   * an explicitly supplied chain wins over whatever the bundle carried.
   */
  async importCertificate(name: string, input: ImportCertificateInput): Promise<CertificateRef> {
    const { leaf, chain } = splitChain(input.certificatePem);
    const explicitChain =
      input.chainPem === undefined || input.chainPem.trim() === "" ? null : input.chainPem;
    return this.engine.importCertificate(
      name,
      input.privateKeyPem,
      {
        certificatePem: leaf,
        chainPem: explicitChain ?? chain ?? undefined,
        autoRenew: input.autoRenew,
        renewBeforeDays: input.renewBeforeDays,
      },
      input.project,
      input.caller,
    );
  }

  /**
   * Generate a key pair and a PKCS#10 request for it. The secret stays PENDING
   * until the issued certificate arrives through `updateCertificate`.
   */
  async generateCsr(name: string, input: GenerateCsrInput): Promise<GeneratedCsr> {
    assertCommonName(input.commonName);
    assertSans(input.sans ?? []);

    const { privateKeyPem } = generateCertKeyPair({
      algorithm: input.algorithm ?? "rsa",
      modulusLength: input.modulusLength,
      namedCurve: input.namedCurve,
    });
    const { pem } = buildCsr({ privateKeyPem, commonName: input.commonName, sans: input.sans });
    const { handle, secretId } = await this.engine.importCertificate(
      name,
      privateKeyPem,
      { csrPem: pem, subject: `CN=${input.commonName}` },
      input.project,
      input.caller,
    );
    return { handle, secretId, csrPem: pem };
  }

  /**
   * Issue a certificate over ACME. The key pair and its CSR never leave this
   * process before the vault holds them.
   *
   * A rate-limited or unavailable CA surfaces as a terminal CERT_ACME_FAILED:
   * backoff belongs to the RenewalScheduler, not to a single issuance. Every
   * issuance registers its own ACME account (one per certificate, kept
   * encrypted beside it — C44 KEEP), which meets Let's Encrypt's "10 new
   * accounts per IP per 3 hours" limit at the eleventh issuance from one host
   * in that window; a shared, KEK-wrapped account per directory URL is
   * deferred until multi-certificate issuance from one host is a demonstrated
   * use case.
   *
   * The ACME account travels inside the certificate import and commits in the
   * same transaction as the certificate row (E86b): a crash, or a session TTL
   * expiring during a long order, leaves either a complete ACME-issued
   * certificate or nothing — never a certificate the renewal daemon can no
   * longer re-order.
   */
  async issueWithAcme(name: string, options: IssueOptions): Promise<IssuedCertificate> {
    const [commonName] = options.domains;
    if (commonName === undefined) {
      throw VaultError.certAcmeFailed("an order needs at least one domain");
    }
    assertCommonName(commonName);
    assertSans(options.domains);
    if (options.email.trim() === "") {
      throw VaultError.certAcmeFailed("an ACME account needs a contact email");
    }
    assertHttpPort(options.httpPort);

    const { privateKeyPem } = generateCertKeyPair({
      algorithm: options.algorithm ?? "rsa",
      modulusLength: options.modulusLength,
      namedCurve: options.namedCurve,
    });
    const csr = buildCsr({ privateKeyPem, commonName, sans: options.domains });
    // The account key is the manager's own protocol material and stays a fresh
    // P-256 key regardless of what the subscriber certificate was asked for.
    const accountKeyPem = generateCertKeyPair({ algorithm: "ec" }).privateKeyPem;

    const client = new AcmeClient({
      directoryUrl:
        this.directoryUrl ??
        (options.staging === true ? LETS_ENCRYPT_STAGING : LETS_ENCRYPT_PRODUCTION),
      accountKeyPem,
      fetchImpl: this.fetchImpl,
    });
    const accountUrl = await client.ensureAccount(options.email);

    const order = await client.newOrder(options.domains);
    for (const authorizationUrl of order.authorizationUrls) {
      const authorization = await client.getAuthorization(authorizationUrl);
      if (authorization.status === AUTHORIZATION_VALID) continue;
      if (options.dns01 === undefined) {
        await solveHttp01(client, challengeOfType(authorization, HTTP_01), options.httpPort);
      } else {
        const challenge = challengeOfType(authorization, DNS_01);
        const txtValue = dns01TxtValue(client.keyAuthorization(challenge.token));
        await options.dns01(authorization.domain, txtValue);
        await client.respondChallenge(challenge.url);
      }
    }

    const { leaf, chain } = splitChain(await finalizeAndDownload(client, order, csr.der));
    const { handle, secretId } = await this.engine.importCertificate(
      name,
      privateKeyPem,
      {
        certificatePem: leaf,
        chainPem: chain ?? undefined,
        csrPem: csr.pem,
        autoRenew: options.autoRenew,
        renewBeforeDays: options.renewBeforeDays,
        acmeIssued: true,
        acmeAccountJson: JSON.stringify({ privateKeyPem: accountKeyPem, accountUrl }),
      },
      options.project,
      options.caller,
    );

    // The closing read stays caller-less deliberately: passing a caller to
    // getCertificateStatus is a policy *gate*, not attribution, and gating the
    // issuer out of the status of the certificate it just created would be a
    // behaviour change, not the attribution fix.
    return { handle, secretId, status: this.engine.getCertificateStatus(secretId) };
  }

  /**
   * Renew an ACME-issued certificate against its stored account, reusing the
   * stored CSR so the key never changes. Unattended by construction: an
   * authorization the CA still counts as valid is not solved again, and one
   * that is not valid and offers no http-01 challenge is refused rather than
   * half-attempted — only http-01 can be solved without an operator.
   *
   * `options.caller` threads a token-derived identity into every engine read
   * and the write, so per-secret access policies apply (V1); omitting it is the
   * trusted local path the scheduler uses.
   */
  async renewCertificate(secretId: string, options?: RenewOptions): Promise<CertificateStatus> {
    assertHttpPort(options?.httpPort);
    const caller = options?.caller;
    const handle = options?.handle;

    const stored = this.engine.getAcmeAccount(secretId, caller, handle);
    if (stored === null) {
      throw VaultError.certAcmeFailed("no ACME account for this certificate");
    }
    const account = parseAcmeAccount(stored);

    const material = this.engine.getCertificatePem(secretId, caller, handle);
    if (material.csrPem === null) throw VaultError.certCsrFailed("no stored CSR");
    if (material.certificatePem === null) {
      throw VaultError.certInvalid("no stored certificate to renew");
    }
    const domains = parseCertificate(material.certificatePem).sans;
    if (domains.length === 0) {
      throw VaultError.certInvalid("stored certificate carries no subject alternative name");
    }
    const csrDer = pemToDer(material.csrPem);

    const client = new AcmeClient({
      directoryUrl: this.directoryUrl ?? directoryForAccount(account.accountUrl),
      accountKeyPem: account.privateKeyPem,
      fetchImpl: this.fetchImpl,
    });
    client.accountUrl = account.accountUrl;

    const order = await client.newOrder(domains);
    for (const authorizationUrl of order.authorizationUrls) {
      const authorization = await client.getAuthorization(authorizationUrl);
      if (authorization.status === AUTHORIZATION_VALID) continue;
      const challenge = authorization.challenges.find((entry) => entry.type === HTTP_01);
      if (challenge === undefined) {
        throw VaultError.certAcmeFailed("dns-01 renewal requires interactive issuance");
      }
      await solveHttp01(client, challenge, options?.httpPort);
    }

    const { leaf, chain } = splitChain(await finalizeAndDownload(client, order, csrDer));
    await this.engine.updateCertificate(
      secretId,
      leaf,
      chain ?? undefined,
      { renewed: true, handle },
      caller,
    );

    return this.engine.getCertificateStatus(secretId, caller, handle);
  }

  getCertificateInfo(secretId: string, caller?: CallerContext): CertificateStatus {
    return this.engine.getCertificateStatus(secretId, caller);
  }
}

async function solveHttp01(
  client: AcmeClient,
  challenge: AcmeChallenge,
  httpPort: number | undefined,
): Promise<void> {
  const solver = new Http01Solver();
  try {
    await solver.start(
      challenge.token,
      client.keyAuthorization(challenge.token),
      httpPort ?? DEFAULT_HTTP_PORT,
    );
    await client.respondChallenge(challenge.url);
  } finally {
    await solver.stop();
  }
}

async function finalizeAndDownload(
  client: AcmeClient,
  order: { orderUrl: string; finalizeUrl: string },
  csrDer: Uint8Array,
): Promise<string> {
  await client.finalize(order.finalizeUrl, csrDer);
  const status = await client.pollOrder(order.orderUrl);
  if (status.status !== "valid") {
    throw VaultError.certAcmeFailed(`order finished with status ${status.status}`);
  }
  if (status.certificateUrl === undefined) {
    throw VaultError.certAcmeFailed("a valid order carried no certificate URL");
  }
  return client.downloadCertificate(status.certificateUrl);
}

function challengeOfType(authorization: AcmeAuthorization, type: string): AcmeChallenge {
  const challenge = authorization.challenges.find((entry) => entry.type === type);
  if (challenge === undefined) {
    throw VaultError.certAcmeFailed(`${authorization.domain} offers no ${type} challenge`);
  }
  return challenge;
}

function assertCommonName(commonName: string): void {
  if (commonName.trim() === "") throw VaultError.certCsrFailed("common name must not be empty");
  if (commonName.length > MAX_COMMON_NAME_CHARS) {
    throw VaultError.certCsrFailed(`common name exceeds ${MAX_COMMON_NAME_CHARS} characters`);
  }
}

function assertSans(sans: string[]): void {
  if (sans.some((san) => san.trim() === "")) {
    throw VaultError.certCsrFailed("a subject alternative name must not be empty");
  }
}

function assertHttpPort(httpPort: number | undefined): void {
  if (httpPort === undefined) return;
  if (!Number.isInteger(httpPort) || httpPort < 1 || httpPort > MAX_PORT) {
    throw VaultError.certAcmeFailed(`http-01 port must be an integer between 1 and ${MAX_PORT}`);
  }
}

function parseAcmeAccount(json: string): { privateKeyPem: string; accountUrl: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw VaultError.certAcmeFailed("the stored ACME account is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw VaultError.certAcmeFailed("the stored ACME account is not a JSON object");
  }
  const record = parsed as Record<string, unknown>;
  const privateKeyPem = record["privateKeyPem"];
  const accountUrl = record["accountUrl"];
  if (
    typeof privateKeyPem !== "string" ||
    privateKeyPem === "" ||
    typeof accountUrl !== "string" ||
    accountUrl === ""
  ) {
    throw VaultError.certAcmeFailed("the stored ACME account is incomplete");
  }
  validateAcmeUrl(accountUrl);
  return { privateKeyPem, accountUrl };
}

/**
 * A renewal has no `staging` flag to go on — the stored account URL names the
 * CA that issued it. Only the two pinned Let's Encrypt origins map to a known
 * directory; any other CA is refused rather than silently retargeted at Let's
 * Encrypt production, because the directory URL is not derivable from an
 * account URL. Configuring `CertManagerOptions.directoryUrl` names it instead.
 */
function directoryForAccount(accountUrl: string): string {
  const origin = new URL(accountUrl).origin;
  const directory = DIRECTORY_BY_ACCOUNT_ORIGIN.get(origin);
  if (directory === undefined) {
    throw VaultError.certAcmeFailed(
      `no ACME directory is known for account origin ${origin} — set CertManagerOptions.directoryUrl`,
    );
  }
  return directory;
}

function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(PEM_ARMOR, "").replace(/\s+/g, "");
  if (body === "" || !BASE64_BODY.test(body)) {
    throw VaultError.certCsrFailed("the stored CSR is not valid PEM");
  }
  const der = new Uint8Array(Buffer.from(body, "base64"));
  if (der.length === 0) throw VaultError.certCsrFailed("the stored CSR is not valid PEM");
  return der;
}
