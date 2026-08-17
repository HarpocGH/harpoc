import { setTimeout as delay } from "node:timers/promises";
import { VaultError } from "@harpoc/shared";
import { validateAcmeUrl } from "./directory.js";
import { jwkThumbprint, publicJwk, signJws } from "./jws.js";

export interface AcmeClientOptions {
  directoryUrl: string;
  accountKeyPem: string;
  fetchImpl?: typeof fetch;
  maxRetryAfterMs?: number;
}

export interface AcmeChallenge {
  type: string;
  url: string;
  token: string;
}

export interface AcmeAuthorization {
  domain: string;
  /**
   * RFC 8555 §7.1.4 authorization status. A CA reuses a `valid` authorization
   * for a later order, so the caller must be able to skip solving one.
   */
  status: string;
  challenges: AcmeChallenge[];
}

export interface AcmeOrder {
  orderUrl: string;
  authorizationUrls: string[];
  finalizeUrl: string;
}

export interface AcmeOrderStatus {
  status: string;
  certificateUrl?: string;
}

const JOSE_CONTENT_TYPE = "application/jose+json";
const PEM_CHAIN_CONTENT_TYPE = "application/pem-certificate-chain";
const PEM_CERTIFICATE_MARKER = "-----BEGIN CERTIFICATE-----";
const BAD_NONCE_TYPE = "urn:ietf:params:acme:error:badNonce";
const DEFAULT_PROBLEM_TYPE = "about:blank";
const MAX_POST_ATTEMPTS = 3;
const MAX_POLL_ATTEMPTS = 30;
const DEFAULT_MAX_RETRY_AFTER_MS = 10_000;
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 1_048_576; // 1 MiB, matching the repo's other body caps
const MAX_PROBLEM_TYPE_CHARS = 128;
const UNSETTLED_STATES = new Set(["pending", "processing"]);
const JWS_ALG_BY_CURVE = new Map<string, string>([
  ["P-256", "ES256"],
  ["P-384", "ES384"],
  ["P-521", "ES512"],
]);

interface AcmeDirectory {
  newNonce: string;
  newAccount: string;
  newOrder: string;
}

interface AcmeResponse {
  status: number;
  headers: Headers;
  body: string;
}

interface AcmeProblem {
  type: string;
  status: number | null;
}

export class AcmeClient {
  private readonly directoryUrl: string;
  private readonly accountKeyPem: string;
  private readonly fetchImpl: typeof fetch;
  private readonly maxRetryAfterMs: number;
  private readonly accountJwk: Record<string, string>;
  private readonly alg: string;
  private readonly thumbprint: string;
  private readonly nonces: string[] = [];
  private cachedDirectory: AcmeDirectory | null = null;
  private account: string | null = null;

  constructor(options: AcmeClientOptions) {
    validateAcmeUrl(options.directoryUrl);
    this.directoryUrl = options.directoryUrl;
    this.accountKeyPem = options.accountKeyPem;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.maxRetryAfterMs = Math.min(
      DEFAULT_MAX_RETRY_AFTER_MS,
      Math.max(0, options.maxRetryAfterMs ?? DEFAULT_MAX_RETRY_AFTER_MS),
    );
    this.accountJwk = publicJwk(options.accountKeyPem);
    this.alg = algorithmFor(this.accountJwk);
    this.thumbprint = jwkThumbprint(this.accountJwk);
  }

  get accountUrl(): string | null {
    return this.account;
  }

  set accountUrl(url: string | null) {
    if (url !== null) validateAcmeUrl(url);
    this.account = url;
  }

  keyAuthorization(token: string): string {
    return `${token}.${this.thumbprint}`;
  }

  async ensureAccount(email: string): Promise<string> {
    if (this.account !== null) return this.account;
    const directory = await this.directory();
    const response = await this.signedPost(directory.newAccount, {
      termsOfServiceAgreed: true,
      contact: [`mailto:${email}`],
    });
    const accountUrl = locationOf(response, "newAccount");
    this.account = accountUrl;
    return accountUrl;
  }

  async newOrder(domains: string[]): Promise<AcmeOrder> {
    if (domains.length === 0) {
      throw VaultError.certAcmeFailed("an order needs at least one domain");
    }
    if (domains.some((domain) => domain.trim() === "")) {
      throw VaultError.certAcmeFailed("an order domain must not be blank");
    }
    this.requireAccount();
    const directory = await this.directory();
    const response = await this.signedPost(directory.newOrder, {
      identifiers: domains.map((value) => ({ type: "dns", value })),
    });
    const body = jsonObject(response.body, "order");
    return {
      orderUrl: locationOf(response, "newOrder"),
      authorizationUrls: urlArrayMember(body, "authorizations", "order"),
      finalizeUrl: urlMember(body, "finalize", "order"),
    };
  }

  async getAuthorization(url: string): Promise<AcmeAuthorization> {
    this.requireAccount();
    const response = await this.signedPost(url, "");
    const body = jsonObject(response.body, "authorization");
    return {
      domain: identifierDomain(body),
      status: stringMember(body, "status", "authorization"),
      challenges: challengesOf(body),
    };
  }

  async respondChallenge(url: string): Promise<void> {
    this.requireAccount();
    let response = await this.signedPost(url, {});
    for (let poll = 0; ; poll++) {
      const body = jsonObject(response.body, "challenge");
      const status = stringMember(body, "status", "challenge");
      if (status === "valid") return;
      if (status === "invalid") {
        throw VaultError.certAcmeFailed(`challenge failed validation: ${challengeReason(body)}`);
      }
      if (poll >= MAX_POLL_ATTEMPTS) {
        throw VaultError.certAcmeFailed(
          `challenge did not settle after ${MAX_POLL_ATTEMPTS} polls`,
        );
      }
      await this.waitFor(response.headers);
      response = await this.signedPost(url, "");
    }
  }

  async pollOrder(orderUrl: string): Promise<AcmeOrderStatus> {
    this.requireAccount();
    for (let poll = 1; poll <= MAX_POLL_ATTEMPTS; poll++) {
      const response = await this.signedPost(orderUrl, "");
      const body = jsonObject(response.body, "order");
      const status = stringMember(body, "status", "order");
      if (!UNSETTLED_STATES.has(status)) {
        const certificate = body["certificate"];
        if (typeof certificate !== "string" || certificate === "") return { status };
        validateAcmeUrl(certificate);
        return { status, certificateUrl: certificate };
      }
      if (poll < MAX_POLL_ATTEMPTS) await this.waitFor(response.headers);
    }
    throw VaultError.certAcmeFailed(`order did not settle after ${MAX_POLL_ATTEMPTS} polls`);
  }

  async finalize(finalizeUrl: string, csrDer: Uint8Array): Promise<void> {
    if (csrDer.length === 0) throw VaultError.certAcmeFailed("CSR is empty");
    this.requireAccount();
    await this.signedPost(finalizeUrl, { csr: Buffer.from(csrDer).toString("base64url") });
  }

  async downloadCertificate(certificateUrl: string): Promise<string> {
    this.requireAccount();
    const response = await this.signedPost(certificateUrl, "", PEM_CHAIN_CONTENT_TYPE);
    if (!response.body.includes(PEM_CERTIFICATE_MARKER)) {
      throw VaultError.certAcmeFailed("certificate response carried no PEM certificate");
    }
    return response.body;
  }

  private requireAccount(): void {
    if (this.account === null) {
      throw VaultError.certAcmeFailed("no ACME account — call ensureAccount first");
    }
  }

  private async directory(): Promise<AcmeDirectory> {
    if (this.cachedDirectory !== null) return this.cachedDirectory;
    const response = await this.request(this.directoryUrl, { method: "GET" });
    assertNoProblem(response, "the directory request");
    const body = jsonObject(response.body, "directory");
    const directory: AcmeDirectory = {
      newNonce: urlMember(body, "newNonce", "directory"),
      newAccount: urlMember(body, "newAccount", "directory"),
      newOrder: urlMember(body, "newOrder", "directory"),
    };
    this.cachedDirectory = directory;
    return directory;
  }

  private async takeNonce(): Promise<string> {
    const pooled = this.nonces.pop();
    if (pooled !== undefined) return pooled;
    const directory = await this.directory();
    const response = await this.request(directory.newNonce, { method: "HEAD" });
    assertNoProblem(response, "the newNonce request");
    const fresh = this.nonces.pop();
    if (fresh === undefined) {
      throw VaultError.certAcmeFailed("newNonce response carried no Replay-Nonce header");
    }
    return fresh;
  }

  private async signedPost(
    url: string,
    payload: object | "",
    accept?: string,
  ): Promise<AcmeResponse> {
    validateAcmeUrl(url);
    for (let attempt = 1; ; attempt++) {
      const nonce = await this.takeNonce();
      const headers: Record<string, string> = { "content-type": JOSE_CONTENT_TYPE };
      if (accept !== undefined) headers["accept"] = accept;
      const jws = signJws({
        payload,
        protectedHeader: this.protectedHeader(url, nonce),
        privateKeyPem: this.accountKeyPem,
      });
      const response = await this.request(url, {
        method: "POST",
        headers,
        body: JSON.stringify(jws),
      });
      if (response.status < 400) return response;
      const problem = readProblem(response);
      if (problem.type === BAD_NONCE_TYPE && attempt < MAX_POST_ATTEMPTS) continue;
      throw problemError(problem, "the request");
    }
  }

  private protectedHeader(url: string, nonce: string): Record<string, unknown> {
    return this.account === null
      ? { alg: this.alg, jwk: this.accountJwk, nonce, url }
      : { alg: this.alg, kid: this.account, nonce, url };
  }

  private async request(url: string, init: RequestInit): Promise<AcmeResponse> {
    /* SSRF posture, deliberate and different from core's HTTP injector: ACME
     * endpoints are operator-trusted CA targets (the pinned Let's Encrypt
     * directories or an admin-configured one), so this choke point does
     * scheme/host validation only — no DNS pinning by design. Every URL that
     * reaches fetch passes here, including the ones read out of CA responses,
     * which is only true because redirects are refused rather than followed:
     * a followed hop would reach a host no validateAcmeUrl ever saw, and would
     * re-send a JWS whose protected url names the original target anyway. */
    validateAcmeUrl(url);
    const origin = new URL(url).origin;
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        ...init,
        redirect: "manual",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      throw VaultError.certAcmeFailed(`network request to ${origin} failed`);
    }
    if (response.status >= 300 && response.status < 400) {
      throw VaultError.certAcmeFailed(
        `${origin} answered with redirect status ${response.status}, which is not followed`,
      );
    }
    const nonce = response.headers.get("replay-nonce");
    if (nonce !== null && nonce !== "") this.nonces.push(nonce);
    assertBodyWithinCap(response.headers, origin);
    let body: string;
    try {
      body = await response.text();
    } catch {
      throw VaultError.certAcmeFailed(`response body from ${origin} could not be read`);
    }
    return { status: response.status, headers: response.headers, body };
  }

  private async waitFor(headers: Headers): Promise<void> {
    const header = headers.get("retry-after");
    const requested = header === null ? DEFAULT_POLL_INTERVAL_MS : parseRetryAfter(header);
    const ms = Math.min(Math.max(requested, 0), this.maxRetryAfterMs);
    if (ms > 0) await delay(ms);
  }
}

function algorithmFor(jwk: Record<string, string>): string {
  if (jwk["kty"] === "RSA") return "RS256";
  const curve = jwk["crv"] ?? "";
  const alg = JWS_ALG_BY_CURVE.get(curve);
  if (alg === undefined) {
    throw VaultError.certAcmeFailed(`unsupported account key curve: ${curve || "(absent)"}`);
  }
  return alg;
}

function parseRetryAfter(header: string): number {
  const trimmed = header.trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed) * 1_000;
  const at = Date.parse(trimmed);
  return Number.isNaN(at) ? DEFAULT_POLL_INTERVAL_MS : at - Date.now();
}

function locationOf(response: AcmeResponse, what: string): string {
  const location = response.headers.get("location");
  if (location === null || location === "") {
    throw VaultError.certAcmeFailed(`${what} response carried no Location header`);
  }
  validateAcmeUrl(location);
  return location;
}

function assertBodyWithinCap(headers: Headers, origin: string): void {
  const declared = headers.get("content-length");
  if (declared === null) return;
  const length = Number(declared);
  if (Number.isFinite(length) && length > MAX_RESPONSE_BYTES) {
    throw VaultError.certAcmeFailed(`response body from ${origin} is too large`);
  }
}

function identifierDomain(body: Record<string, unknown>): string {
  const identifier = body["identifier"];
  if (!isRecord(identifier)) {
    throw VaultError.certAcmeFailed("authorization response carried no identifier");
  }
  if (stringMember(identifier, "type", "authorization identifier") !== "dns") {
    throw VaultError.certAcmeFailed("authorization identifier is not a dns identifier");
  }
  return stringMember(identifier, "value", "authorization identifier");
}

function challengesOf(body: Record<string, unknown>): AcmeChallenge[] {
  const challenges = body["challenges"];
  if (!Array.isArray(challenges)) {
    throw VaultError.certAcmeFailed("authorization response carried no challenges");
  }
  return challenges.map((entry) => {
    if (!isRecord(entry)) throw VaultError.certAcmeFailed("challenge entry is not an object");
    return {
      type: stringMember(entry, "type", "challenge"),
      url: urlMember(entry, "url", "challenge"),
      token: stringMember(entry, "token", "challenge"),
    };
  });
}

function challengeReason(body: Record<string, unknown>): string {
  const error = body["error"];
  return isRecord(error) ? describeProblem(problemOf(error, null)) : "no reason given";
}

function assertNoProblem(response: AcmeResponse, what: string): void {
  if (response.status < 400) return;
  throw problemError(readProblem(response), what);
}

function problemError(problem: AcmeProblem, what: string): VaultError {
  return VaultError.certAcmeFailed(`server rejected ${what}: ${describeProblem(problem)}`);
}

function describeProblem(problem: AcmeProblem): string {
  return problem.status === null ? problem.type : `${problem.type} (status ${problem.status})`;
}

function readProblem(response: AcmeResponse): AcmeProblem {
  let parsed: unknown;
  try {
    parsed = JSON.parse(response.body);
  } catch {
    parsed = null;
  }
  return isRecord(parsed)
    ? problemOf(parsed, response.status)
    : { type: DEFAULT_PROBLEM_TYPE, status: response.status };
}

function problemOf(source: Record<string, unknown>, fallbackStatus: number | null): AcmeProblem {
  const type = source["type"];
  const status = source["status"];
  return {
    type: safeProblemType(typeof type === "string" ? type : DEFAULT_PROBLEM_TYPE),
    status: typeof status === "number" && Number.isFinite(status) ? status : fallbackStatus,
  };
}

function safeProblemType(type: string): string {
  const printable = type.replace(/[^ -~]/g, "");
  if (printable === "") return DEFAULT_PROBLEM_TYPE;
  return printable.length > MAX_PROBLEM_TYPE_CHARS
    ? `${printable.slice(0, MAX_PROBLEM_TYPE_CHARS)}...`
    : printable;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonObject(body: string, what: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw VaultError.certAcmeFailed(`${what} response is not valid JSON`);
  }
  if (!isRecord(parsed)) throw VaultError.certAcmeFailed(`${what} response is not a JSON object`);
  return parsed;
}

function stringMember(source: Record<string, unknown>, member: string, what: string): string {
  const value = source[member];
  if (typeof value !== "string" || value === "") {
    throw VaultError.certAcmeFailed(`${what} response is missing the ${member} member`);
  }
  return value;
}

function urlMember(source: Record<string, unknown>, member: string, what: string): string {
  const url = stringMember(source, member, what);
  validateAcmeUrl(url);
  return url;
}

function urlArrayMember(source: Record<string, unknown>, member: string, what: string): string[] {
  const value = source[member];
  if (!Array.isArray(value) || value.length === 0) {
    throw VaultError.certAcmeFailed(`${what} response is missing the ${member} member`);
  }
  return value.map((entry) => {
    if (typeof entry !== "string" || entry === "") {
      throw VaultError.certAcmeFailed(`${what} response has a non-URL ${member} entry`);
    }
    validateAcmeUrl(entry);
    return entry;
  });
}
