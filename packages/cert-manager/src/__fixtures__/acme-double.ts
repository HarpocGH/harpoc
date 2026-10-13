import {
  createHash,
  createPublicKey,
  createSign,
  generateKeyPairSync,
  randomBytes,
  verify,
  X509Certificate,
} from "node:crypto";
import type { KeyObject } from "node:crypto";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  derBitString,
  derBoolean,
  derContext,
  derInteger,
  derOctetString,
  derOid,
  derSequence,
  derSet,
  derUtf8String,
} from "../der.js";

/*
 * A local RFC 8555 CA double for the composed issuance and renewal cases
 * (test-review-2026-10-09 M-P3-5): a loopback node:http server speaking the
 * subset the in-house AcmeClient uses, and a CA that signs each CSR it is
 * handed with its own P-256 key. Every JWS signature is verified against the
 * account's key, every nonce is single-use and every order is bound to its
 * account; identifiers meet no issuance policy, and the http-01 response is
 * fetched from 127.0.0.1 at the port the test names, whatever the domain.
 */

const CA_NAME = "Harpoc ACME Double CA";
const OID_COMMON_NAME = "2.5.4.3";
const OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
const OID_BASIC_CONSTRAINTS = "2.5.29.19";
const OID_SUBJECT_ALT_NAME = "2.5.29.17";
const DAY_MS = 86_400_000;

export interface AcmeDoubleRequest {
  method: string;
  path: string;
  protectedHeader: Record<string, unknown> | null;
  payload: unknown;
}

export interface AcmeDouble {
  directoryUrl: string;
  caCertificate: X509Certificate;
  caPem: string;
  /** Every request in arrival order, the JWS decoded. */
  requests: AcmeDoubleRequest[];
  /** The subjectPublicKeyInfo (DER) of every CSR the double signed. */
  csrPublicKeys: Buffer[];
  close(): Promise<void>;
}

interface Order {
  account: string;
  status: string;
  domains: string[];
  authorizations: number[];
  certificate?: string;
}

interface Authorization {
  order: number;
  domain: string;
  token: string;
  status: string;
}

export async function startAcmeDouble(options: { httpPort: number }): Promise<AcmeDouble> {
  const ca = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const caName = nameOf(CA_NAME);
  const caSpki = ca.publicKey.export({ type: "spki", format: "der" });
  const caPem = toPem(issue(ca.privateKey, caName, caName, caSpki, [], true));
  const requests: AcmeDoubleRequest[] = [];
  const csrPublicKeys: Buffer[] = [];
  const nonces = new Set<string>();
  const accounts = new Map<string, JsonWebKey>();
  const orders: Order[] = [];
  const authorizations: Authorization[] = [];
  let origin = "";

  const send = (res: ServerResponse, status: number, body: unknown, location?: string): void => {
    const nonce = randomBytes(16).toString("base64url");
    nonces.add(nonce);
    const headers: Record<string, string> = { "replay-nonce": nonce };
    if (location !== undefined) headers["location"] = location;
    if (typeof body === "string") headers["content-type"] = "application/pem-certificate-chain";
    else if (body !== null) headers["content-type"] = "application/json";
    res.writeHead(status, headers);
    res.end(body === null ? undefined : typeof body === "string" ? body : JSON.stringify(body));
  };
  const problem = (res: ServerResponse, status: number, type: string): void => {
    send(res, status, { type: `urn:ietf:params:acme:error:${type}`, status });
  };
  const orderBody = (id: number): Record<string, unknown> => {
    const order = orders[id] as Order;
    return {
      status: order.status,
      identifiers: order.domains.map((value) => ({ type: "dns", value })),
      authorizations: order.authorizations.map((a) => `${origin}/authz/${a}`),
      finalize: `${origin}/finalize/${id}`,
      ...(order.certificate === undefined ? {} : { certificate: `${origin}/cert/${id}` }),
    };
  };
  const challengeBody = (id: number): Record<string, unknown> => {
    const authz = authorizations[id] as Authorization;
    const failed = { error: { type: "urn:ietf:params:acme:error:incorrectResponse", status: 403 } };
    return {
      type: "http-01",
      url: `${origin}/chall/${id}`,
      token: authz.token,
      status: authz.status,
      ...(authz.status === "invalid" ? failed : {}),
    };
  };

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const path = req.url ?? "/";
    const raw = await readBody(req);
    if (req.method !== "POST") {
      requests.push({ method: req.method ?? "", path, protectedHeader: null, payload: null });
      if (path === "/new-nonce") return send(res, 200, null);
      if (path !== "/directory") return problem(res, 404, "malformed");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          newNonce: `${origin}/new-nonce`,
          newAccount: `${origin}/new-account`,
          newOrder: `${origin}/new-order`,
          revokeCert: `${origin}/revoke-cert`,
          keyChange: `${origin}/key-change`,
        }),
      );
      return;
    }
    const jws = JSON.parse(raw) as { protected: string; payload: string; signature: string };
    const header = decode(jws.protected) as Record<string, unknown>;
    const payload = jws.payload === "" ? "" : decode(jws.payload);
    requests.push({ method: "POST", path, protectedHeader: header, payload });
    if (typeof header.nonce !== "string" || !nonces.delete(header.nonce)) {
      return problem(res, 400, "badNonce");
    }
    if (header.alg !== "ES256") return problem(res, 400, "badSignatureAlgorithm");
    if (header.url !== `${origin}${path}`) return problem(res, 401, "unauthorized");
    const isNewAccount = path === "/new-account";
    const jwk = isNewAccount ? (header.jwk as JsonWebKey) : accounts.get(String(header.kid));
    if (jwk === undefined) return problem(res, 400, "accountDoesNotExist");
    const signingInput = Buffer.from(`${jws.protected}.${jws.payload}`);
    const key = createPublicKey({ key: jwk, format: "jwk" });
    const signature = Buffer.from(jws.signature, "base64url");
    if (!verify("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, signature)) {
      return problem(res, 401, "unauthorized");
    }
    if (isNewAccount) {
      const account = `${origin}/acct/${accounts.size + 1}`;
      accounts.set(account, jwk);
      return send(res, 201, { status: "valid" }, account);
    }
    const account = String(header.kid);
    const [, kind, segment] = path.split("/");
    const id = Number(segment);
    if (kind === "new-order") {
      const { identifiers } = payload as { identifiers: { value: string }[] };
      const domains = identifiers.map((identifier) => identifier.value);
      const orderId = orders.length;
      const ids = domains.map((domain) => {
        const token = randomBytes(32).toString("base64url");
        return authorizations.push({ order: orderId, domain, token, status: "pending" }) - 1;
      });
      orders.push({ account, status: "pending", domains, authorizations: ids });
      return send(res, 201, orderBody(orderId), `${origin}/order/${orderId}`);
    }
    const authz = kind === "authz" || kind === "chall" ? authorizations[id] : undefined;
    const order = authz === undefined ? orders[id] : orders[authz.order];
    if (order === undefined || order.account !== account) return problem(res, 403, "unauthorized");
    if (kind === "authz" && authz !== undefined) {
      return send(res, 200, {
        identifier: { type: "dns", value: authz.domain },
        status: authz.status,
        challenges: [challengeBody(id)],
      });
    }
    if (kind === "chall" && authz !== undefined) {
      if (payload !== "" && authz.status === "pending") {
        const url = `http://127.0.0.1:${options.httpPort}/.well-known/acme-challenge/${authz.token}`;
        const answer = await fetch(url).then(
          (response) => response.text(),
          () => "",
        );
        authz.status = answer === `${authz.token}.${thumbprint(jwk)}` ? "valid" : "invalid";
        const states = order.authorizations.map((a) => authorizations[a]?.status);
        if (authz.status === "invalid") order.status = "invalid";
        else if (states.every((state) => state === "valid")) order.status = "ready";
      }
      return send(res, 200, challengeBody(id));
    }
    if (kind === "finalize") {
      if (order.status !== "ready") return problem(res, 403, "orderNotReady");
      const csr = Buffer.from((payload as { csr: string }).csr, "base64url");
      const [info, , csrSignature] = children(csr);
      const [, subject, spki] = info === undefined ? [] : children(info);
      if (info === undefined || subject === undefined || spki === undefined) {
        return problem(res, 400, "badCSR");
      }
      const csrKey = createPublicKey({ key: spki, format: "der", type: "spki" });
      const possession = csrSignature?.subarray(tlvAt(csrSignature, 0).header + 1);
      if (possession === undefined || !verify("sha256", info, csrKey, possession)) {
        return problem(res, 400, "badCSR");
      }
      csrPublicKeys.push(spki);
      const leaf = issue(ca.privateKey, caName, subject, spki, order.domains, false);
      order.certificate = `${toPem(leaf)}${caPem}`;
      order.status = "valid";
      return send(res, 200, orderBody(id));
    }
    if (kind === "order") return send(res, 200, orderBody(id));
    if (kind === "cert" && order.certificate !== undefined)
      return send(res, 200, order.certificate);
    return problem(res, 404, "malformed");
  }

  const server = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) problem(res, 500, "serverInternal");
      else res.destroy();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  return {
    directoryUrl: `${origin}/directory`,
    caCertificate: new X509Certificate(caPem),
    caPem,
    requests,
    csrPublicKeys,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

/** A version-3 certificate over `subjectSpki`, signed ecdsa-with-SHA256 by `caKey`. */
function issue(
  caKey: KeyObject,
  issuer: Uint8Array,
  subject: Uint8Array,
  subjectSpki: Uint8Array,
  domains: string[],
  isCa: boolean,
): Uint8Array {
  const now = Date.now();
  const algorithm = derSequence([derOid(OID_ECDSA_WITH_SHA256)]);
  const extensions = [
    derSequence([
      derOid(OID_BASIC_CONSTRAINTS),
      derBoolean(true),
      derOctetString(derSequence(isCa ? [derBoolean(true)] : [])),
    ]),
  ];
  if (domains.length > 0) {
    const names = domains.map((d) => derContext(2, false, new TextEncoder().encode(d)));
    extensions.push(
      derSequence([derOid(OID_SUBJECT_ALT_NAME), derOctetString(derSequence(names))]),
    );
  }
  const tbs = derSequence([
    derContext(0, true, derInteger(2)),
    derInteger(randomBytes(6).readUIntBE(0, 6) + 1),
    algorithm,
    issuer,
    derSequence([utcTime(now - DAY_MS), utcTime(now + 90 * DAY_MS)]),
    subject,
    subjectSpki,
    derContext(3, true, derSequence(extensions)),
  ]);
  const signature = createSign("sha256").update(tbs).sign(caKey);
  return derSequence([tbs, algorithm, derBitString(new Uint8Array(signature))]);
}

function nameOf(commonName: string): Uint8Array {
  return derSequence([derSet([derSequence([derOid(OID_COMMON_NAME), derUtf8String(commonName)])])]);
}

function utcTime(ms: number): Uint8Array {
  const text = `${new Date(ms).toISOString().replace(/[-:T]/g, "").slice(2, 14)}Z`;
  return Uint8Array.from([0x17, text.length, ...Buffer.from(text, "ascii")]);
}

function toPem(der: Uint8Array): string {
  const body = Buffer.from(der)
    .toString("base64")
    .replace(/(.{64})/g, "$1\n")
    .trimEnd();
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

function tlvAt(der: Buffer, offset: number): { header: number; end: number } {
  const first = der[offset + 1] ?? 0;
  if (first < 0x80) return { header: 2, end: offset + 2 + first };
  let length = 0;
  for (let i = 0; i < (first & 0x7f); i++) length = length * 256 + (der[offset + 2 + i] ?? 0);
  return { header: 2 + (first & 0x7f), end: offset + 2 + (first & 0x7f) + length };
}

function children(der: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const { header, end } = tlvAt(der, 0);
  for (let offset = header; offset < end; offset = tlvAt(der, offset).end) {
    out.push(der.subarray(offset, tlvAt(der, offset).end));
  }
  return out;
}

function thumbprint(jwk: JsonWebKey): string {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return createHash("sha256").update(canonical).digest("base64url");
}

function decode(part: string): unknown {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}
