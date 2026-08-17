import { generateKeyPairSync } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { generateCertKeyPair } from "../key-pair.js";
import { jwkThumbprint, publicJwk } from "./jws.js";
import { AcmeClient } from "./acme-client.js";
import type { AcmeClientOptions } from "./acme-client.js";

const DIRECTORY_URL = "https://acme.example.com/directory";
const NEW_NONCE_URL = "https://acme.example.com/acme/new-nonce";
const NEW_ACCOUNT_URL = "https://acme.example.com/acme/new-acct";
const NEW_ORDER_URL = "https://acme.example.com/acme/new-order";
const ACCOUNT_URL = "https://acme.example.com/acme/acct/1";
const ORDER_URL = "https://acme.example.com/acme/order/1";
const AUTHZ_URL = "https://acme.example.com/acme/authz/1";
const HTTP01_URL = "https://acme.example.com/acme/chall/1";
const DNS01_URL = "https://acme.example.com/acme/chall/2";
const FINALIZE_URL = "https://acme.example.com/acme/order/1/finalize";
const CERTIFICATE_URL = "https://acme.example.com/acme/cert/1";

const DIRECTORY_BODY = {
  newNonce: NEW_NONCE_URL,
  newAccount: NEW_ACCOUNT_URL,
  newOrder: NEW_ORDER_URL,
  revokeCert: "https://acme.example.com/acme/revoke-cert",
  keyChange: "https://acme.example.com/acme/key-change",
};

const PEM_CHAIN =
  "-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----\n" +
  "-----BEGIN CERTIFICATE-----\naXNzdWVy\n-----END CERTIFICATE-----\n";

const BAD_NONCE_TYPE = "urn:ietf:params:acme:error:badNonce";

const accountKeyPem = generateCertKeyPair({ algorithm: "ec" }).privateKeyPem;
const accountJwk = publicJwk(accountKeyPem);

const acmeFailed = expect.objectContaining({ code: ErrorCode.CERT_ACME_FAILED });

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  redirect: RequestRedirect | undefined;
}

const headerRecord = (init: HeadersInit | undefined): Record<string, string> => {
  const record: Record<string, string> = {};
  new Headers(init).forEach((value, key) => {
    record[key] = value;
  });
  return record;
};

class FakeCa {
  readonly calls: Call[] = [];
  private readonly queue: Response[] = [];

  readonly fetch: typeof fetch = (input, init) => {
    const next = this.queue.shift();
    this.calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: headerRecord(init?.headers),
      body: typeof init?.body === "string" ? init.body : "",
      redirect: init?.redirect,
    });
    if (next === undefined) {
      return Promise.reject(new Error(`unexpected request to ${String(input)}`));
    }
    return Promise.resolve(next);
  };

  enqueue(...responses: Response[]): this {
    this.queue.push(...responses);
    return this;
  }

  posts(): Call[] {
    return this.calls.filter((call) => call.method === "POST");
  }

  heads(): Call[] {
    return this.calls.filter((call) => call.method === "HEAD");
  }
}

const json = (
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
): Response =>
  new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...init.headers },
  });

const nonce = (value: string): Response =>
  new Response(null, { status: 200, headers: { "replay-nonce": value } });

const problem = (
  status: number,
  type: string,
  detail: string,
  headers: Record<string, string> = {},
): Response =>
  json(
    { type, status, detail },
    { status, headers: { "content-type": "application/problem+json", ...headers } },
  );

const badNonce = (fresh: string): Response =>
  problem(400, BAD_NONCE_TYPE, "JWS has an invalid anti-replay nonce: STALE", {
    "replay-nonce": fresh,
  });

const authorizationBody = (): unknown => ({
  identifier: { type: "dns", value: "a.example.com" },
  status: "pending",
  challenges: [
    { type: "http-01", url: HTTP01_URL, token: "tok-http", status: "pending" },
    { type: "dns-01", url: DNS01_URL, token: "tok-dns", status: "pending" },
  ],
});

/** A CA whose directory has already been served — the queue starts at newNonce. */
const caWith = (...responses: Response[]): FakeCa =>
  new FakeCa().enqueue(json(DIRECTORY_BODY), ...responses);

const jwsOf = (call: Call): { protected: string; payload: string; signature: string } =>
  JSON.parse(call.body) as { protected: string; payload: string; signature: string };

const headerOf = (call: Call): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwsOf(call).protected, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;

const payloadOf = (call: Call): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwsOf(call).payload, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;

const at = (calls: Call[], index: number): Call => {
  const call = calls[index];
  if (call === undefined) throw new Error(`no call at index ${index} (have ${calls.length})`);
  return call;
};

const messageOf = async (run: () => Promise<unknown>): Promise<string> => {
  try {
    await run();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  return "(did not throw)";
};

const makeClient = (ca: FakeCa, overrides: Partial<AcmeClientOptions> = {}): AcmeClient =>
  new AcmeClient({
    directoryUrl: DIRECTORY_URL,
    accountKeyPem,
    fetchImpl: ca.fetch,
    maxRetryAfterMs: 0,
    ...overrides,
  });

const registeredClient = (ca: FakeCa, overrides: Partial<AcmeClientOptions> = {}): AcmeClient => {
  const client = makeClient(ca, overrides);
  client.accountUrl = ACCOUNT_URL;
  return client;
};

describe("AcmeClient happy path", () => {
  const ca = new FakeCa();
  const csrDer = new Uint8Array([0x30, 0x82, 0x01, 0x0a, 0xff, 0xfe, 0x00, 0x7f]);
  let calls: Call[];
  let order: { orderUrl: string; authorizationUrls: string[]; finalizeUrl: string };
  let authorization: { domain: string; challenges: { type: string; url: string; token: string }[] };
  let polled: { status: string; certificateUrl?: string };
  let chain: string;

  beforeAll(async () => {
    ca.enqueue(
      json(DIRECTORY_BODY),
      nonce("n1"),
      json(
        { status: "valid", contact: ["mailto:ops@example.com"] },
        { status: 201, headers: { location: ACCOUNT_URL, "replay-nonce": "n2" } },
      ),
      json(
        { status: "pending", authorizations: [AUTHZ_URL], finalize: FINALIZE_URL },
        { status: 201, headers: { location: ORDER_URL, "replay-nonce": "n3" } },
      ),
      json(authorizationBody(), { headers: { "replay-nonce": "n4" } }),
      json(
        { type: "http-01", url: HTTP01_URL, token: "tok-http", status: "pending" },
        { headers: { "replay-nonce": "n5" } },
      ),
      json(
        { type: "http-01", url: HTTP01_URL, token: "tok-http", status: "valid" },
        { headers: { "replay-nonce": "n6" } },
      ),
      json({ status: "processing" }, { headers: { "replay-nonce": "n7" } }),
      json(
        { status: "valid", certificate: CERTIFICATE_URL },
        { headers: { "replay-nonce": "n8" } },
      ),
      new Response(PEM_CHAIN, {
        status: 200,
        headers: { "content-type": "application/pem-certificate-chain", "replay-nonce": "n9" },
      }),
    );

    const client = makeClient(ca);
    expect(await client.ensureAccount("ops@example.com")).toBe(ACCOUNT_URL);
    order = await client.newOrder(["a.example.com"]);
    const authzUrl = order.authorizationUrls[0];
    if (authzUrl === undefined) throw new Error("no authorization URL");
    authorization = await client.getAuthorization(authzUrl);
    const challenge = authorization.challenges.find((entry) => entry.type === "http-01");
    if (challenge === undefined) throw new Error("no http-01 challenge");
    await client.respondChallenge(challenge.url);
    await client.finalize(order.finalizeUrl, csrDer);
    polled = await client.pollOrder(order.orderUrl);
    chain = await client.downloadCertificate(polled.certificateUrl ?? "");
    calls = ca.calls;
  });

  it("issues exactly the ten requests the flow needs, in order", () => {
    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `GET ${DIRECTORY_URL}`,
      `HEAD ${NEW_NONCE_URL}`,
      `POST ${NEW_ACCOUNT_URL}`,
      `POST ${NEW_ORDER_URL}`,
      `POST ${AUTHZ_URL}`,
      `POST ${HTTP01_URL}`,
      `POST ${HTTP01_URL}`,
      `POST ${FINALIZE_URL}`,
      `POST ${ORDER_URL}`,
      `POST ${CERTIFICATE_URL}`,
    ]);
  });

  it("fetches the directory once, with a bodyless GET, and newNonce once", () => {
    expect(calls.filter((call) => call.url === DIRECTORY_URL)).toHaveLength(1);
    expect(calls.filter((call) => call.url === NEW_NONCE_URL)).toHaveLength(1);
    expect(at(calls, 0).body).toBe("");
  });

  it("chains every Replay-Nonce from the previous response into the next POST", () => {
    expect(ca.posts().map((call) => headerOf(call)["nonce"])).toEqual([
      "n1",
      "n2",
      "n3",
      "n4",
      "n5",
      "n6",
      "n7",
      "n8",
    ]);
  });

  it("signs newAccount with a jwk header and the terms-of-service payload", () => {
    const call = at(calls, 2);
    expect(call.headers["content-type"]).toBe("application/jose+json");
    expect(headerOf(call)).toEqual({
      alg: "ES256",
      jwk: accountJwk,
      nonce: "n1",
      url: NEW_ACCOUNT_URL,
    });
    expect(payloadOf(call)).toEqual({
      termsOfServiceAgreed: true,
      contact: ["mailto:ops@example.com"],
    });
  });

  it("switches to a kid header once the account exists", () => {
    for (const index of [3, 4, 5, 6, 7, 8, 9]) {
      const header = headerOf(at(calls, index));
      expect(header["kid"]).toBe(ACCOUNT_URL);
      expect(header["jwk"]).toBeUndefined();
      expect(header["alg"]).toBe("ES256");
    }
  });

  it("binds every protected header to the URL the request is sent to", () => {
    for (const call of ca.posts()) {
      expect(headerOf(call)["url"]).toBe(call.url);
    }
  });

  it("orders the identifiers as dns entries and returns the order URLs", () => {
    expect(payloadOf(at(calls, 3))).toEqual({
      identifiers: [{ type: "dns", value: "a.example.com" }],
    });
    expect(order).toEqual({
      orderUrl: ORDER_URL,
      authorizationUrls: [AUTHZ_URL],
      finalizeUrl: FINALIZE_URL,
    });
  });

  it("reads the authorization with POST-as-GET and returns its domain, status and challenges", () => {
    expect(jwsOf(at(calls, 4)).payload).toBe("");
    expect(authorization).toEqual({
      domain: "a.example.com",
      status: "pending",
      challenges: [
        { type: "http-01", url: HTTP01_URL, token: "tok-http" },
        { type: "dns-01", url: DNS01_URL, token: "tok-dns" },
      ],
    });
  });

  it("responds to the challenge with an empty JSON object, then polls it", () => {
    expect(payloadOf(at(calls, 5))).toEqual({});
    expect(jwsOf(at(calls, 6)).payload).toBe("");
  });

  it("finalizes with the base64url of the DER CSR and nothing else", () => {
    const payload = payloadOf(at(calls, 7));
    expect(Object.keys(payload)).toEqual(["csr"]);
    expect(payload["csr"]).toBe("MIIBCv_-AH8");
    expect(payload["csr"]).toBe(Buffer.from(csrDer).toString("base64url"));
  });

  it("polls the order and downloads the PEM chain with POST-as-GET", () => {
    expect(polled).toEqual({ status: "valid", certificateUrl: CERTIFICATE_URL });
    expect(jwsOf(at(calls, 9)).payload).toBe("");
    expect(at(calls, 9).headers["accept"]).toBe("application/pem-certificate-chain");
    expect(chain).toBe(PEM_CHAIN);
  });
});

describe("AcmeClient account handling", () => {
  it("treats an existing-account 200 with a Location header as success", async () => {
    const ca = caWith(
      nonce("n1"),
      json(
        { status: "valid" },
        { status: 200, headers: { location: ACCOUNT_URL, "replay-nonce": "n2" } },
      ),
    );
    const client = makeClient(ca);
    expect(await client.ensureAccount("ops@example.com")).toBe(ACCOUNT_URL);
    expect(client.accountUrl).toBe(ACCOUNT_URL);
  });

  /*
   * RFC 8555 §6.2: newAccount is one of the two requests that MUST be signed
   * with an embedded jwk, never a kid. A second ensureAccount must therefore
   * not re-POST it once an account URL is known — Boulder answers a kid-signed
   * newAccount with `malformed`.
   */
  it("is idempotent: a second ensureAccount issues no request at all", async () => {
    const ca = caWith(
      nonce("n1"),
      json({}, { status: 201, headers: { location: ACCOUNT_URL, "replay-nonce": "n2" } }),
    );
    const client = makeClient(ca);
    expect(await client.ensureAccount("ops@example.com")).toBe(ACCOUNT_URL);
    expect(await client.ensureAccount("ops@example.com")).toBe(ACCOUNT_URL);
    expect(await client.ensureAccount("someone-else@example.com")).toBe(ACCOUNT_URL);
    expect(ca.posts()).toHaveLength(1);
    expect(ca.calls).toHaveLength(3);
    const header = headerOf(at(ca.posts(), 0));
    expect(header["jwk"]).toEqual(accountJwk);
    expect(header["kid"]).toBeUndefined();
  });

  it("short-circuits ensureAccount for a restored account, touching no network", async () => {
    const ca = new FakeCa();
    const client = makeClient(ca);
    client.accountUrl = ACCOUNT_URL;
    expect(await client.ensureAccount("ops@example.com")).toBe(ACCOUNT_URL);
    expect(ca.calls).toHaveLength(0);
  });

  it("refuses a newAccount response without a Location header", async () => {
    const ca = caWith(
      nonce("n1"),
      json({ status: "valid" }, { status: 201, headers: { "replay-nonce": "n2" } }),
    );
    await expect(makeClient(ca).ensureAccount("ops@example.com")).rejects.toThrow(acmeFailed);
  });

  it("restores a stored account URL without re-registering", async () => {
    const ca = caWith(
      nonce("n1"),
      json(
        { status: "pending", authorizations: [AUTHZ_URL], finalize: FINALIZE_URL },
        { status: 201, headers: { location: ORDER_URL, "replay-nonce": "n2" } },
      ),
    );
    const client = makeClient(ca);
    expect(client.accountUrl).toBeNull();
    client.accountUrl = ACCOUNT_URL;
    await client.newOrder(["a.example.com"]);
    expect(ca.calls.some((call) => call.url === NEW_ACCOUNT_URL)).toBe(false);
    expect(headerOf(at(ca.posts(), 0))["kid"]).toBe(ACCOUNT_URL);
  });

  it("refuses to restore an account URL that fails ACME URL validation", () => {
    const client = makeClient(new FakeCa());
    expect(() => {
      client.accountUrl = "http://acme.example.com/acct/1";
    }).toThrow(acmeFailed);
    expect(client.accountUrl).toBeNull();
  });

  it("refuses every account-bound operation before an account exists", async () => {
    const ca = new FakeCa();
    const client = makeClient(ca);
    await expect(client.newOrder(["a.example.com"])).rejects.toThrow(acmeFailed);
    await expect(client.getAuthorization(AUTHZ_URL)).rejects.toThrow(acmeFailed);
    await expect(client.respondChallenge(HTTP01_URL)).rejects.toThrow(acmeFailed);
    await expect(client.pollOrder(ORDER_URL)).rejects.toThrow(acmeFailed);
    await expect(client.finalize(FINALIZE_URL, new Uint8Array([1]))).rejects.toThrow(acmeFailed);
    await expect(client.downloadCertificate(CERTIFICATE_URL)).rejects.toThrow(acmeFailed);
    client.accountUrl = ACCOUNT_URL;
    client.accountUrl = null;
    await expect(client.pollOrder(ORDER_URL)).rejects.toThrow(acmeFailed);
    expect(ca.calls).toHaveLength(0);
  });

  it("refuses an order with no domains before touching the network", async () => {
    const ca = new FakeCa();
    await expect(registeredClient(ca).newOrder([])).rejects.toThrow(acmeFailed);
    expect(ca.calls).toHaveLength(0);
  });

  it("refuses an order carrying a blank or whitespace-only domain", async () => {
    const ca = new FakeCa();
    const client = registeredClient(ca);
    await expect(client.newOrder([""])).rejects.toThrow(acmeFailed);
    await expect(client.newOrder(["a.example.com", "   "])).rejects.toThrow(acmeFailed);
    await expect(client.newOrder(["\t\n"])).rejects.toThrow(acmeFailed);
    expect(ca.calls).toHaveLength(0);
  });

  it("surfaces the authorization status so a valid authorization need not be solved again", async () => {
    for (const status of ["pending", "valid"]) {
      const ca = caWith(nonce("n1"), json({ ...(authorizationBody() as object), status }));
      const authorization = await registeredClient(ca).getAuthorization(AUTHZ_URL);
      expect(authorization.status).toBe(status);
      expect(authorization.domain).toBe("a.example.com");
    }
  });

  it("refuses an authorization that carries no status member", async () => {
    const ca = caWith(
      nonce("n1"),
      json({
        identifier: { type: "dns", value: "a.example.com" },
        challenges: [{ type: "http-01", url: HTTP01_URL, token: "tok-http" }],
      }),
    );
    const message = await messageOf(() => registeredClient(ca).getAuthorization(AUTHZ_URL));
    expect(message).toContain("status");
  });
});

describe("AcmeClient key authorization and account key algorithm", () => {
  it("joins the token and the account key thumbprint with a dot", () => {
    const client = makeClient(new FakeCa());
    expect(client.keyAuthorization("tok-http")).toBe(`tok-http.${jwkThumbprint(accountJwk)}`);
    expect(client.keyAuthorization("tok-http")).toMatch(/^tok-http\.[A-Za-z0-9_-]{43}$/);
  });

  it("derives the protected-header alg from the account key, matching signJws", async () => {
    const keys: [string, string][] = [
      [generateCertKeyPair({ algorithm: "ec" }).privateKeyPem, "ES256"],
      [generateCertKeyPair({ algorithm: "ec", namedCurve: "P-384" }).privateKeyPem, "ES384"],
      [
        generateKeyPairSync("ec", {
          namedCurve: "P-521",
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
          publicKeyEncoding: { type: "spki", format: "pem" },
        }).privateKey,
        "ES512",
      ],
      [generateCertKeyPair({ algorithm: "rsa" }).privateKeyPem, "RS256"],
    ];
    for (const [privateKeyPem, alg] of keys) {
      const ca = caWith(
        nonce("n1"),
        json(authorizationBody(), { headers: { "replay-nonce": "n2" } }),
      );
      await registeredClient(ca, { accountKeyPem: privateKeyPem }).getAuthorization(AUTHZ_URL);
      expect(headerOf(at(ca.posts(), 0))["alg"]).toBe(alg);
    }
  });

  it("refuses an account key signJws could never sign with", () => {
    const { privateKey } = generateKeyPairSync("ec", {
      namedCurve: "secp256k1",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    expect(
      () => new AcmeClient({ directoryUrl: DIRECTORY_URL, accountKeyPem: privateKey }),
    ).toThrow(acmeFailed);
    expect(
      () => new AcmeClient({ directoryUrl: DIRECTORY_URL, accountKeyPem: "not a pem" }),
    ).toThrow(acmeFailed);
  });
});

describe("AcmeClient nonce handling", () => {
  it("fetches a fresh nonce with HEAD whenever the pool has run dry", async () => {
    const ca = caWith(
      nonce("m1"),
      json(authorizationBody()),
      nonce("m2"),
      json(authorizationBody()),
    );
    const client = registeredClient(ca);
    await client.getAuthorization(AUTHZ_URL);
    await client.getAuthorization(AUTHZ_URL);
    expect(ca.heads()).toHaveLength(2);
    expect(ca.heads().map((call) => call.url)).toEqual([NEW_NONCE_URL, NEW_NONCE_URL]);
    expect(ca.posts().map((call) => headerOf(call)["nonce"])).toEqual(["m1", "m2"]);
  });

  it("captures the nonce carried by an error response", async () => {
    const ca = caWith(
      nonce("m1"),
      problem(403, "urn:ietf:params:acme:error:unauthorized", "no", { "replay-nonce": "m2" }),
      json(authorizationBody()),
    );
    const client = registeredClient(ca);
    await expect(client.getAuthorization(AUTHZ_URL)).rejects.toThrow(acmeFailed);
    await client.getAuthorization(AUTHZ_URL);
    expect(ca.heads()).toHaveLength(1);
    expect(headerOf(at(ca.posts(), 1))["nonce"]).toBe("m2");
  });

  it("refuses when the newNonce endpoint supplies no Replay-Nonce header", async () => {
    const ca = caWith(new Response(null, { status: 200 }));
    await expect(registeredClient(ca).getAuthorization(AUTHZ_URL)).rejects.toThrow(acmeFailed);
    expect(ca.posts()).toHaveLength(0);
  });
});

describe("AcmeClient badNonce retry", () => {
  it("replays the same request with the fresh nonce, in exactly two attempts", async () => {
    const ca = caWith(
      nonce("stale"),
      badNonce("fresh"),
      json(authorizationBody(), { headers: { "replay-nonce": "after" } }),
    );
    const authorization = await registeredClient(ca).getAuthorization(AUTHZ_URL);
    const posts = ca.posts();
    expect(posts).toHaveLength(2);
    expect(headerOf(at(posts, 0))["nonce"]).toBe("stale");
    expect(headerOf(at(posts, 1))["nonce"]).toBe("fresh");
    expect(at(posts, 0).url).toBe(at(posts, 1).url);
    expect(jwsOf(at(posts, 0)).payload).toBe(jwsOf(at(posts, 1)).payload);
    expect(ca.heads()).toHaveLength(1);
    expect(authorization.domain).toBe("a.example.com");
  });

  it("gives up after three attempts and reports the badNonce type", async () => {
    const ca = caWith(nonce("s1"), badNonce("f1"), badNonce("f2"), badNonce("f3"));
    const message = await messageOf(() => registeredClient(ca).getAuthorization(AUTHZ_URL));
    expect(message).toContain("badNonce");
    expect(ca.posts()).toHaveLength(3);
    expect(ca.posts().map((call) => headerOf(call)["nonce"])).toEqual(["s1", "f1", "f2"]);
  });

  it("throws a typed error, not a bare one, when the replays run out", async () => {
    const ca = caWith(nonce("s1"), badNonce("f1"), badNonce("f2"), badNonce("f3"));
    await expect(registeredClient(ca).getAuthorization(AUTHZ_URL)).rejects.toThrow(acmeFailed);
  });
});

describe("AcmeClient problem documents", () => {
  const unauthorized = (): Response =>
    problem(
      403,
      "urn:ietf:params:acme:error:unauthorized",
      "Invalid response from http://a.example.com/.well-known/acme-challenge/tok [203.0.113.9]: 404",
    );

  it("maps a problem document to CERT_ACME_FAILED", async () => {
    const ca = caWith(nonce("n1"), unauthorized());
    await expect(registeredClient(ca).getAuthorization(AUTHZ_URL)).rejects.toThrow(acmeFailed);
  });

  it("carries the problem type and status only, never the body detail", async () => {
    const ca = caWith(nonce("n1"), unauthorized());
    const message = await messageOf(() => registeredClient(ca).getAuthorization(AUTHZ_URL));
    expect(message).toContain("unauthorized");
    expect(message).toContain("403");
    expect(message).not.toContain("Invalid response");
    expect(message).not.toContain("203.0.113.9");
    expect(message).not.toContain("well-known");
  });

  it("refuses a non-JSON error body without echoing it", async () => {
    const ca = caWith(
      nonce("n1"),
      new Response("<html><body>Gateway Timeout at edge-42</body></html>", {
        status: 504,
        headers: { "content-type": "text/html" },
      }),
    );
    const message = await messageOf(() => registeredClient(ca).getAuthorization(AUTHZ_URL));
    expect(message).toContain("504");
    expect(message).not.toContain("edge-42");
    expect(message).not.toContain("html");
  });

  it("strips control characters from a hostile problem type and truncates it at 128", async () => {
    const ca = caWith(nonce("n1"), problem(400, `urn:evil\n\r${"A".repeat(500)}`, "detail"));
    const message = await messageOf(() => registeredClient(ca).getAuthorization(AUTHZ_URL));
    const truncated = `urn:evil${"A".repeat(120)}`;
    expect(truncated).toHaveLength(128);
    expect(message).toContain(`${truncated}... (status 400)`);
    expect(message).not.toContain(`${truncated}A`);
    expect(message).not.toContain("\n");
    expect(message).not.toContain("\r");
  });

  it("keeps a problem type that is exactly at the limit intact", async () => {
    const exact = `urn:x:${"B".repeat(122)}`;
    const ca = caWith(nonce("n1"), problem(400, exact, "detail"));
    const message = await messageOf(() => registeredClient(ca).getAuthorization(AUTHZ_URL));
    expect(exact).toHaveLength(128);
    expect(message).toContain(`${exact} (status 400)`);
    expect(message).not.toContain("...");
  });

  it("refuses a directory response that is not a JSON object", async () => {
    const ca = new FakeCa().enqueue(new Response("not json", { status: 200 }));
    await expect(makeClient(ca).ensureAccount("ops@example.com")).rejects.toThrow(acmeFailed);
  });

  it("maps a directory HTTP error to CERT_ACME_FAILED naming the directory step", async () => {
    const ca = new FakeCa().enqueue(
      problem(500, "urn:ietf:params:acme:error:serverInternal", "stack trace here"),
    );
    const message = await messageOf(() => makeClient(ca).ensureAccount("ops@example.com"));
    expect(message).toContain("serverInternal");
    expect(message).toContain("directory");
    expect(message).not.toContain("stack trace");
  });

  it("wraps a transport failure as CERT_ACME_FAILED naming the origin only", async () => {
    const failing: typeof fetch = () => Promise.reject(new Error("getaddrinfo ENOTFOUND"));
    const client = new AcmeClient({
      directoryUrl: "https://acme.example.com/directory/secret-path",
      accountKeyPem,
      fetchImpl: failing,
    });
    const message = await messageOf(() => client.ensureAccount("ops@example.com"));
    expect(message).toContain("https://acme.example.com");
    expect(message).not.toContain("secret-path");
    expect(message).not.toContain("ENOTFOUND");
  });
});

describe("AcmeClient URL validation", () => {
  it("refuses a plain-HTTP directory URL at construction", () => {
    expect(
      () => new AcmeClient({ directoryUrl: "http://acme.example.com/directory", accountKeyPem }),
    ).toThrow(acmeFailed);
    expect(
      () => new AcmeClient({ directoryUrl: "https://acme.example.com/dir", accountKeyPem }),
    ).not.toThrow();
  });

  it("refuses a directory whose endpoints are not ACME-valid URLs", async () => {
    const ca = new FakeCa().enqueue(
      json({ ...DIRECTORY_BODY, newOrder: "http://internal.example.com/acme/new-order" }),
    );
    await expect(makeClient(ca).ensureAccount("ops@example.com")).rejects.toThrow(acmeFailed);
    expect(ca.calls).toHaveLength(1);
  });

  it("refuses a Location header pointing at a non-ACME URL", async () => {
    const ca = caWith(
      nonce("n1"),
      json(
        { status: "valid" },
        { status: 201, headers: { location: "http://internal.example.com/acct/1" } },
      ),
    );
    await expect(makeClient(ca).ensureAccount("ops@example.com")).rejects.toThrow(acmeFailed);
  });

  it("refuses authorization URLs read out of an order", async () => {
    const ca = caWith(
      nonce("n1"),
      json(
        {
          status: "pending",
          authorizations: ["http://internal.example.com/authz/1"],
          finalize: FINALIZE_URL,
        },
        { status: 201, headers: { location: ORDER_URL, "replay-nonce": "n2" } },
      ),
    );
    await expect(registeredClient(ca).newOrder(["a.example.com"])).rejects.toThrow(acmeFailed);
  });

  it("refuses an authorization whose identifier is not a dns name", async () => {
    for (const identifier of [{ type: "ip", value: "203.0.113.9" }, { value: "a.example.com" }]) {
      const ca = caWith(nonce("n1"), json({ identifier, challenges: [] }));
      await expect(registeredClient(ca).getAuthorization(AUTHZ_URL)).rejects.toThrow(acmeFailed);
    }
  });

  it("refuses challenge URLs read out of an authorization", async () => {
    const ca = caWith(
      nonce("n1"),
      json({
        identifier: { type: "dns", value: "a.example.com" },
        challenges: [{ type: "http-01", url: "http://internal.example.com/chall/1", token: "t" }],
      }),
    );
    await expect(registeredClient(ca).getAuthorization(AUTHZ_URL)).rejects.toThrow(acmeFailed);
  });

  it("validates every caller-supplied URL before a nonce is even spent", async () => {
    const bad = "http://internal.example.com/x";
    const operations: ((client: AcmeClient) => Promise<unknown>)[] = [
      (client) => client.getAuthorization(bad),
      (client) => client.respondChallenge(bad),
      (client) => client.pollOrder(bad),
      (client) => client.finalize(bad, new Uint8Array([1])),
      (client) => client.downloadCertificate(bad),
    ];
    for (const operation of operations) {
      const ca = caWith(nonce("n1"));
      await expect(operation(registeredClient(ca))).rejects.toThrow(acmeFailed);
      expect(ca.posts()).toHaveLength(0);
      expect(ca.heads()).toHaveLength(0);
      expect(ca.calls).toHaveLength(0);
    }
  });

  it("refuses caller-supplied URLs that are not HTTPS or parseable at all", async () => {
    for (const bad of ["file:///etc/passwd", "ftp://acme.example.com/x", "not a url", ""]) {
      const ca = caWith(nonce("n1"));
      await expect(registeredClient(ca).getAuthorization(bad)).rejects.toThrow(acmeFailed);
      expect(ca.calls).toHaveLength(0);
    }
  });

  it("refuses a certificate URL read out of an order", async () => {
    const ca = caWith(
      nonce("n1"),
      json({ status: "valid", certificate: "http://internal.example.com/cert/1" }),
    );
    await expect(registeredClient(ca).pollOrder(ORDER_URL)).rejects.toThrow(acmeFailed);
  });
});

describe("AcmeClient redirects and body size", () => {
  it("asks fetch for manual redirect handling on every request", async () => {
    const ca = caWith(nonce("n1"), json(authorizationBody()));
    await registeredClient(ca).getAuthorization(AUTHZ_URL);
    expect(ca.calls).toHaveLength(3);
    expect(ca.calls.map((call) => call.redirect)).toEqual(["manual", "manual", "manual"]);
  });

  it("refuses a CA redirect instead of following it, and makes no second request", async () => {
    const ca = caWith(
      nonce("n1"),
      new Response(null, {
        status: 302,
        headers: { location: "https://evil.example.com/steal", "replay-nonce": "n2" },
      }),
    );
    const message = await messageOf(() => registeredClient(ca).getAuthorization(AUTHZ_URL));
    expect(message).toContain("302");
    expect(message).toContain("https://acme.example.com");
    expect(message).not.toContain("evil.example.com");
    expect(message).not.toContain("steal");
    expect(ca.posts()).toHaveLength(1);
    expect(ca.calls).toHaveLength(3);
  });

  it("refuses every 3xx, including the ones that look benign", async () => {
    for (const status of [301, 302, 303, 307, 308]) {
      const ca = caWith(
        nonce("n1"),
        new Response(null, { status, headers: { location: "https://evil.example.com/x" } }),
      );
      await expect(registeredClient(ca).getAuthorization(AUTHZ_URL)).rejects.toThrow(acmeFailed);
      expect(ca.calls).toHaveLength(3);
    }
  });

  it("refuses a response whose Content-Length exceeds the 1 MiB cap", async () => {
    const ca = caWith(
      nonce("n1"),
      new Response("{}", { status: 200, headers: { "content-length": "1048577" } }),
    );
    const message = await messageOf(() => registeredClient(ca).getAuthorization(AUTHZ_URL));
    expect(message).toContain("too large");
    expect(message).toContain("https://acme.example.com");
  });

  it("accepts a response sitting exactly on the cap", async () => {
    const ca = caWith(
      nonce("n1"),
      new Response(JSON.stringify(authorizationBody()), {
        status: 200,
        headers: { "content-length": "1048576" },
      }),
    );
    const authorization = await registeredClient(ca).getAuthorization(AUTHZ_URL);
    expect(authorization.domain).toBe("a.example.com");
  });
});

describe("AcmeClient challenge polling", () => {
  it("polls the challenge until it turns valid", async () => {
    const ca = caWith(
      nonce("n1"),
      json({ status: "pending" }, { headers: { "replay-nonce": "n2" } }),
      json({ status: "processing" }, { headers: { "replay-nonce": "n3" } }),
      json({ status: "valid" }, { headers: { "replay-nonce": "n4" } }),
    );
    await registeredClient(ca).respondChallenge(HTTP01_URL);
    expect(ca.posts()).toHaveLength(3);
    expect(payloadOf(at(ca.posts(), 0))).toEqual({});
    expect(jwsOf(at(ca.posts(), 1)).payload).toBe("");
    expect(jwsOf(at(ca.posts(), 2)).payload).toBe("");
  });

  it("returns immediately when the response POST already reports valid", async () => {
    const ca = caWith(nonce("n1"), json({ status: "valid" }));
    await registeredClient(ca).respondChallenge(HTTP01_URL);
    expect(ca.posts()).toHaveLength(1);
  });

  it("reports an invalid challenge by its error type, never its detail", async () => {
    const ca = caWith(
      nonce("n1"),
      json({
        status: "invalid",
        error: {
          type: "urn:ietf:params:acme:error:incorrectResponse",
          status: 403,
          detail: "the key authorization file at /var/secret/tok was wrong",
        },
      }),
    );
    const message = await messageOf(() => registeredClient(ca).respondChallenge(HTTP01_URL));
    expect(message).toContain("incorrectResponse");
    expect(message).toContain("status 403");
    expect(message).not.toContain("/var/secret/tok");
  });

  it("omits the status suffix when the challenge error carries no status", async () => {
    const ca = caWith(
      nonce("n1"),
      json({ status: "invalid", error: { type: "urn:ietf:params:acme:error:dns" } }),
    );
    const message = await messageOf(() => registeredClient(ca).respondChallenge(HTTP01_URL));
    expect(message).toContain("urn:ietf:params:acme:error:dns");
    expect(message).not.toContain("status");
  });

  it("says so plainly when an invalid challenge carries no error object", async () => {
    const ca = caWith(nonce("n1"), json({ status: "invalid" }));
    const message = await messageOf(() => registeredClient(ca).respondChallenge(HTTP01_URL));
    expect(message).toContain("no reason given");
  });

  it("caps challenge polling at thirty polls after the initial response", async () => {
    const ca = caWith(
      nonce("n1"),
      ...Array.from({ length: 31 }, (_unused, index) =>
        json({ status: "pending" }, { headers: { "replay-nonce": `p${index}` } }),
      ),
    );
    await expect(registeredClient(ca).respondChallenge(HTTP01_URL)).rejects.toThrow(acmeFailed);
    expect(ca.posts()).toHaveLength(31);
  });
});

describe("AcmeClient order polling", () => {
  it("returns a ready order without waiting for a certificate", async () => {
    const ca = caWith(nonce("n1"), json({ status: "ready", finalize: FINALIZE_URL }));
    expect(await registeredClient(ca).pollOrder(ORDER_URL)).toEqual({ status: "ready" });
  });

  it("returns an invalid order rather than throwing", async () => {
    const ca = caWith(nonce("n1"), json({ status: "invalid" }));
    expect(await registeredClient(ca).pollOrder(ORDER_URL)).toEqual({ status: "invalid" });
  });

  it("throws after thirty polls of an order that stays processing", async () => {
    const ca = caWith(
      nonce("n1"),
      ...Array.from({ length: 30 }, (_unused, index) =>
        json({ status: "processing" }, { headers: { "replay-nonce": `p${index}` } }),
      ),
    );
    await expect(registeredClient(ca).pollOrder(ORDER_URL)).rejects.toThrow(acmeFailed);
    expect(ca.posts()).toHaveLength(30);
  });
});

describe("AcmeClient finalize and download", () => {
  it("refuses an empty CSR before touching the network", async () => {
    const ca = new FakeCa();
    await expect(registeredClient(ca).finalize(FINALIZE_URL, new Uint8Array())).rejects.toThrow(
      acmeFailed,
    );
    expect(ca.calls).toHaveLength(0);
  });

  it("base64url-encodes DER bytes that base64 would render with + and /", async () => {
    const csrDer = new Uint8Array([0xfb, 0xff, 0xbe, 0x00]);
    const ca = caWith(nonce("n1"), json({ status: "processing" }));
    await registeredClient(ca).finalize(FINALIZE_URL, csrDer);
    const csr = payloadOf(at(ca.posts(), 0))["csr"];
    expect(csr).toBe("-_--AA");
    expect(Buffer.from(String(csr), "base64url")).toEqual(Buffer.from(csrDer));
  });

  it("refuses a certificate response that carries no PEM certificate", async () => {
    const ca = caWith(nonce("n1"), new Response("nope", { status: 200 }));
    await expect(registeredClient(ca).downloadCertificate(CERTIFICATE_URL)).rejects.toThrow(
      acmeFailed,
    );
  });
});

describe("AcmeClient Retry-After", () => {
  const elapsedFor = async (
    retryAfter: string | null,
    maxRetryAfterMs: number,
  ): Promise<number> => {
    const headers: Record<string, string> = { "replay-nonce": "n2" };
    if (retryAfter !== null) headers["retry-after"] = retryAfter;
    const ca = caWith(
      nonce("n1"),
      json({ status: "processing" }, { headers }),
      json({ status: "valid", certificate: CERTIFICATE_URL }),
    );
    const started = Date.now();
    await registeredClient(ca, { maxRetryAfterMs }).pollOrder(ORDER_URL);
    return Date.now() - started;
  };

  it("honours delta-seconds and clamps the wait to maxRetryAfterMs", async () => {
    const elapsed = await elapsedFor("120", 40);
    expect(elapsed).toBeGreaterThanOrEqual(25);
    expect(elapsed).toBeLessThan(2_000);
  });

  it("skips the wait entirely when the server asks for zero seconds", async () => {
    expect(await elapsedFor("0", 5_000)).toBeLessThan(500);
  });

  it("parses an HTTP-date Retry-After that has already passed", async () => {
    const past = new Date(Date.now() - 60_000).toUTCString();
    expect(await elapsedFor(past, 5_000)).toBeLessThan(500);
  });

  it("falls back to a one-second poll interval when the header is absent or unusable", async () => {
    expect(await elapsedFor(null, 5_000)).toBeGreaterThanOrEqual(900);
    expect(await elapsedFor("soon", 0)).toBeLessThan(500);
  });
});
