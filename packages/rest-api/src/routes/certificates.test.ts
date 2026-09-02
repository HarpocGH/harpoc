import { generateKeyPairSync } from "node:crypto";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import { ENCRYPTED_KEY_IMPORT_REFUSAL, ErrorCode, VaultError } from "@harpoc/shared";
import type { CertificateStatus, VaultApiToken } from "@harpoc/shared";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { RateLimiter } from "../middleware/rate-limit.js";
import { createApp } from "../app.js";
import { createCertificateRoutes } from "./certificates.js";
import type { HarpocEnv } from "../types.js";

const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["list", "read", "create", "rotate", "revoke", "use"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
};

const EXPECTED_CALLER = {
  principal_type: "agent",
  principal_id: "test-agent",
  interface: "rest",
};

const PRIVATE_KEY_PEM =
  "-----BEGIN PRIVATE KEY-----\nMIIFakePrivateKey\n-----END PRIVATE KEY-----\n";
const CERTIFICATE_PEM =
  "-----BEGIN CERTIFICATE-----\nMIIFakeCertificate\n-----END CERTIFICATE-----\n";
const CSR_PEM =
  "-----BEGIN CERTIFICATE REQUEST-----\nMIIFakeCsr\n-----END CERTIFICATE REQUEST-----\n";

const CERT_STATUS: CertificateStatus = {
  secret_id: "secret-uuid-1",
  subject: "CN=example.com",
  issuer: "CN=example.com",
  not_before: 1_700_000_000_000,
  not_after: 1_800_000_000_000,
  auto_renew: false,
  renewal_status: "ok",
};

/**
 * A real passphrase-protected PKCS#8 PEM (not a fixture string): the route
 * must detect it via `isEncryptedPrivateKeyPem`, which matches on the PEM
 * header, so a genuine `node:crypto` export is what proves the detection
 * path rather than a hand-typed marker.
 */
function encryptedEcPrivateKeyPem(): string {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return privateKey.export({
    type: "pkcs8",
    format: "pem",
    cipher: "aes-256-cbc",
    passphrase: "pw",
  }) as string;
}

function createMockEngine() {
  return {
    verifyToken: vi.fn().mockReturnValue(MOCK_TOKEN),
    resolveSecretId: vi.fn().mockResolvedValue("secret-uuid-1"),
    getCertificateStatus: vi.fn().mockReturnValue(CERT_STATUS),
    // Only reached when `createApp` builds its own default `CertManager`: a
    // real one calls this first, before any PEM parsing that would otherwise
    // hide whether the engine was ever reached.
    importCertificate: vi.fn().mockRejectedValue(VaultError.invalidInput("stub engine")),
  };
}

function createMockCertManager() {
  return {
    importCertificate: vi.fn().mockResolvedValue({
      handle: "secret://my-cert",
      secretId: "secret-uuid-1",
    }),
    generateCsr: vi.fn().mockResolvedValue({
      handle: "secret://my-csr",
      secretId: "secret-uuid-2",
      csrPem: CSR_PEM,
    }),
    renewCertificate: vi.fn().mockResolvedValue(CERT_STATUS),
  };
}

let app: Hono<HarpocEnv>;
let engine: ReturnType<typeof createMockEngine>;
let certManager: ReturnType<typeof createMockCertManager>;
let limiter: RateLimiter;

beforeEach(() => {
  engine = createMockEngine();
  certManager = createMockCertManager();
  limiter = new RateLimiter();
  app = new Hono<HarpocEnv>();
  app.onError(errorHandler);
  app.use("*", async (c, next) => {
    c.set("engine", engine as never);
    c.set("limiter", limiter);
    c.set("certManager", certManager as never);
    await next();
  });
  app.use("/api/v1/certificates/*", authMiddleware);
  app.route("/api/v1/certificates", createCertificateRoutes());
});

const AUTH = { authorization: "Bearer valid-jwt" };
const JSON_HEADERS = { ...AUTH, "content-type": "application/json" };

function post(path: string, body: unknown): Response | Promise<Response> {
  return app.request(path, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });
}

const IMPORT_BODY = {
  name: "my-cert",
  private_key_pem: PRIVATE_KEY_PEM,
  certificate_pem: CERTIFICATE_PEM,
};

describe("POST /api/v1/certificates/import", () => {
  it("returns 201 with the handle and a snake_case secret_id", async () => {
    const res = await post("/api/v1/certificates/import", IMPORT_BODY);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.data).toEqual({ handle: "secret://my-cert", secret_id: "secret-uuid-1" });
  });

  it("maps the snake_case body onto the camelCase manager input, with a rest caller", async () => {
    await post("/api/v1/certificates/import", {
      ...IMPORT_BODY,
      chain_pem: "-----BEGIN CERTIFICATE-----\nMIIFakeChain\n-----END CERTIFICATE-----\n",
      project: "myproj",
      auto_renew: true,
      renew_before_days: 45,
    });

    expect(certManager.importCertificate).toHaveBeenCalledWith("my-cert", {
      privateKeyPem: PRIVATE_KEY_PEM,
      certificatePem: CERTIFICATE_PEM,
      chainPem: "-----BEGIN CERTIFICATE-----\nMIIFakeChain\n-----END CERTIFICATE-----\n",
      project: "myproj",
      autoRenew: true,
      renewBeforeDays: 45,
      caller: EXPECTED_CALLER,
    });
  });

  it("rejects a passphrase-protected private key naming 'harpoc cert import' (manager untouched)", async () => {
    const res = await post("/api/v1/certificates/import", {
      ...IMPORT_BODY,
      private_key_pem: encryptedEcPrivateKeyPem(),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe(ErrorCode.ENCRYPTED_KEY_UNSUPPORTED);
    expect(body.message).toBe(ENCRYPTED_KEY_IMPORT_REFUSAL);
    expect(certManager.importCertificate).not.toHaveBeenCalled();
  });

  it("rejects a body without certificate_pem (manager untouched)", async () => {
    const withoutCert: Record<string, unknown> = { ...IMPORT_BODY };
    delete withoutCert.certificate_pem;
    const res = await post("/api/v1/certificates/import", withoutCert);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
    expect(certManager.importCertificate).not.toHaveBeenCalled();
  });

  it("rejects a token without the create scope (403, manager untouched)", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read", "rotate"] });
    const res = await post("/api/v1/certificates/import", IMPORT_BODY);
    expect(res.status).toBe(403);
    expect(certManager.importCertificate).not.toHaveBeenCalled();
  });

  it("rejects a cross-project request from a project-scoped token", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, project: "other" });
    const res = await post("/api/v1/certificates/import", { ...IMPORT_BODY, project: "myproj" });
    expect(res.status).toBe(403);
    expect(certManager.importCertificate).not.toHaveBeenCalled();
  });
});

// The wire `subject` is the bare common name: the manager prefixes `CN=`
// itself when it stores the CSR's subject, so a `CN=`-carrying request models
// a certificate that would be stored as `CN=CN=example.com`.
const CSR_BODY = {
  name: "my-csr",
  subject: "example.com",
};

describe("POST /api/v1/certificates/csr", () => {
  it("returns 201 with the handle and csr_pem", async () => {
    const res = await post("/api/v1/certificates/csr", CSR_BODY);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.data).toEqual({ handle: "secret://my-csr", csr_pem: CSR_PEM });
  });

  it("maps subject/bits/curve onto commonName/modulusLength/namedCurve", async () => {
    await post("/api/v1/certificates/csr", {
      name: "my-csr",
      subject: "example.com",
      sans: ["www.example.com"],
      algorithm: "rsa",
      bits: 4096,
      project: "myproj",
    });

    expect(certManager.generateCsr).toHaveBeenCalledWith("my-csr", {
      commonName: "example.com",
      sans: ["www.example.com"],
      algorithm: "rsa",
      modulusLength: 4096,
      namedCurve: undefined,
      project: "myproj",
      caller: EXPECTED_CALLER,
    });
  });

  it("maps a curve for the ec algorithm", async () => {
    await post("/api/v1/certificates/csr", {
      name: "my-csr",
      subject: "example.com",
      algorithm: "ec",
      curve: "P-384",
    });

    expect(certManager.generateCsr).toHaveBeenCalledWith(
      "my-csr",
      expect.objectContaining({ namedCurve: "P-384", modulusLength: undefined }),
    );
  });

  it("defaults algorithm to ec when omitted, so an explicit curve is not silently dropped", async () => {
    await post("/api/v1/certificates/csr", {
      name: "my-csr",
      subject: "example.com",
      curve: "P-384",
    });

    expect(certManager.generateCsr).toHaveBeenCalledWith(
      "my-csr",
      expect.objectContaining({ algorithm: "ec", namedCurve: "P-384" }),
    );
  });

  it("rejects bits paired without algorithm rsa (manager untouched)", async () => {
    const res = await post("/api/v1/certificates/csr", {
      name: "my-csr",
      subject: "example.com",
      bits: 2048,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
    expect(certManager.generateCsr).not.toHaveBeenCalled();
  });

  it("rejects a token without the create scope (403, manager untouched)", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read", "rotate"] });
    const res = await post("/api/v1/certificates/csr", CSR_BODY);
    expect(res.status).toBe(403);
    expect(certManager.generateCsr).not.toHaveBeenCalled();
  });
});

describe("POST /api/v1/certificates/:handle/renew", () => {
  it("returns 200 with the certificate status", async () => {
    const res = await post("/api/v1/certificates/my-cert/renew", {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual(CERT_STATUS);
    expect(certManager.renewCertificate).toHaveBeenCalledWith("secret-uuid-1", {
      httpPort: undefined,
      caller: EXPECTED_CALLER,
      handle: "secret://my-cert",
    });
  });

  it("passes http_port through to the manager", async () => {
    await post("/api/v1/certificates/my-cert/renew", { http_port: 8080 });
    expect(certManager.renewCertificate).toHaveBeenCalledWith(
      "secret-uuid-1",
      expect.objectContaining({ httpPort: 8080 }),
    );
  });

  it("charges the per-secret rate limiter on the handle, before resolution", async () => {
    const checkSecret = vi.spyOn(limiter, "checkSecret");
    await post("/api/v1/certificates/my-cert/renew", {});
    expect(checkSecret).toHaveBeenCalledWith("secret://my-cert");
  });

  it("requires the rotate scope (403, manager untouched)", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read", "create"] });
    const res = await post("/api/v1/certificates/my-cert/renew", {});
    expect(res.status).toBe(403);
    expect(certManager.renewCertificate).not.toHaveBeenCalled();
  });

  // `post()` always stringifies, so the bodyless request is built by hand.
  it("a bodyless POST is a descriptive 400, not a generic 500", async () => {
    const res = await app.request("/api/v1/certificates/my-cert/renew", {
      method: "POST",
      headers: JSON_HEADERS,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
    expect(body.message).toBe("Request body must be valid JSON");
    expect(certManager.renewCertificate).not.toHaveBeenCalled();
  });
});

describe("GET /api/v1/certificates/:handle/status", () => {
  it("returns the certificate status for the resolved secret id", async () => {
    const res = await app.request("/api/v1/certificates/my-cert/status", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual(CERT_STATUS);
    expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://my-cert");
    expect(engine.getCertificateStatus).toHaveBeenCalledWith(
      "secret-uuid-1",
      EXPECTED_CALLER,
      "secret://my-cert",
    );
  });

  it("charges the per-secret rate limiter on the handle, before resolution", async () => {
    const checkSecret = vi.spyOn(limiter, "checkSecret");
    await app.request("/api/v1/certificates/my-cert/status", { headers: AUTH });
    expect(checkSecret).toHaveBeenCalledWith("secret://my-cert");
  });

  it("requires the read scope (403, engine untouched)", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["create"] });
    const res = await app.request("/api/v1/certificates/my-cert/status", { headers: AUTH });
    expect(res.status).toBe(403);
    expect(engine.getCertificateStatus).not.toHaveBeenCalled();
  });

  it("resolves a project-qualified handle", async () => {
    await app.request("/api/v1/certificates/myproj%2Fmy-cert/status", { headers: AUTH });
    expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://myproj/my-cert");
  });
});

describe("createApp certificate wiring", () => {
  it("mounts the routes and serves the injected manager from context", async () => {
    const appEngine = createMockEngine();
    const injected = createMockCertManager();
    const wired = createApp(appEngine as never, {
      oauthManager: {} as never,
      certManager: injected as never,
    });

    const res = await wired.request("/api/v1/certificates/import", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(IMPORT_BODY),
    });
    expect(res.status).toBe(201);
    expect(injected.importCertificate).toHaveBeenCalledTimes(1);
  });

  it("requires auth on the mounted certificate routes", async () => {
    const appEngine = createMockEngine();
    const injected = createMockCertManager();
    const wired = createApp(appEngine as never, {
      oauthManager: {} as never,
      certManager: injected as never,
    });

    const status = await wired.request("/api/v1/certificates/my-cert/status");
    expect(status.status).toBe(401);

    // The `/*` middleware pattern must cover the single-segment import/csr
    // paths too — an unguarded route would read an unset `token` from context.
    const imported = await wired.request("/api/v1/certificates/import", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(IMPORT_BODY),
    });
    expect(imported.status).toBe(401);
    expect(injected.importCertificate).not.toHaveBeenCalled();
  });

  it("constructs its own certificate manager when none is injected", async () => {
    const appEngine = createMockEngine();
    const wired = createApp(appEngine as never);

    const res = await wired.request("/api/v1/certificates/import", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(IMPORT_BODY),
    });

    // The default manager's first engine call. An unset context var would throw
    // a TypeError and answer 500 INTERNAL_ERROR instead of the stub's own code.
    expect(appEngine.importCertificate).toHaveBeenCalled();
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.INVALID_INPUT);
  });
});
