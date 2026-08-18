import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { CallerContext, CertificateStatus } from "@harpoc/shared";
import { CertManager } from "./cert-manager.js";
import type { CertificateEngine } from "./cert-manager.js";
import { generateCertKeyPair } from "./key-pair.js";
import type { KeyPairOptions } from "./key-pair.js";
import { RenewalScheduler } from "./renewal-scheduler.js";

interface ScriptedChallenge {
  type: string;
  url: string;
  token: string;
}

interface ScriptedAuthorization {
  domain: string;
  status: string;
  challenges: ScriptedChallenge[];
}

interface SolverStart {
  token: string;
  keyAuthorization: string;
  port: number;
}

interface AcmeStub {
  directoryUrl: string;
  accountKeyPem: string;
  accountUrl: string | null;
  ensureAccount: Mock;
  newOrder: Mock;
  getAuthorization: Mock;
  respondChallenge: Mock;
  finalize: Mock;
  pollOrder: Mock;
  downloadCertificate: Mock;
  keyAuthorization: Mock;
}

const scenario = vi.hoisted(() => ({
  instances: [] as AcmeStub[],
  accountUrl: "",
  order: { orderUrl: "", authorizationUrls: [] as string[], finalizeUrl: "" },
  authorizations: {} as Record<string, ScriptedAuthorization>,
  respondChallengeError: null as unknown,
  orderStatus: { status: "valid" } as { status: string; certificateUrl?: string },
  chainPem: "",
  solverStarts: [] as SolverStart[],
  solverStops: 0,
}));

vi.mock("./acme/acme-client.js", () => {
  class AcmeClient {
    accountUrl: string | null = null;
    directoryUrl: string;
    accountKeyPem: string;
    ensureAccount: Mock;
    newOrder: Mock;
    getAuthorization: Mock;
    respondChallenge: Mock;
    finalize: Mock;
    pollOrder: Mock;
    downloadCertificate: Mock;
    keyAuthorization: Mock;

    constructor(options: { directoryUrl: string; accountKeyPem: string }) {
      this.directoryUrl = options.directoryUrl;
      this.accountKeyPem = options.accountKeyPem;
      this.ensureAccount = vi.fn(async () => {
        this.accountUrl = scenario.accountUrl;
        return scenario.accountUrl;
      });
      this.newOrder = vi.fn(async () => scenario.order);
      this.getAuthorization = vi.fn(async (url: string) => {
        const authorization = scenario.authorizations[url];
        if (authorization === undefined) throw new Error(`unscripted authorization ${url}`);
        return authorization;
      });
      this.respondChallenge = vi.fn(async () => {
        if (scenario.respondChallengeError !== null) throw scenario.respondChallengeError;
      });
      this.finalize = vi.fn(async () => undefined);
      this.pollOrder = vi.fn(async () => scenario.orderStatus);
      this.downloadCertificate = vi.fn(async () => scenario.chainPem);
      this.keyAuthorization = vi.fn((token: string) => `${token}.thumbprint`);
      scenario.instances.push(this);
    }
  }
  return { AcmeClient };
});

vi.mock("./acme/challenge-solver.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./acme/challenge-solver.js")>();
  class Http01Solver {
    async start(token: string, keyAuthorization: string, port: number): Promise<number> {
      scenario.solverStarts.push({ token, keyAuthorization, port });
      return port;
    }
    async stop(): Promise<void> {
      scenario.solverStops += 1;
    }
  }
  return { ...actual, Http01Solver };
});

vi.mock("./key-pair.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./key-pair.js")>();
  return { generateCertKeyPair: vi.fn(actual.generateCertKeyPair) };
});

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__", "certs");
const fx = (name: string): string => readFileSync(join(FIXTURES, name), "utf8");

const LEAF = fx("rsa-cert.pem").trim();
const INTERMEDIATE = fx("expired-cert.pem").trim();
const RENEWED_LEAF = fx("rsa-cert-renewed.pem").trim();
const BUNDLE = `${LEAF}\n${INTERMEDIATE}\n`;
const RENEWED_BUNDLE = `${RENEWED_LEAF}\n${INTERMEDIATE}\n`;
const KEY = fx("rsa-key.pem");
const CSR_PEM = fx("csr-fixture.pem");

const PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";
const STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";
const ACCOUNT_URL = "https://acme-v02.api.letsencrypt.org/acme/acct/1";
const STAGING_ACCOUNT_URL = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/1";
const ORDER_URL = "https://acme-v02.api.letsencrypt.org/acme/order/1";
const FINALIZE_URL = "https://acme-v02.api.letsencrypt.org/acme/finalize/1";
const CERTIFICATE_URL = "https://acme-v02.api.letsencrypt.org/acme/cert/1";
const AUTHZ_URL = "https://acme-v02.api.letsencrypt.org/acme/authz/1";

const SECRET_ID = "cert-secret-id";
const HANDLE = "secret://web-cert";
const STATUS: CertificateStatus = {
  secret_id: SECRET_ID,
  subject: "CN=fixture.example.com",
  issuer: "CN=fixture.example.com",
  not_before: 1_700_000_000_000,
  not_after: 1_800_000_000_000,
  auto_renew: true,
  renewal_status: "ok",
};

const CALLER: CallerContext = {
  principal_type: "agent",
  principal_id: "agent-1",
  interface: "cli",
};

const acmeFailed = expect.objectContaining({ code: ErrorCode.CERT_ACME_FAILED });
const csrFailed = expect.objectContaining({ code: ErrorCode.CERT_CSR_FAILED });
const certInvalid = expect.objectContaining({ code: ErrorCode.CERT_INVALID });

function httpAuthorization(domain: string, status = "pending"): ScriptedAuthorization {
  return {
    domain,
    status,
    challenges: [
      {
        type: "dns-01",
        url: `https://acme-v02.api.letsencrypt.org/c/${domain}/dns`,
        token: `t-${domain}`,
      },
      {
        type: "http-01",
        url: `https://acme-v02.api.letsencrypt.org/c/${domain}/http`,
        token: `t-${domain}`,
      },
    ],
  };
}

function dnsOnlyAuthorization(domain: string, status = "pending"): ScriptedAuthorization {
  return {
    domain,
    status,
    challenges: [
      {
        type: "dns-01",
        url: `https://acme-v02.api.letsencrypt.org/c/${domain}/dns`,
        token: `t-${domain}`,
      },
    ],
  };
}

interface ImportOptions {
  certificatePem?: string;
  chainPem?: string;
  csrPem?: string;
  subject?: string;
  autoRenew?: boolean;
  renewBeforeDays?: number;
  acmeIssued?: boolean;
}

interface CertificateMaterial {
  certificatePem: string | null;
  chainPem: string | null;
  csrPem: string | null;
}

function makeEngine() {
  return {
    importCertificate: vi.fn<
      (
        name: string,
        privateKeyPem: string,
        opts?: ImportOptions,
        project?: string,
        caller?: CallerContext,
      ) => Promise<{ handle: string; secretId: string }>
    >(async () => ({ handle: HANDLE, secretId: SECRET_ID })),
    updateCertificate: vi.fn<
      (
        secretId: string,
        certificatePem: string,
        chainPem?: string,
        opts?: { renewed?: boolean },
        caller?: CallerContext,
      ) => Promise<void>
    >(async () => undefined),
    getCertificatePem: vi.fn<(secretId: string, caller?: CallerContext) => CertificateMaterial>(
      () => ({ certificatePem: null, chainPem: null, csrPem: null }),
    ),
    getCertificateStatus: vi.fn<(secretId: string, caller?: CallerContext) => CertificateStatus>(
      () => STATUS,
    ),
    storeAcmeAccount: vi.fn<(secretId: string, accountJson: string) => void>(),
    getAcmeAccount: vi.fn<(secretId: string, caller?: CallerContext) => string | null>(() => null),
  };
}

type EngineMock = ReturnType<typeof makeEngine>;

function managerFor(engine: EngineMock, options?: ConstructorParameters<typeof CertManager>[1]) {
  return new CertManager(engine as unknown as CertificateEngine, options);
}

function issued(): AcmeStub {
  const [instance] = scenario.instances;
  if (instance === undefined) throw new Error("no AcmeClient was constructed");
  return instance;
}

function storedAccount(engine: EngineMock): { privateKeyPem: string; accountUrl: string } {
  const call = engine.storeAcmeAccount.mock.calls[0];
  if (call === undefined) throw new Error("storeAcmeAccount was not called");
  return JSON.parse(call[1]) as { privateKeyPem: string; accountUrl: string };
}

/**
 * The generateCertKeyPair arguments in call order. `issueWithAcme` generates
 * the certificate key first and the ACME account key second, so index 0 is the
 * key the operator's flags govern and index 1 the one they must never reach.
 */
function keyPairCalls(): KeyPairOptions[] {
  return vi.mocked(generateCertKeyPair).mock.calls.map((call) => call[0]);
}

function importOptions(engine: EngineMock): ImportOptions {
  const call = engine.importCertificate.mock.calls[0];
  if (call === undefined) throw new Error("importCertificate was not called");
  return call[2] ?? {};
}

describe("CertManager", () => {
  let engine: EngineMock;
  let manager: CertManager;

  beforeEach(() => {
    vi.clearAllMocks();
    scenario.instances.length = 0;
    scenario.accountUrl = ACCOUNT_URL;
    scenario.order = {
      orderUrl: ORDER_URL,
      authorizationUrls: [AUTHZ_URL],
      finalizeUrl: FINALIZE_URL,
    };
    scenario.authorizations = { [AUTHZ_URL]: httpAuthorization("fixture.example.com") };
    scenario.respondChallengeError = null;
    scenario.orderStatus = { status: "valid", certificateUrl: CERTIFICATE_URL };
    scenario.chainPem = BUNDLE;
    scenario.solverStarts.length = 0;
    scenario.solverStops = 0;
    engine = makeEngine();
    manager = managerFor(engine);
  });

  describe("importCertificate", () => {
    it("splits a bundle and delegates leaf plus chain to the engine", async () => {
      const result = await manager.importCertificate("web", {
        privateKeyPem: KEY,
        certificatePem: BUNDLE,
      });

      expect(result).toEqual({ handle: HANDLE, secretId: SECRET_ID });
      expect(engine.importCertificate).toHaveBeenCalledTimes(1);
      expect(engine.importCertificate).toHaveBeenCalledWith(
        "web",
        KEY,
        expect.objectContaining({ certificatePem: LEAF, chainPem: INTERMEDIATE }),
        undefined,
        undefined,
      );
    });

    it("passes no chain when the bundle holds a single certificate", async () => {
      await manager.importCertificate("web", { privateKeyPem: KEY, certificatePem: LEAF });

      expect(importOptions(engine)).toMatchObject({ certificatePem: LEAF, chainPem: undefined });
    });

    it("prefers an explicitly supplied chain over the bundle's own intermediates", async () => {
      await manager.importCertificate("web", {
        privateKeyPem: KEY,
        certificatePem: BUNDLE,
        chainPem: RENEWED_LEAF,
      });

      expect(importOptions(engine)).toMatchObject({
        certificatePem: LEAF,
        chainPem: RENEWED_LEAF,
      });
    });

    it("treats an empty chain string as absent and falls back to the bundle's own chain", async () => {
      await manager.importCertificate("web", {
        privateKeyPem: KEY,
        certificatePem: BUNDLE,
        chainPem: "",
      });

      expect(importOptions(engine)).toMatchObject({
        certificatePem: LEAF,
        chainPem: INTERMEDIATE,
      });
    });

    it("forwards project, autoRenew and renewBeforeDays", async () => {
      await manager.importCertificate("web", {
        privateKeyPem: KEY,
        certificatePem: LEAF,
        project: "edge",
        autoRenew: true,
        renewBeforeDays: 14,
      });

      expect(engine.importCertificate).toHaveBeenCalledWith(
        "web",
        KEY,
        expect.objectContaining({ autoRenew: true, renewBeforeDays: 14 }),
        "edge",
        undefined,
      );
    });

    it("refuses a PEM with no certificate block before touching the engine", async () => {
      await expect(
        manager.importCertificate("web", { privateKeyPem: KEY, certificatePem: "not a pem" }),
      ).rejects.toThrow(certInvalid);
      expect(engine.importCertificate).not.toHaveBeenCalled();
    });

    it("threads the caller through to the engine for audit attribution", async () => {
      await manager.importCertificate("web", {
        privateKeyPem: KEY,
        certificatePem: LEAF,
        caller: CALLER,
      });

      expect(engine.importCertificate).toHaveBeenCalledWith(
        "web",
        KEY,
        expect.objectContaining({ certificatePem: LEAF }),
        undefined,
        CALLER,
      );
    });

    it("passes no caller on the trusted local path", async () => {
      await manager.importCertificate("web", { privateKeyPem: KEY, certificatePem: LEAF });

      expect(engine.importCertificate.mock.calls[0]?.[4]).toBeUndefined();
    });
  });

  describe("generateCsr", () => {
    it("stores the CSR with a CN subject and returns it", async () => {
      const result = await manager.generateCsr("api", { commonName: "api.example.com" });

      expect(result.csrPem).toContain("-----BEGIN CERTIFICATE REQUEST-----");
      expect(result).toMatchObject({ handle: HANDLE, secretId: SECRET_ID });
      expect(engine.importCertificate).toHaveBeenCalledWith(
        "api",
        expect.stringContaining("-----BEGIN PRIVATE KEY-----"),
        { csrPem: result.csrPem, subject: "CN=api.example.com" },
        undefined,
        undefined,
      );
    });

    it("forwards the project and the requested algorithm", async () => {
      await manager.generateCsr("api", {
        commonName: "api.example.com",
        algorithm: "ec",
        project: "edge",
      });

      expect(vi.mocked(generateCertKeyPair)).toHaveBeenCalledWith({ algorithm: "ec" });
      expect(engine.importCertificate).toHaveBeenCalledWith(
        "api",
        expect.any(String),
        expect.objectContaining({ subject: "CN=api.example.com" }),
        "edge",
        undefined,
      );
    });

    it("defaults to an RSA key pair", async () => {
      await manager.generateCsr("api", { commonName: "api.example.com" });

      expect(vi.mocked(generateCertKeyPair)).toHaveBeenCalledWith({ algorithm: "rsa" });
    });

    it("threads modulusLength through to the RSA key pair", async () => {
      await manager.generateCsr("api", {
        commonName: "api.example.com",
        algorithm: "rsa",
        modulusLength: 4096,
      });

      expect(vi.mocked(generateCertKeyPair)).toHaveBeenCalledWith({
        algorithm: "rsa",
        modulusLength: 4096,
      });
    });

    it("threads namedCurve through to the EC key pair", async () => {
      await manager.generateCsr("api", {
        commonName: "api.example.com",
        algorithm: "ec",
        namedCurve: "P-384",
      });

      expect(vi.mocked(generateCertKeyPair)).toHaveBeenCalledWith({
        algorithm: "ec",
        namedCurve: "P-384",
      });
    });

    it("threads the caller through to the engine for audit attribution", async () => {
      await manager.generateCsr("api", { commonName: "api.example.com", caller: CALLER });

      expect(engine.importCertificate.mock.calls[0]?.[4]).toEqual(CALLER);
    });

    it("carries the SANs into the CSR", async () => {
      const result = await manager.generateCsr("api", {
        commonName: "api.example.com",
        sans: ["api.example.com", "www.example.com"],
        algorithm: "ec",
      });

      const der = Buffer.from(
        result.csrPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
        "base64",
      ).toString("latin1");
      expect(der).toContain("www.example.com");
    });

    it("refuses an empty common name", async () => {
      await expect(manager.generateCsr("api", { commonName: "   " })).rejects.toThrow(csrFailed);
      expect(engine.importCertificate).not.toHaveBeenCalled();
    });

    it("refuses a common name longer than 64 characters", async () => {
      await expect(
        manager.generateCsr("api", { commonName: `${"a".repeat(61)}.example.com` }),
      ).rejects.toThrow(csrFailed);
      expect(engine.importCertificate).not.toHaveBeenCalled();
    });

    it("refuses a blank SAN entry", async () => {
      await expect(
        manager.generateCsr("api", {
          commonName: "api.example.com",
          sans: ["ok.example.com", " "],
        }),
      ).rejects.toThrow(csrFailed);
      expect(engine.importCertificate).not.toHaveBeenCalled();
    });
  });

  describe("issueWithAcme", () => {
    const issueOptions = { domains: ["fixture.example.com"], email: "ops@example.com" };

    it("issues over http-01 and stores the certificate as ACME-issued", async () => {
      const result = await manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec" });

      expect(result).toEqual({ handle: HANDLE, secretId: SECRET_ID, status: STATUS });
      expect(engine.importCertificate).toHaveBeenCalledWith(
        "web",
        expect.stringContaining("-----BEGIN PRIVATE KEY-----"),
        expect.objectContaining({
          certificatePem: LEAF,
          chainPem: INTERMEDIATE,
          csrPem: expect.stringContaining("-----BEGIN CERTIFICATE REQUEST-----"),
          acmeIssued: true,
        }),
        undefined,
        undefined,
      );
    });

    it("threads the caller through to the engine for audit attribution", async () => {
      await manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec", caller: CALLER });

      expect(engine.importCertificate.mock.calls[0]?.[4]).toEqual(CALLER);
      // The closing status read stays on the trusted path: a caller there
      // would be a policy gate, not attribution (see issueWithAcme).
      expect(engine.getCertificateStatus).toHaveBeenCalledWith(SECRET_ID);
    });

    it("orders exactly the requested domains and finalizes with the generated CSR DER", async () => {
      await manager.issueWithAcme("web", {
        domains: ["fixture.example.com", "alt.example.com"],
        email: "ops@example.com",
        algorithm: "ec",
      });

      const client = issued();
      expect(client.newOrder).toHaveBeenCalledWith(["fixture.example.com", "alt.example.com"]);
      const csrPem = importOptions(engine).csrPem as string;
      const expected = new Uint8Array(
        Buffer.from(csrPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64"),
      );
      expect(client.finalize).toHaveBeenCalledWith(FINALIZE_URL, expected);
    });

    it("stores the ACME account key and URL only after the certificate landed", async () => {
      await manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec" });

      const account = storedAccount(engine);
      expect(account.accountUrl).toBe(ACCOUNT_URL);
      expect(account.privateKeyPem).toBe(issued().accountKeyPem);
      expect(engine.storeAcmeAccount).toHaveBeenCalledWith(SECRET_ID, expect.any(String));
      const importOrder = engine.importCertificate.mock.invocationCallOrder[0] as number;
      const storeOrder = engine.storeAcmeAccount.mock.invocationCallOrder[0] as number;
      expect(storeOrder).toBeGreaterThan(importOrder);
    });

    it("uses a freshly generated EC account key", async () => {
      await manager.issueWithAcme("web", { ...issueOptions, algorithm: "rsa" });

      expect(vi.mocked(generateCertKeyPair)).toHaveBeenCalledWith({ algorithm: "ec" });
      expect(storedAccount(engine).privateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");
    });

    it("threads modulusLength through to the certificate key pair", async () => {
      await manager.issueWithAcme("web", {
        ...issueOptions,
        algorithm: "rsa",
        modulusLength: 4096,
      });

      const [certificateKey, accountKey] = keyPairCalls();
      expect(certificateKey).toEqual({ algorithm: "rsa", modulusLength: 4096 });
      // The account key is the manager's own material, not the subscriber's:
      // an operator's key-strength request must not follow it (P-256 stays).
      expect(accountKey).toEqual({ algorithm: "ec" });
    });

    it("threads namedCurve through to the certificate key pair", async () => {
      await manager.issueWithAcme("web", {
        ...issueOptions,
        algorithm: "ec",
        namedCurve: "P-384",
      });

      const [certificateKey, accountKey] = keyPairCalls();
      expect(certificateKey).toEqual({ algorithm: "ec", namedCurve: "P-384" });
      expect(accountKey).toEqual({ algorithm: "ec" });
    });

    it("defaults the certificate key to RSA with no size or curve override", async () => {
      await manager.issueWithAcme("web", issueOptions);

      expect(keyPairCalls()[0]).toEqual({ algorithm: "rsa" });
    });

    it("registers the account exactly once", async () => {
      await manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec" });

      expect(issued().ensureAccount).toHaveBeenCalledTimes(1);
      expect(issued().ensureAccount).toHaveBeenCalledWith("ops@example.com");
    });

    it("targets the production directory by default", async () => {
      await manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec" });

      expect(issued().directoryUrl).toBe(PRODUCTION);
    });

    it("targets the staging directory when asked", async () => {
      await manager.issueWithAcme("web", { ...issueOptions, staging: true, algorithm: "ec" });

      expect(issued().directoryUrl).toBe(STAGING);
    });

    it("lets a configured directory URL override the staging selection", async () => {
      const custom = "https://acme.internal.example.com/directory";
      manager = managerFor(engine, { directoryUrl: custom });

      await manager.issueWithAcme("web", { ...issueOptions, staging: true, algorithm: "ec" });

      expect(issued().directoryUrl).toBe(custom);
    });

    it("serves the challenge on the requested port and stops the solver", async () => {
      await manager.issueWithAcme("web", { ...issueOptions, httpPort: 8080, algorithm: "ec" });

      expect(scenario.solverStarts).toEqual([
        {
          token: "t-fixture.example.com",
          keyAuthorization: "t-fixture.example.com.thumbprint",
          port: 8080,
        },
      ]);
      expect(scenario.solverStops).toBe(1);
    });

    it("defaults the challenge port to 80", async () => {
      await manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec" });

      expect(scenario.solverStarts[0]?.port).toBe(80);
    });

    it("stops the solver when the challenge fails", async () => {
      scenario.respondChallengeError = VaultError.certAcmeFailed("challenge failed validation");

      await expect(
        manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec" }),
      ).rejects.toThrow(acmeFailed);
      expect(scenario.solverStarts).toHaveLength(1);
      expect(scenario.solverStops).toBe(1);
      expect(engine.importCertificate).not.toHaveBeenCalled();
      expect(engine.storeAcmeAccount).not.toHaveBeenCalled();
    });

    it("solves every authorization of a multi-domain order", async () => {
      const second = "https://acme-v02.api.letsencrypt.org/acme/authz/2";
      scenario.order = {
        orderUrl: ORDER_URL,
        authorizationUrls: [AUTHZ_URL, second],
        finalizeUrl: FINALIZE_URL,
      };
      scenario.authorizations = {
        [AUTHZ_URL]: httpAuthorization("fixture.example.com"),
        [second]: httpAuthorization("alt.example.com"),
      };

      await manager.issueWithAcme("web", {
        domains: ["fixture.example.com", "alt.example.com"],
        email: "ops@example.com",
        algorithm: "ec",
      });

      expect(scenario.solverStarts.map((s) => s.token)).toEqual([
        "t-fixture.example.com",
        "t-alt.example.com",
      ]);
      expect(scenario.solverStops).toBe(2);
    });

    it("uses the dns-01 callback with the RFC 8555 TXT value and starts no HTTP solver", async () => {
      const dns01 = vi.fn(async () => undefined);

      await manager.issueWithAcme("web", { ...issueOptions, dns01, algorithm: "ec" });

      const expected = createHash("sha256")
        .update("t-fixture.example.com.thumbprint")
        .digest("base64url");
      expect(dns01).toHaveBeenCalledWith("fixture.example.com", expected);
      expect(scenario.solverStarts).toHaveLength(0);
      expect(issued().respondChallenge).toHaveBeenCalledWith(
        "https://acme-v02.api.letsencrypt.org/c/fixture.example.com/dns",
      );
    });

    it("refuses when the authorization offers no matching challenge", async () => {
      scenario.authorizations = { [AUTHZ_URL]: dnsOnlyAuthorization("fixture.example.com") };

      await expect(
        manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec" }),
      ).rejects.toThrow(acmeFailed);
      expect(engine.importCertificate).not.toHaveBeenCalled();
    });

    it("treats an invalid order as a failure and stores nothing", async () => {
      scenario.orderStatus = { status: "invalid" };

      await expect(
        manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec" }),
      ).rejects.toThrow(
        expect.objectContaining({
          code: ErrorCode.CERT_ACME_FAILED,
          message: expect.stringContaining("invalid"),
        }),
      );
      expect(issued().downloadCertificate).not.toHaveBeenCalled();
      expect(engine.importCertificate).not.toHaveBeenCalled();
    });

    it("refuses a valid order that carries no certificate URL", async () => {
      scenario.orderStatus = { status: "valid" };

      await expect(
        manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec" }),
      ).rejects.toThrow(acmeFailed);
      expect(engine.importCertificate).not.toHaveBeenCalled();
    });

    it("skips solving an authorization the CA already counts as valid", async () => {
      scenario.authorizations = {
        [AUTHZ_URL]: httpAuthorization("fixture.example.com", "valid"),
      };

      await manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec" });

      expect(scenario.solverStarts).toHaveLength(0);
      expect(scenario.solverStops).toBe(0);
      expect(issued().respondChallenge).not.toHaveBeenCalled();
      expect(issued().finalize).toHaveBeenCalledTimes(1);
      expect(engine.importCertificate).toHaveBeenCalledTimes(1);
    });

    it("skips the dns-01 callback for an already-valid authorization", async () => {
      scenario.authorizations = {
        [AUTHZ_URL]: dnsOnlyAuthorization("fixture.example.com", "valid"),
      };
      const dns01 = vi.fn(async () => undefined);

      await manager.issueWithAcme("web", { ...issueOptions, dns01, algorithm: "ec" });

      expect(dns01).not.toHaveBeenCalled();
      expect(engine.importCertificate).toHaveBeenCalledTimes(1);
    });

    it("generates a distinct ACME account key per issuance", async () => {
      await manager.issueWithAcme("web", { ...issueOptions, algorithm: "ec" });
      const first = storedAccount(engine).privateKeyPem;

      engine = makeEngine();
      manager = managerFor(engine);
      scenario.instances.length = 0;
      await manager.issueWithAcme("web-2", { ...issueOptions, algorithm: "ec" });
      const second = storedAccount(engine).privateKeyPem;

      expect(second).not.toBe(first);
      expect(second).toBe(issued().accountKeyPem);
    });

    it("refuses an out-of-range http port before any network call", async () => {
      for (const httpPort of [70_000, 0, -1, 8080.5, Number.NaN]) {
        engine = makeEngine();
        manager = managerFor(engine);
        await expect(
          manager.issueWithAcme("web", { ...issueOptions, httpPort, algorithm: "ec" }),
        ).rejects.toThrow(acmeFailed);
        expect(scenario.instances).toHaveLength(0);
      }
    });

    it("refuses an empty domain list", async () => {
      await expect(
        manager.issueWithAcme("web", { domains: [], email: "ops@example.com" }),
      ).rejects.toThrow(acmeFailed);
      expect(scenario.instances).toHaveLength(0);
    });

    it("refuses a blank domain", async () => {
      await expect(
        manager.issueWithAcme("web", { domains: ["  "], email: "ops@example.com" }),
      ).rejects.toThrow(csrFailed);
      expect(scenario.instances).toHaveLength(0);
    });

    it("refuses a blank contact email", async () => {
      await expect(
        manager.issueWithAcme("web", { domains: ["fixture.example.com"], email: " " }),
      ).rejects.toThrow(acmeFailed);
      expect(scenario.instances).toHaveLength(0);
    });
  });

  describe("renewCertificate", () => {
    function primeRenewal(accountUrl = ACCOUNT_URL): void {
      engine.getAcmeAccount.mockReturnValue(
        JSON.stringify({
          privateKeyPem: generateCertKeyPair({ algorithm: "ec" }).privateKeyPem,
          accountUrl,
        }),
      );
      engine.getCertificatePem.mockReturnValue({
        certificatePem: LEAF,
        chainPem: INTERMEDIATE,
        csrPem: CSR_PEM,
      });
      scenario.chainPem = RENEWED_BUNDLE;
    }

    it("refuses a certificate with no stored ACME account", async () => {
      await expect(manager.renewCertificate(SECRET_ID)).rejects.toThrow(
        expect.objectContaining({
          code: ErrorCode.CERT_ACME_FAILED,
          message: expect.stringContaining("no ACME account for this certificate"),
        }),
      );
      expect(scenario.instances).toHaveLength(0);
    });

    it("refuses a certificate with no stored CSR", async () => {
      primeRenewal();
      engine.getCertificatePem.mockReturnValue({
        certificatePem: LEAF,
        chainPem: null,
        csrPem: null,
      });

      await expect(manager.renewCertificate(SECRET_ID)).rejects.toThrow(
        expect.objectContaining({
          code: ErrorCode.CERT_CSR_FAILED,
          message: expect.stringContaining("no stored CSR"),
        }),
      );
      expect(scenario.instances).toHaveLength(0);
    });

    it("updates the certificate as renewed and returns the refreshed status", async () => {
      primeRenewal();

      const status = await manager.renewCertificate(SECRET_ID);

      expect(engine.updateCertificate).toHaveBeenCalledWith(
        SECRET_ID,
        RENEWED_LEAF,
        INTERMEDIATE,
        { renewed: true },
        undefined,
      );
      expect(status).toEqual(STATUS);
    });

    it("restores the stored account instead of registering a new one", async () => {
      primeRenewal();

      await manager.renewCertificate(SECRET_ID);

      const client = issued();
      expect(client.ensureAccount).not.toHaveBeenCalled();
      expect(client.accountUrl).toBe(ACCOUNT_URL);
      expect(client.accountKeyPem).toContain("-----BEGIN PRIVATE KEY-----");
      expect(engine.storeAcmeAccount).not.toHaveBeenCalled();
    });

    it("orders the stored certificate's SANs and finalizes with the stored CSR DER", async () => {
      primeRenewal();

      await manager.renewCertificate(SECRET_ID);

      const client = issued();
      expect(client.newOrder).toHaveBeenCalledWith(["fixture.example.com", "alt.example.com"]);
      const expected = new Uint8Array(
        Buffer.from(CSR_PEM.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64"),
      );
      expect(client.finalize).toHaveBeenCalledWith(FINALIZE_URL, expected);
    });

    it("renews against the staging directory when the stored account is a staging account", async () => {
      primeRenewal(STAGING_ACCOUNT_URL);

      await manager.renewCertificate(SECRET_ID);

      expect(issued().directoryUrl).toBe(STAGING);
    });

    it("renews against the production directory for a production account", async () => {
      primeRenewal();

      await manager.renewCertificate(SECRET_ID);

      expect(issued().directoryUrl).toBe(PRODUCTION);
    });

    it("serves the renewal challenge on the requested port and stops the solver", async () => {
      primeRenewal();

      await manager.renewCertificate(SECRET_ID, { httpPort: 8080 });

      expect(scenario.solverStarts[0]?.port).toBe(8080);
      expect(scenario.solverStops).toBe(1);
    });

    it("stops the solver when the renewal challenge fails", async () => {
      primeRenewal();
      scenario.respondChallengeError = VaultError.certAcmeFailed("challenge failed validation");

      await expect(manager.renewCertificate(SECRET_ID)).rejects.toThrow(acmeFailed);
      expect(scenario.solverStops).toBe(1);
      expect(engine.updateCertificate).not.toHaveBeenCalled();
    });

    it("refuses a dns-01 only renewal", async () => {
      primeRenewal();
      scenario.authorizations = { [AUTHZ_URL]: dnsOnlyAuthorization("fixture.example.com") };

      await expect(manager.renewCertificate(SECRET_ID)).rejects.toThrow(
        expect.objectContaining({
          code: ErrorCode.CERT_ACME_FAILED,
          message: expect.stringContaining("dns-01 renewal requires interactive issuance"),
        }),
      );
      expect(scenario.solverStarts).toHaveLength(0);
      expect(engine.updateCertificate).not.toHaveBeenCalled();
    });

    it("refuses to renew a certificate that carries no SANs", async () => {
      primeRenewal();
      engine.getCertificatePem.mockReturnValue({
        certificatePem: fx("ec-cert.pem").trim(),
        chainPem: null,
        csrPem: CSR_PEM,
      });

      await expect(manager.renewCertificate(SECRET_ID)).rejects.toThrow(certInvalid);
      expect(scenario.instances).toHaveLength(0);
    });

    it("refuses a stored ACME account that is not usable JSON", async () => {
      engine.getAcmeAccount.mockReturnValue("{}");

      await expect(manager.renewCertificate(SECRET_ID)).rejects.toThrow(acmeFailed);
      expect(scenario.instances).toHaveLength(0);
    });

    it("refuses an account at an unknown CA when no directory URL is configured", async () => {
      primeRenewal("https://acme.other-ca.example.com/acme/acct/9");

      await expect(manager.renewCertificate(SECRET_ID)).rejects.toThrow(
        expect.objectContaining({
          code: ErrorCode.CERT_ACME_FAILED,
          message: expect.stringContaining("https://acme.other-ca.example.com"),
        }),
      );
      expect(scenario.instances).toHaveLength(0);
      expect(engine.updateCertificate).not.toHaveBeenCalled();
    });

    it("renews an account at an unknown CA when a directory URL is configured", async () => {
      const custom = "https://acme.other-ca.example.com/directory";
      manager = managerFor(engine, { directoryUrl: custom });
      primeRenewal("https://acme.other-ca.example.com/acme/acct/9");

      await manager.renewCertificate(SECRET_ID);

      expect(issued().directoryUrl).toBe(custom);
      expect(engine.updateCertificate).toHaveBeenCalledTimes(1);
    });

    it("skips solving a renewal authorization the CA already counts as valid", async () => {
      primeRenewal();
      scenario.authorizations = {
        [AUTHZ_URL]: httpAuthorization("fixture.example.com", "valid"),
      };

      await manager.renewCertificate(SECRET_ID);

      expect(scenario.solverStarts).toHaveLength(0);
      expect(scenario.solverStops).toBe(0);
      expect(issued().respondChallenge).not.toHaveBeenCalled();
      expect(engine.updateCertificate).toHaveBeenCalledTimes(1);
    });

    it("accepts an already-valid dns-01 authorization instead of refusing it", async () => {
      primeRenewal();
      scenario.authorizations = {
        [AUTHZ_URL]: dnsOnlyAuthorization("fixture.example.com", "valid"),
      };

      await manager.renewCertificate(SECRET_ID);

      expect(scenario.solverStarts).toHaveLength(0);
      expect(engine.updateCertificate).toHaveBeenCalledTimes(1);
    });

    it("threads a caller into every engine read and the write", async () => {
      primeRenewal();

      await manager.renewCertificate(SECRET_ID, { caller: CALLER });

      expect(engine.getAcmeAccount).toHaveBeenCalledWith(SECRET_ID, CALLER);
      expect(engine.getCertificatePem).toHaveBeenCalledWith(SECRET_ID, CALLER);
      expect(engine.updateCertificate).toHaveBeenCalledWith(
        SECRET_ID,
        RENEWED_LEAF,
        INTERMEDIATE,
        { renewed: true },
        CALLER,
      );
      expect(engine.getCertificateStatus).toHaveBeenCalledWith(SECRET_ID, CALLER);
    });

    it("passes no caller on the trusted local path", async () => {
      primeRenewal();

      await manager.renewCertificate(SECRET_ID);

      expect(engine.getAcmeAccount).toHaveBeenCalledWith(SECRET_ID, undefined);
      expect(engine.updateCertificate).toHaveBeenCalledWith(
        SECRET_ID,
        RENEWED_LEAF,
        INTERMEDIATE,
        { renewed: true },
        undefined,
      );
    });

    it("refuses an out-of-range http port before reading anything from the engine", async () => {
      primeRenewal();
      engine.getAcmeAccount.mockClear();

      await expect(manager.renewCertificate(SECRET_ID, { httpPort: 70_000 })).rejects.toThrow(
        acmeFailed,
      );
      expect(engine.getAcmeAccount).not.toHaveBeenCalled();
      expect(scenario.instances).toHaveLength(0);
    });

    it("decodes a CRLF CSR PEM with blank lines around the armor", async () => {
      primeRenewal();
      const crlf = `\r\n${CSR_PEM.trim().replace(/\n/g, "\r\n")}\r\n\r\n`;
      engine.getCertificatePem.mockReturnValue({
        certificatePem: LEAF,
        chainPem: null,
        csrPem: crlf,
      });

      await manager.renewCertificate(SECRET_ID);

      const expected = new Uint8Array(
        Buffer.from(CSR_PEM.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64"),
      );
      expect(issued().finalize).toHaveBeenCalledWith(FINALIZE_URL, expected);
    });

    it("refuses a stored CSR that is not valid PEM", async () => {
      primeRenewal();
      engine.getCertificatePem.mockReturnValue({
        certificatePem: LEAF,
        chainPem: null,
        csrPem:
          "-----BEGIN CERTIFICATE REQUEST-----\n!!!not base64!!!\n-----END CERTIFICATE REQUEST-----\n",
      });

      await expect(manager.renewCertificate(SECRET_ID)).rejects.toThrow(
        expect.objectContaining({
          code: ErrorCode.CERT_CSR_FAILED,
          message: expect.stringContaining("the stored CSR is not valid PEM"),
        }),
      );
      expect(scenario.instances).toHaveLength(0);
    });

    it("treats an invalid renewal order as a failure", async () => {
      primeRenewal();
      scenario.orderStatus = { status: "invalid" };

      await expect(manager.renewCertificate(SECRET_ID)).rejects.toThrow(acmeFailed);
      expect(engine.updateCertificate).not.toHaveBeenCalled();
    });
  });

  describe("getCertificateInfo", () => {
    it("returns the engine's certificate status", () => {
      expect(manager.getCertificateInfo(SECRET_ID)).toEqual(STATUS);
      expect(engine.getCertificateStatus).toHaveBeenCalledWith(SECRET_ID, undefined);
    });

    it("threads a caller into the engine read", () => {
      manager.getCertificateInfo(SECRET_ID, CALLER);
      expect(engine.getCertificateStatus).toHaveBeenCalledWith(SECRET_ID, CALLER);
    });
  });

  describe("public surface", () => {
    it("re-exports the mandated members from the barrel", async () => {
      const barrel = await vi.importActual<typeof import("./index.js")>("./index.js");

      for (const member of [
        "CertManager",
        "RenewalScheduler",
        "AcmeClient",
        "Http01Solver",
        "buildCsr",
        "generateCertKeyPair",
        "parseCertificate",
        "splitChain",
        "assertKeyMatchesCert",
        "dns01TxtValue",
        "validateAcmeUrl",
        "LETS_ENCRYPT_PRODUCTION",
        "LETS_ENCRYPT_STAGING",
      ]) {
        expect(barrel).toHaveProperty(member);
      }
      expect(barrel.LETS_ENCRYPT_PRODUCTION).toBe(PRODUCTION);
      expect(barrel.LETS_ENCRYPT_STAGING).toBe(STAGING);
    });
  });

  describe("RenewalScheduler conformance", () => {
    it("satisfies the scheduler's structural renewer contract", () => {
      const _renewerCheck: ConstructorParameters<typeof RenewalScheduler>[1] = manager;
      expect(_renewerCheck).toBe(manager);

      const scheduler = new RenewalScheduler(
        { getExpiringCertificates: vi.fn(() => []) } as never,
        manager,
      );
      expect(scheduler.isRunning).toBe(false);
    });
  });
});
