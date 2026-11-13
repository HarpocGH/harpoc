import { X509Certificate } from "node:crypto";
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretStatus, SecretType } from "@harpoc/shared";
import { PROXY_CA_HANDLE, VaultEngine } from "./vault-engine.js";
import type { DecryptedAuditEvent } from "./audit/audit-query.js";
import { nonReadAuditCount, registerAgents } from "./__fixtures__/engine-seams.js";
import { SqliteStore } from "./storage/sqlite-store.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__", "certs");
const fx = (name: string): string => readFileSync(join(FIXTURES, name), "utf8");

/**
 * The two-tier fixture (R-X1): a name-constrained intermediate, its PKCS#8 key and the root that
 * signed it (openssl, 3650 days, the root's key discarded). The canonical self-signed and expired
 * CAs and a key of neither stand in for the refusals.
 */
const HOSTS = ["api.github.com", "127.0.0.1"];
const CA = {
  certPem: fx("proxy-ca-intermediate.pem"),
  keyPem: fx("proxy-ca-intermediate-key.pem"),
  rootPem: fx("proxy-ca-root.pem"),
  hosts: HOSTS,
};
const OTHER_ROOT = fx("ec-cert.pem");
const EXPIRED_ROOT = fx("expired-cert.pem");
const OTHER_KEY = fx("other-key.pem");
const INTERMEDIATE = new X509Certificate(CA.certPem);
const ROOT = new X509Certificate(CA.rootPem);
const UNPARSEABLE = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

/** The key's base64 body without armour or line breaks: what a leaked row or reply would hold. */
const KEY_BODY = CA.keyPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");

let tempDir: string;
let engine: VaultEngine;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-proxy-ca-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
});

afterEach(async () => {
  vi.restoreAllMocks();
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function rows(eventType: AuditEventType, secretId?: string): DecryptedAuditEvent[] {
  return engine.queryAudit({ eventType, secretId });
}

function liveStore(): SqliteStore {
  return (engine as unknown as { store: SqliteStore }).store;
}

function everyRowText(): string {
  return JSON.stringify(engine.queryAudit({ limit: 1000 }));
}

function vaultReads(operation: string): DecryptedAuditEvent[] {
  return rows(AuditEventType.VAULT_READ).filter((row) => row.detail?.operation === operation);
}

describe("createProxyCa — secret://harpoc-ca", () => {
  it("stores the intermediate and its key with the root as the chain, never auto-renewed, and returns no key", async () => {
    const created = await engine.createProxyCa(CA);

    expect(JSON.stringify(created).includes('"type":"Buffer"')).toBe(false);
    expect(JSON.stringify(created)).not.toContain(KEY_BODY.slice(0, 40));
    expect(created).toEqual({
      handle: PROXY_CA_HANDLE,
      hosts: HOSTS,
      unconstrained: false,
      notAfter: INTERMEDIATE.validToDate.getTime(),
      fingerprint256: INTERMEDIATE.fingerprint256,
      rootNotAfter: ROOT.validToDate.getTime(),
      rootFingerprint256: ROOT.fingerprint256,
      replaced: false,
    });
    expect(await engine.getSecretInfo(PROXY_CA_HANDLE)).toMatchObject({
      name: "harpoc-ca",
      type: SecretType.CERTIFICATE,
      status: SecretStatus.ACTIVE,
      project: null,
      expiresAt: INTERMEDIATE.validToDate.getTime(),
    });
    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);
    expect(engine.getCertificateStatus(secretId).auto_renew).toBe(false);
    expect(engine.getCertificatePem(secretId)).toEqual({
      certificatePem: CA.certPem,
      chainPem: CA.rootPem,
      csrPem: null,
    });
  });

  it("writes importCertificate's two rows — secret.create and cert.issue with action proxy_ca_init", async () => {
    await engine.createProxyCa(CA);
    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);

    expect(rows(AuditEventType.SECRET_CREATE, secretId)).toHaveLength(1);
    const issued = rows(AuditEventType.CERT_ISSUE, secretId);
    expect(issued).toHaveLength(1);
    expect(issued[0]).toMatchObject({ success: true, principal_type: null, principal_id: null });
    expect(everyRowText().includes('"type":"Buffer"')).toBe(false);
    expect(everyRowText()).not.toContain(KEY_BODY.slice(0, 40));
    expect(issued[0]?.detail).toEqual({
      handle: PROXY_CA_HANDLE,
      action: "proxy_ca_init",
      subject: INTERMEDIATE.subject,
      not_after: INTERMEDIATE.validToDate.getTime(),
      acme: false,
      acme_account: false,
      hosts: HOSTS,
      unconstrained: false,
    });
  });

  it("refuses a second CA DUPLICATE_SECRET with one failed cert.issue row, the stored CA untouched", async () => {
    await engine.createProxyCa(CA);
    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);

    await expectVaultError(() => engine.createProxyCa(CA), ErrorCode.DUPLICATE_SECRET);

    const failed = rows(AuditEventType.CERT_ISSUE, secretId).filter((row) => !row.success);
    expect(failed).toHaveLength(1);
    expect(failed[0]?.detail).toEqual({
      handle: PROXY_CA_HANDLE,
      action: "proxy_ca_init",
      error: ErrorCode.DUPLICATE_SECRET,
    });
    expect(await engine.resolveSecretId(PROXY_CA_HANDLE)).toBe(secretId);
    expect(rows(AuditEventType.SECRET_REVOKE)).toHaveLength(0);
  });

  it("--force replaces it: the old secret revoked (its secret.revoke row), the new one live under the same handle", async () => {
    await engine.createProxyCa(CA);
    const oldId = await engine.resolveSecretId(PROXY_CA_HANDLE);

    const created = await engine.createProxyCa({ ...CA, force: true });
    const newId = await engine.resolveSecretId(PROXY_CA_HANDLE);

    expect(created.replaced).toBe(true);
    expect(newId).not.toBe(oldId);
    expect(rows(AuditEventType.SECRET_REVOKE, oldId)).toHaveLength(1);
    expect(rows(AuditEventType.SECRET_CREATE, newId)).toHaveLength(1);
    expect(rows(AuditEventType.CERT_ISSUE, newId)).toHaveLength(1);
    expect((await engine.loadProxyCa())?.certPem).toBe(CA.certPem);
  });

  it.each([
    {
      label: "a key that is not the intermediate's",
      input: { ...CA, keyPem: OTHER_KEY },
      code: ErrorCode.CERT_PRIVATE_KEY_MISMATCH,
    },
    {
      label: "an unparseable intermediate",
      input: { ...CA, certPem: UNPARSEABLE },
      code: ErrorCode.CERT_INVALID,
    },
    {
      label: "an intermediate its root did not sign",
      input: { ...CA, rootPem: OTHER_ROOT },
      code: ErrorCode.CERT_INVALID,
    },
    {
      label: "a root that is not self-signed",
      input: { ...CA, rootPem: CA.certPem },
      code: ErrorCode.CERT_INVALID,
    },
    {
      label: "an expired root",
      input: { ...CA, rootPem: EXPIRED_ROOT },
      code: ErrorCode.CERT_EXPIRED,
    },
    { label: "an empty host list", input: { ...CA, hosts: [] }, code: ErrorCode.INVALID_INPUT },
  ])(
    "refuses $label before anything is written, with one failed cert.issue row",
    async ({ input, code }) => {
      await expectVaultError(() => engine.createProxyCa(input), code);

      expect(await engine.proxyCaCertificate()).toBeNull();
      expect(rows(AuditEventType.SECRET_CREATE)).toHaveLength(0);
      const failed = rows(AuditEventType.CERT_ISSUE);
      expect(failed).toHaveLength(1);
      expect(failed[0]).toMatchObject({ success: false, secret_id: null });
      expect(failed[0]?.detail).toEqual({
        handle: PROXY_CA_HANDLE,
        action: "proxy_ca_init",
        error: code,
      });
    },
  );

  it("--force replaces the host list with the certificates", async () => {
    await engine.createProxyCa(CA);

    await engine.createProxyCa({ ...CA, hosts: ["api.github.com"], force: true });

    expect((await engine.loadProxyCa())?.hosts).toEqual(["api.github.com"]);
  });

  // RD-B8-13: the host list bounds the proxy in both modes; the flag names only the certificates.
  it("stores an unconstrained CA's host list and flag, and hands both to the daemon", async () => {
    const created = await engine.createProxyCa({ ...CA, unconstrained: true });

    expect(created).toMatchObject({ hosts: HOSTS, unconstrained: true });
    const material = await engine.loadProxyCa();
    expect(material).toMatchObject({ hosts: HOSTS, unconstrained: true });
  });

  it("the host row commits with the certificate row: a failed row write leaves no certificate", async () => {
    const original = SqliteStore.prototype.setMeta;
    vi.spyOn(SqliteStore.prototype, "setMeta").mockImplementation(function (
      this: SqliteStore,
      key: string,
      value: string,
    ) {
      if (key === "proxy_ca") throw new Error("injected meta write failure");
      original.call(this, key, value);
    });

    await expect(engine.createProxyCa(CA)).rejects.toThrow("injected meta write failure");
    vi.restoreAllMocks();

    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);
    expect(liveStore().getCertificate(secretId)).toBeUndefined();
    expect(liveStore().getMeta("proxy_ca")).toBeUndefined();
    expect(rows(AuditEventType.CERT_ISSUE).filter((row) => row.success)).toHaveLength(0);
  });

  it("a refused --force replacement leaves the stored CA live (the checks run before the revoke)", async () => {
    await engine.createProxyCa(CA);
    const oldId = await engine.resolveSecretId(PROXY_CA_HANDLE);

    await expectVaultError(
      () => engine.createProxyCa({ ...CA, keyPem: OTHER_KEY, force: true }),
      ErrorCode.CERT_PRIVATE_KEY_MISMATCH,
    );

    expect(await engine.resolveSecretId(PROXY_CA_HANDLE)).toBe(oldId);
    expect(rows(AuditEventType.SECRET_REVOKE)).toHaveLength(0);
  });
});

describe("loadProxyCa — the daemon's one read", () => {
  it("is null on a vault without a CA: one vault.read row found: false, NULL principal, and no other row", async () => {
    const before = nonReadAuditCount(engine);

    expect(await engine.loadProxyCa()).toBeNull();
    expect(nonReadAuditCount(engine)).toBe(before);
    const reads = vaultReads("proxy_ca");
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({ secret_id: null, principal_type: null, success: true });
    expect(reads[0]?.detail).toEqual({ operation: "proxy_ca", found: false });
    expect(JSON.stringify(reads[0]?.detail).includes("harpoc-ca")).toBe(false);
  });

  it("hands the intermediate, its key as bytes and the root, with one secret.read row of the key", async () => {
    await engine.createProxyCa(CA);
    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);

    const material = await engine.loadProxyCa();

    expect(material?.certPem).toBe(CA.certPem);
    expect(material?.rootPem).toBe(CA.rootPem);
    expect(Buffer.isBuffer(material?.keyPem)).toBe(true);
    expect(material?.keyPem.toString("utf8") === CA.keyPem).toBe(true);
    expect(material?.notAfter).toBe(INTERMEDIATE.validToDate.getTime());
    expect(material?.fingerprint256).toBe(INTERMEDIATE.fingerprint256);
    expect(material?.hosts).toEqual(HOSTS);
    expect(material?.unconstrained).toBe(false);
    expect(vaultReads("proxy_ca")).toEqual([]);
    const reads = rows(AuditEventType.SECRET_READ, secretId);
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({ success: true, principal_type: null });
    expect(everyRowText().includes('"type":"Buffer"')).toBe(false);
    expect(everyRowText()).not.toContain(KEY_BODY.slice(0, 40));
    expect(reads[0]?.detail).toEqual({ config: "certificate_private_key" });
  });

  it("the daemon's zero-fill of the key bytes leaves the vault's copy whole: the next load reads it again", async () => {
    await engine.createProxyCa(CA);
    const first = await engine.loadProxyCa();
    first?.keyPem.fill(0);

    const second = await engine.loadProxyCa();

    expect(first?.keyPem.every((byte) => byte === 0)).toBe(true);
    expect(second?.keyPem.toString("utf8") === CA.keyPem).toBe(true);
  });

  it("is null once the CA is revoked (secret delete): no secret.read row, one vault.read row found: false", async () => {
    await engine.createProxyCa(CA);
    await engine.revokeSecret(PROXY_CA_HANDLE);

    expect((await engine.loadProxyCa()) === null).toBe(true);
    expect(rows(AuditEventType.SECRET_READ)).toHaveLength(0);
    expect(vaultReads("proxy_ca").map((row) => row.detail)).toEqual([
      { operation: "proxy_ca", found: false },
    ]);
  });

  it("refuses a harpoc-ca that is no vault-managed certificate CERT_NOT_CONFIGURED with a failed row", async () => {
    await engine.createSecret({
      name: "harpoc-ca",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("not-a-ca")),
    });
    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);

    await expectVaultError(() => engine.loadProxyCa(), ErrorCode.CERT_NOT_CONFIGURED);

    const reads = rows(AuditEventType.SECRET_READ, secretId);
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({ success: false });
    expect(reads[0]?.detail).toEqual({
      config: "certificate_private_key",
      error: ErrorCode.CERT_NOT_CONFIGURED,
    });
  });

  it("a live CA without its host row refuses CERT_NOT_CONFIGURED (fail closed), with a failed row", async () => {
    await engine.createProxyCa(CA);
    liveStore().deleteMeta("proxy_ca");

    await expectVaultError(() => engine.loadProxyCa(), ErrorCode.CERT_NOT_CONFIGURED);

    expect(rows(AuditEventType.SECRET_READ).filter((row) => !row.success)).toHaveLength(1);
  });

  // The stored window moved into the past through the store seam: a mocked clock would expire
  // the session first.
  it("refuses a CA past its stored notAfter CERT_EXPIRED naming the expiry, with a failed row", async () => {
    await engine.createProxyCa(CA);
    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);
    const notAfter = Date.now() - 1;
    liveStore().updateCertificate(secretId, { not_after: notAfter });

    const err = await expectVaultError(() => engine.loadProxyCa(), ErrorCode.CERT_EXPIRED);

    expect(err.message).toBe(
      `The Harpoc CA (secret://harpoc-ca) expired at ${new Date(notAfter).toISOString()}; harpoc proxy ca init --force issues a new one`,
    );
    const failed = rows(AuditEventType.SECRET_READ).filter((row) => !row.success);
    expect(failed).toHaveLength(1);
  });

  it("refuses a CA whose stored certificate is not parseable CERT_INVALID before the key is read, with one failed row", async () => {
    await engine.createProxyCa(CA);
    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);
    liveStore().updateCertificate(secretId, { certificate_pem: UNPARSEABLE });

    await expectVaultError(() => engine.loadProxyCa(), ErrorCode.CERT_INVALID);

    const reads = rows(AuditEventType.SECRET_READ, secretId);
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({ success: false });
    expect(reads[0]?.detail).toEqual({
      config: "certificate_private_key",
      error: ErrorCode.CERT_INVALID,
    });
  });

  it("refuses on a sealed vault VAULT_LOCKED", async () => {
    await engine.createProxyCa(CA);
    await engine.lock();

    await expectVaultError(() => engine.loadProxyCa(), ErrorCode.VAULT_LOCKED);
  });
});

describe("proxyCaCertificate — the export's read", () => {
  it("is null without a CA: no secret.read row, one vault.read row found: false", async () => {
    expect(await engine.proxyCaCertificate()).toBeNull();
    expect(rows(AuditEventType.SECRET_READ)).toHaveLength(0);
    const reads = vaultReads("proxy_ca");
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({ secret_id: null, principal_type: null, success: true });
    expect(reads[0]?.detail).toEqual({ operation: "proxy_ca", found: false });
    expect(JSON.stringify(reads[0]?.detail).includes("harpoc-ca")).toBe(false);
  });

  it("returns the root — the trust anchor — and its window with one secret.read row of the PEMs", async () => {
    await engine.createProxyCa(CA);
    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);

    expect(await engine.proxyCaCertificate()).toEqual({
      handle: PROXY_CA_HANDLE,
      certPem: CA.rootPem,
      notBefore: ROOT.validFromDate.getTime(),
      notAfter: ROOT.validToDate.getTime(),
      fingerprint256: ROOT.fingerprint256,
    });
    expect(vaultReads("proxy_ca")).toEqual([]);
    const reads = rows(AuditEventType.SECRET_READ, secretId);
    expect(reads).toHaveLength(1);
    expect(reads[0]?.detail).toEqual({ config: "certificate_pem" });
  });

  it("refuses a harpoc-ca certificate imported without its root CERT_NOT_CONFIGURED with exactly one failed row", async () => {
    await engine.importCertificate("harpoc-ca", CA.keyPem, { certificatePem: CA.certPem });
    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);

    await expectVaultError(() => engine.proxyCaCertificate(), ErrorCode.CERT_NOT_CONFIGURED);

    const reads = rows(AuditEventType.SECRET_READ, secretId);
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({ success: false });
    expect(reads[0]?.detail).toEqual({
      config: "certificate_pem",
      error: ErrorCode.CERT_NOT_CONFIGURED,
    });
  });

  it("refuses a CA whose stored root is not parseable CERT_INVALID with exactly one failed row", async () => {
    await engine.createProxyCa(CA);
    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);
    liveStore().updateCertificate(secretId, { chain_pem: UNPARSEABLE });

    await expectVaultError(() => engine.proxyCaCertificate(), ErrorCode.CERT_INVALID);

    const reads = rows(AuditEventType.SECRET_READ, secretId);
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({ success: false });
    expect(reads[0]?.detail).toEqual({
      config: "certificate_pem",
      error: ErrorCode.CERT_INVALID,
    });
  });
});

describe("secret://harpoc-ca is never a credential", () => {
  function proxyCaller(id: string): CallerContext {
    return {
      principal_type: "agent",
      principal_id: id,
      interface: "proxy",
      remote_address: "127.0.0.1",
    };
  }

  async function brokerable(): Promise<string> {
    await engine.createProxyCa(CA);
    const secretId = await engine.resolveSecretId(PROXY_CA_HANDLE);
    await engine.setInjectionPolicy(PROXY_CA_HANDLE, {
      url_allowlist: ["https://api.github.com/*"],
      proxy: true,
    });
    registerAgents(engine, "alice");
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alice", permissions: ["use"] },
      "test-admin",
    );
    return secretId;
  }

  it("resolveForProxy refuses it CERT_VALUE_UNSUPPORTED even with proxy: true, a matching allowlist and use", async () => {
    const secretId = await brokerable();

    await expectVaultError(
      () =>
        engine.resolveForProxy(PROXY_CA_HANDLE, proxyCaller("alice"), {
          method: "GET",
          origin: "https://api.github.com",
          path: "/user",
        }),
      ErrorCode.CERT_VALUE_UNSUPPORTED,
    );
    const uses = rows(AuditEventType.SECRET_USE, secretId);
    expect(uses).toHaveLength(1);
    expect(uses[0]).toMatchObject({ success: false });
    expect(uses[0]?.detail).toMatchObject({ error: ErrorCode.CERT_VALUE_UNSUPPORTED });
  });

  // The engine's own refusal precedes the opt-in and the allowlist (the secret manager's value
  // read refuses it a second time behind them): a target outside the allowlist still reads
  // CERT_VALUE_UNSUPPORTED, not URL_NOT_ALLOWED.
  it("the refusal precedes the opt-in and the allowlist: an unlisted target reads CERT_VALUE_UNSUPPORTED", async () => {
    await brokerable();

    await expectVaultError(
      () =>
        engine.resolveForProxy(PROXY_CA_HANDLE, proxyCaller("alice"), {
          method: "GET",
          origin: "https://evil.example",
          path: "/",
        }),
      ErrorCode.CERT_VALUE_UNSUPPORTED,
    );
  });

  it("getSecretValue refuses it CERT_VALUE_UNSUPPORTED", async () => {
    await engine.createProxyCa(CA);

    await expectVaultError(
      () => engine.getSecretValue(PROXY_CA_HANDLE),
      ErrorCode.CERT_VALUE_UNSUPPORTED,
    );
  });
});

describe("the reads that can find nothing write found: false (A-6)", () => {
  const CERT_NAME = "web-cert";
  const READER: CallerContext = {
    principal_type: "agent",
    principal_id: "alice",
    interface: "rest",
    remote_address: "127.0.0.1",
  };

  function failNextAuditInsert(): void {
    vi.spyOn(liveStore(), "insertAuditEvent").mockImplementationOnce(() => {
      throw new Error("audit unavailable");
    });
  }

  async function certificateWithoutAccount(): Promise<string> {
    const { secretId } = await engine.importCertificate(CERT_NAME, fx("ec-key.pem"), {
      certificatePem: fx("ec-cert.pem"),
    });
    registerAgents(engine, "alice");
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alice", permissions: ["read"] },
      "test-admin",
    );
    return secretId;
  }

  it.each([
    { read: "loadProxyCa", call: () => engine.loadProxyCa() },
    { read: "proxyCaCertificate", call: () => engine.proxyCaCertificate() },
  ])(
    "$read without a CA throws the logger's error and answers nothing when its row cannot be written",
    async ({ call }) => {
      failNextAuditInsert();

      await expect(call()).rejects.toThrow("audit unavailable");
      expect(vaultReads("proxy_ca")).toEqual([]);
    },
  );

  it("getAcmeAccount without a stored account: null, one vault.read row found: false with the caller's principal and no secret id, no secret.read row", async () => {
    const secretId = await certificateWithoutAccount();

    expect(engine.getAcmeAccount(secretId, READER, `secret://${CERT_NAME}`)).toBeNull();

    expect(rows(AuditEventType.SECRET_READ, secretId)).toEqual([]);
    const reads = vaultReads("acme_account");
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({
      secret_id: null,
      principal_type: "agent",
      principal_id: "alice",
      ip_address: "127.0.0.1",
      success: true,
    });
    expect(reads[0]?.detail).toEqual({
      operation: "acme_account",
      found: false,
      interface: "rest",
    });
    expect(JSON.stringify(reads[0]?.detail).includes(CERT_NAME)).toBe(false);
    expect(JSON.stringify(reads[0]?.detail).includes(secretId)).toBe(false);
  });

  it("getAcmeAccount with a stored account writes the secret.read row it writes today and no vault.read row", async () => {
    const { secretId } = await engine.importCertificate(CERT_NAME, fx("ec-key.pem"), {
      certificatePem: fx("ec-cert.pem"),
      acmeIssued: true,
      acmeAccountJson: JSON.stringify({ accountUrl: "u" }),
    });

    expect(engine.getAcmeAccount(secretId)).toContain("accountUrl");

    expect(vaultReads("acme_account")).toEqual([]);
    const reads = rows(AuditEventType.SECRET_READ, secretId);
    expect(reads).toHaveLength(1);
    expect(reads[0]?.detail).toEqual({ config: "acme_account" });
  });

  it("getAcmeAccount without a stored account throws the logger's error and returns nothing when its row cannot be written", async () => {
    const secretId = await certificateWithoutAccount();
    failNextAuditInsert();

    let answer: unknown;
    expect(() => {
      answer = engine.getAcmeAccount(secretId, READER);
    }).toThrow("audit unavailable");
    expect(answer).toBeUndefined();
    expect(vaultReads("acme_account")).toEqual([]);
  });
});
