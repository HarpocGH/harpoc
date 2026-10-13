import { X509Certificate } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, SecretStatus } from "@harpoc/shared";
import { VaultEngine } from "@harpoc/core";
import { CertManager } from "../cert-manager.js";
import { startAcmeDouble } from "../__fixtures__/acme-double.js";
import type { AcmeDouble } from "../__fixtures__/acme-double.js";

vi.mock("argon2", () => ({
  hash: async (password: Buffer | string, opts: { salt: Buffer | Uint8Array }) => {
    const { createHash } = await import("node:crypto");
    const salt = opts.salt instanceof Uint8Array ? Buffer.from(opts.salt) : opts.salt;
    return createHash("sha256")
      .update(typeof password === "string" ? password : Buffer.from(password))
      .update(salt)
      .digest();
  },
}));

/** A loopback port the OS just handed out (bound on 0, read back, released). */
async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", () => resolve()));
  const { port } = probe.address() as { port: number };
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

function spkiOf(pem: string): Buffer {
  return new X509Certificate(pem).publicKey.export({ type: "spki", format: "der" });
}

// M-P3-5 (test-review-2026-10-09): ACME issuance and renewal composed end to
// end — the real AcmeClient, the real http-01 responder and a real engine —
// against a local CA double, where every other suite stubs one of the three.
describe("CertManager against a local ACME CA double (M-P3-5)", () => {
  let tempDir: string;
  let engine: VaultEngine;
  let double: AcmeDouble;
  let stopDouble: (() => Promise<void>) | undefined;
  let httpPort: number;
  let manager: CertManager;

  beforeEach(async () => {
    tempDir = join(
      tmpdir(),
      `harpoc-acme-live-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    mkdirSync(tempDir, { recursive: true });
    engine = new VaultEngine({
      dbPath: join(tempDir, "test.vault.db"),
      sessionPath: join(tempDir, "session.json"),
    });
    await engine.initVault("password");
    httpPort = await freePort();
    double = await startAcmeDouble({ httpPort });
    stopDouble = double.close;
    manager = new CertManager(engine, { directoryUrl: double.directoryUrl });
  });

  afterEach(async () => {
    await stopDouble?.();
    stopDouble = undefined;
    await engine.destroy();
    rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const issueOptions = (): Parameters<CertManager["issueWithAcme"]>[1] => ({
    domains: ["localhost"],
    email: "ops@example.com",
    httpPort,
    algorithm: "ec",
  });

  it("issueWithAcme stores an active certificate the double's CA signed, with its ACME account", async () => {
    const issued = await manager.issueWithAcme("acme-live", issueOptions());

    expect(double.requests.map((r) => `${r.method} ${r.path.replace(/\/\d+$/, "/:id")}`)).toEqual([
      "GET /directory",
      "HEAD /new-nonce",
      "POST /new-account",
      "POST /new-order",
      "POST /authz/:id",
      "POST /chall/:id",
      "POST /finalize/:id",
      "POST /order/:id",
      "POST /cert/:id",
    ]);
    expect((await engine.getSecretInfo(issued.handle)).status).toBe(SecretStatus.ACTIVE);
    const material = engine.getCertificatePem(issued.secretId);
    const leaf = new X509Certificate(material.certificatePem as string);
    expect(leaf.verify(double.caCertificate.publicKey)).toBe(true);
    expect(leaf.checkIssued(double.caCertificate)).toBe(true);
    expect(leaf.issuer).toBe(double.caCertificate.subject);
    expect(leaf.subjectAltName).toBe("DNS:localhost");
    expect(material.chainPem?.trim()).toBe(double.caPem.trim());
    expect(issued.status.issuer).toBe(double.caCertificate.subject);

    // The key never crossed the wire: the CA signed the CSR's public key and
    // the engine accepted the leaf against the key it holds. No recorded
    // request carries a PEM private key, and the one JWK sent (newAccount's
    // account key) carries no private `d` member.
    expect(spkiOf(leaf.toString())).toEqual(double.csrPublicKeys[0]);
    expect(JSON.stringify(double.requests)).not.toContain("PRIVATE KEY");
    const jwks = double.requests
      .map((r) => r.protectedHeader?.jwk)
      .filter((jwk) => jwk !== undefined);
    expect(jwks).toHaveLength(1);
    expect(jwks[0]).not.toHaveProperty("d");

    const rows = engine.queryAudit({
      secretId: issued.secretId,
      eventType: AuditEventType.CERT_ISSUE,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(true);
    expect(rows[0]?.detail).toMatchObject({ acme: true, acme_account: true });
    const account = JSON.parse(engine.getAcmeAccount(issued.secretId) as string) as {
      accountUrl: string;
    };
    expect(account.accountUrl).toBe(`${new URL(double.directoryUrl).origin}/acct/1`);
  });

  it("renewCertificate re-orders on the stored account: a new serial, the same key, the cert.renew row", async () => {
    const issued = await manager.issueWithAcme("acme-live", issueOptions());
    const first = new X509Certificate(
      engine.getCertificatePem(issued.secretId).certificatePem as string,
    );
    const { accountUrl } = JSON.parse(engine.getAcmeAccount(issued.secretId) as string) as {
      accountUrl: string;
    };
    const issuance = double.requests.length;

    const status = await manager.renewCertificate(issued.secretId, { httpPort });

    const renewal = double.requests.slice(issuance);
    expect(renewal.map((r) => `${r.method} ${r.path.replace(/\/\d+$/, "/:id")}`)).toEqual([
      "GET /directory",
      "HEAD /new-nonce",
      "POST /new-order",
      "POST /authz/:id",
      "POST /chall/:id",
      "POST /finalize/:id",
      "POST /order/:id",
      "POST /cert/:id",
    ]);
    const signed = renewal.filter((r) => r.protectedHeader !== null);
    expect(signed.map((r) => r.protectedHeader?.kid)).toEqual(signed.map(() => accountUrl));

    const second = new X509Certificate(
      engine.getCertificatePem(issued.secretId).certificatePem as string,
    );
    expect(second.serialNumber).not.toBe(first.serialNumber);
    expect(second.verify(double.caCertificate.publicKey)).toBe(true);
    expect(spkiOf(second.toString())).toEqual(spkiOf(first.toString()));
    expect(double.csrPublicKeys).toHaveLength(2);
    expect(double.csrPublicKeys[1]).toEqual(double.csrPublicKeys[0]);
    expect(status.renewal_status).toBe("ok");

    const rows = engine.queryAudit({
      secretId: issued.secretId,
      eventType: AuditEventType.CERT_RENEW,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(true);
  });
});
