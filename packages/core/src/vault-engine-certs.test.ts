import { createServer } from "node:http";
import type { Server } from "node:http";
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, PrincipalType, SecretType, VaultError } from "@harpoc/shared";
import type { Permission } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";
import type { SqliteStore } from "./storage/sqlite-store.js";

vi.mock("./crypto/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array) => {
      const { createHash } = await import("node:crypto");
      return new Uint8Array(createHash("sha256").update(password).update(salt).digest());
    },
  };
});

/*
 * The __fixtures__/certs material was generated once with OpenSSL 3.5.3:
 *
 * openssl req -x509 -newkey rsa:2048 -keyout rsa-key.pem -out rsa-cert.pem -days 3650 -nodes \
 *   -subj "/CN=fixture.example.com" \
 *   -addext "subjectAltName=DNS:fixture.example.com,DNS:alt.example.com"
 * openssl req -x509 -newkey rsa:2048 -keyout expired-key.pem -out expired-cert.pem -nodes \
 *   -subj "/CN=expired.example.com" -not_before 20190101000000Z -not_after 20200101000000Z
 * openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout ec-key.pem \
 *   -out ec-cert.pem -days 3650 -nodes -subj "/CN=ec.example.com"
 * openssl genrsa -out other-key.pem 2048
 *
 * rsa-cert-renewed.pem is a second leaf for the SAME rsa-key — the renewal
 * case: different serial, not_after 20 years out instead of 10:
 *
 * openssl req -x509 -key rsa-key.pem -out rsa-cert-renewed.pem -days 7300 \
 *   -subj "/CN=fixture.example.com" \
 *   -addext "subjectAltName=DNS:fixture.example.com,DNS:alt.example.com"
 */
const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__", "certs");
const fx = (name: string): string => readFileSync(join(FIXTURES, name), "utf8");

interface StoredCertRow {
  secret_id: string;
  subject: string;
  issuer: string | null;
  serial_number: string | null;
  not_before: number | null;
  not_after: number | null;
  private_key_encrypted: Buffer;
  private_key_iv: Buffer;
  private_key_tag: Buffer;
  certificate_pem: string | null;
  chain_pem: string | null;
  csr_pem: string | null;
  auto_renew: number;
  renew_before_days: number;
  acme_account_encrypted: Buffer | null;
  acme_account_iv: Buffer | null;
  acme_account_tag: Buffer | null;
}

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

/**
 * Register the agent identities this suite mints tokens or grants for — the
 * v1.4 registration gate refuses an unregistered agent-typed principal.
 */
function registerAgents(...names: string[]): void {
  for (const name of names) {
    try {
      engine.registerAgent({ name });
    } catch (err) {
      if (!(err instanceof VaultError) || err.code !== ErrorCode.AGENT_EXISTS) throw err;
    }
  }
}

/**
 * Some row-level assertions read the committed row straight from SQLite — for
 * the encrypted-at-rest checks that must not go through the accessor under
 * test.
 */
function storedCert(secretId: string): StoredCertRow | undefined {
  const db = new Database(dbPath, { readonly: true });
  try {
    return db.prepare("SELECT * FROM certificates WHERE secret_id = ?").get(secretId) as
      | StoredCertRow
      | undefined;
  } finally {
    db.close();
  }
}

/**
 * Backdate a secret's `updated_at` out-of-band, so a bump is observable even
 * when the write lands inside the same millisecond as its setup.
 */
function backdateSecret(secretId: string): void {
  const db = new Database(dbPath);
  try {
    db.prepare("UPDATE secrets SET updated_at = 0 WHERE id = ?").run(secretId);
  } finally {
    db.close();
  }
}

function storedSecretUpdatedAt(secretId: string): number {
  const db = new Database(dbPath, { readonly: true });
  try {
    const row = db.prepare("SELECT updated_at AS t FROM secrets WHERE id = ?").get(secretId) as {
      t: number;
    };
    return row.t;
  } finally {
    db.close();
  }
}

/**
 * Fault injection for the NM3 atomicity claims: let the first `passes` audit
 * inserts through, then break the next one. `passes` skips the rows a method
 * legitimately writes before the transaction under test (updateCertificate
 * reads the private key first, which audits).
 */
function failAuditInsertAfter(passes: number): void {
  const store = (engine as unknown as { store: SqliteStore }).store;
  const original = store.insertAuditEvent.bind(store);
  let seen = 0;
  vi.spyOn(store, "insertAuditEvent").mockImplementation((event, rowHmac) => {
    seen += 1;
    if (seen > passes) throw new Error("audit unavailable");
    return original(event, rowHmac);
  });
}

/** Move an encrypted ACME blob onto another secret's row, out-of-band. */
function transplantAcmeBlob(fromSecretId: string, toSecretId: string): void {
  const source = storedCert(fromSecretId) as StoredCertRow;
  const db = new Database(dbPath);
  try {
    db.prepare(
      `UPDATE certificates
         SET acme_account_encrypted = ?, acme_account_iv = ?, acme_account_tag = ?
       WHERE secret_id = ?`,
    ).run(
      source.acme_account_encrypted,
      source.acme_account_iv,
      source.acme_account_tag,
      toSecretId,
    );
  } finally {
    db.close();
  }
}

/**
 * Shrink a stored certificate's expiry out-of-band (idiom:
 * vault-engine-expiring-status.test.ts). The row count is asserted: an UPDATE
 * matching nothing is silent, and the caller would go on asserting about the
 * fixture's own imported validity window while believing it had moved it.
 */
function setNotAfter(secretId: string, notAfter: number): void {
  const db = new Database(dbPath);
  try {
    const { changes }: { changes: number } = db
      .prepare("UPDATE certificates SET not_after = ? WHERE secret_id = ?")
      .run(notAfter, secretId);
    expect(changes).toBe(1);
  } finally {
    db.close();
  }
}

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-certs-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
});

afterEach(async () => {
  vi.restoreAllMocks();
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

// Loopback target for the http action: the request counter makes "refused
// before any request" observable, and the captured header makes "the real
// credential still reaches the wire" observable for the legacy shape.
let targetServer: Server;
let targetUrl: string;
let requestCount = 0;
let lastAuthHeader: string | undefined;

beforeAll(async () => {
  targetServer = createServer((req, res) => {
    requestCount += 1;
    lastAuthHeader = req.headers["authorization"];
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end("{}");
  });
  await new Promise<void>((resolve) => {
    targetServer.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = targetServer.address() as { port: number };
  targetUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(() => {
  targetServer.close();
});

beforeEach(() => {
  requestCount = 0;
  lastAuthHeader = undefined;
});

// ---------------------------------------------------------------------------
// importCertificate
// ---------------------------------------------------------------------------

describe("importCertificate", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("imports key+cert, parses metadata, sets expires_at, transitions ACTIVE", async () => {
    const { handle, secretId } = await engine.importCertificate("web-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    });
    expect(handle).toBe("secret://web-cert");
    expect(secretId).toBeTruthy();

    const secrets = engine.listSecrets();
    const info = secrets.find((x) => x.name === "web-cert") as (typeof secrets)[number];
    expect(info.type).toBe("certificate");
    expect(info.status).toBe("active");
    expect(info.expiresAt).toBeGreaterThan(Date.now());
  });

  it("persists the parsed certificate metadata and an encrypted private key", async () => {
    const { secretId } = await engine.importCertificate("meta-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    });

    const row = storedCert(secretId) as StoredCertRow;
    expect(row.subject).toBe("CN=fixture.example.com");
    expect(row.issuer).toBe("CN=fixture.example.com");
    expect(row.serial_number).toBeTruthy();
    expect(row.not_before).toBeLessThanOrEqual(Date.now());
    expect(row.not_after).toBeGreaterThan(Date.now());
    expect(row.certificate_pem).toBe(fx("rsa-cert.pem"));
    expect(row.csr_pem).toBeNull();
    expect(row.auto_renew).toBe(0);
    expect(row.renew_before_days).toBe(30);
    expect(row.acme_account_encrypted).toBeNull();
    expect(row.private_key_encrypted.toString("utf8")).not.toContain("PRIVATE KEY");
  });

  it("rejects a renewBeforeDays above 365 before any write", async () => {
    await expect(
      engine.importCertificate("cap-cert", fx("rsa-key.pem"), {
        certificatePem: fx("rsa-cert.pem"),
        renewBeforeDays: 366,
      }),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
    expect(engine.listSecrets().find((x) => x.name === "cap-cert")).toBeUndefined();
  });

  it("rejects a non-positive renewBeforeDays", async () => {
    await expect(
      engine.importCertificate("cap-zero", fx("rsa-key.pem"), {
        certificatePem: fx("rsa-cert.pem"),
        renewBeforeDays: 0,
      }),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
  });

  it("accepts the 365-day boundary and stores it", async () => {
    const { secretId } = await engine.importCertificate("cap-max", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      renewBeforeDays: 365,
    });
    expect((storedCert(secretId) as StoredCertRow).renew_before_days).toBe(365);
  });

  it("accepts an EC key/cert pair", async () => {
    const { secretId } = await engine.importCertificate("ec-cert", fx("ec-key.pem"), {
      certificatePem: fx("ec-cert.pem"),
    });
    expect(storedCert(secretId)?.subject).toBe("CN=ec.example.com");
  });

  it("imports an already-expired certificate with a past not_after", async () => {
    const { secretId } = await engine.importCertificate("old-cert", fx("expired-key.pem"), {
      certificatePem: fx("expired-cert.pem"),
    });
    expect(storedCert(secretId)?.not_after).toBeLessThan(Date.now());
  });

  it("refuses a mismatched key/cert pair", async () => {
    await expect(
      engine.importCertificate("bad", fx("other-key.pem"), { certificatePem: fx("rsa-cert.pem") }),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_PRIVATE_KEY_MISMATCH });
  });

  it("audits a pre-write refusal, with no secret id when nothing was created", async () => {
    await expect(
      engine.importCertificate("bad-audited", fx("other-key.pem"), {
        certificatePem: fx("rsa-cert.pem"),
      }),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_PRIVATE_KEY_MISMATCH });

    const denials = engine
      .queryAudit({ eventType: AuditEventType.CERT_ISSUE })
      .filter((e) => !e.success);
    expect(denials.length).toBe(1);
    expect(denials[0]?.secret_id).toBeNull();
    expect(denials[0]?.detail).toMatchObject({
      name: "bad-audited",
      action: "import_certificate",
      error: ErrorCode.CERT_PRIVATE_KEY_MISMATCH,
    });
    expect(JSON.stringify(denials[0]?.detail)).not.toContain("PRIVATE KEY");
    // Nothing was created: the name is still free.
    expect(engine.listSecrets().length).toBe(0);
  });

  it("audits a duplicate-name refusal and leaves the first import intact", async () => {
    const { secretId } = await engine.importCertificate("dup-audited", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    });

    await expect(
      engine.importCertificate("dup-audited", fx("rsa-key.pem"), {
        certificatePem: fx("rsa-cert.pem"),
      }),
    ).rejects.toMatchObject({ code: ErrorCode.DUPLICATE_SECRET });

    const denials = engine
      .queryAudit({ eventType: AuditEventType.CERT_ISSUE })
      .filter((e) => !e.success);
    expect(denials.length).toBe(1);
    expect(denials[0]?.detail).toMatchObject({
      name: "dup-audited",
      action: "import_certificate",
      error: ErrorCode.DUPLICATE_SECRET,
    });
    // No id: the collision is detected inside the create transaction, before
    // any row of this import exists.
    expect(denials[0]?.secret_id).toBeNull();
    expect(storedCert(secretId)?.certificate_pem).toBe(fx("rsa-cert.pem"));
  });

  it("refuses an unparseable private key", async () => {
    await expect(
      engine.importCertificate("bad-key", "-----BEGIN PRIVATE KEY-----\nnope\n", {
        certificatePem: fx("rsa-cert.pem"),
      }),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_INVALID });
  });

  it("refuses an unparseable certificate", async () => {
    await expect(
      engine.importCertificate("bad-cert", fx("rsa-key.pem"), {
        certificatePem: "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n",
      }),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_INVALID });
  });

  it("refuses import with neither certificate nor csr+subject", async () => {
    await expect(engine.importCertificate("bare", fx("rsa-key.pem"))).rejects.toMatchObject({
      code: ErrorCode.CERT_INVALID,
    });
  });

  it("refuses a csr without a subject", async () => {
    await expect(
      engine.importCertificate("csr-only", fx("rsa-key.pem"), {
        csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
      }),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_INVALID });
  });

  it("accepts csr+subject without a certificate and stays PENDING with no expires_at", async () => {
    const csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";
    const { secretId } = await engine.importCertificate("pending-csr", fx("rsa-key.pem"), {
      csrPem: csr,
      subject: "CN=pending.example.com",
    });
    const secrets = engine.listSecrets();
    const info = secrets.find((x) => x.name === "pending-csr") as (typeof secrets)[number];
    expect(info.status).toBe("pending");
    expect(info.expiresAt).toBeNull();
    expect(secretId).toBeTruthy();

    const row = storedCert(secretId) as StoredCertRow;
    expect(row.subject).toBe("CN=pending.example.com");
    expect(row.csr_pem).toBe(csr);
    expect(row.certificate_pem).toBeNull();
    expect(row.not_before).toBeNull();
    expect(row.not_after).toBeNull();
  });

  it("honours autoRenew, renewBeforeDays, chainPem and project", async () => {
    const { handle, secretId } = await engine.importCertificate(
      "opts-cert",
      fx("rsa-key.pem"),
      {
        certificatePem: fx("rsa-cert.pem"),
        chainPem: fx("ec-cert.pem"),
        autoRenew: true,
        renewBeforeDays: 14,
      },
      "webops",
    );
    expect(handle).toBe("secret://webops/opts-cert");

    const row = storedCert(secretId) as StoredCertRow;
    expect(row.auto_renew).toBe(1);
    expect(row.renew_before_days).toBe(14);
    expect(row.chain_pem).toBe(fx("ec-cert.pem"));
  });

  it("always writes secret.create and cert.issue, with acme flagging the ACME path", async () => {
    const { secretId: plainId } = await engine.importCertificate("plain-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    });
    const { secretId: acmeId } = await engine.importCertificate("acme-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      acmeIssued: true,
    });

    const events = engine.queryAudit({ limit: 50 });
    for (const id of [plainId, acmeId]) {
      const forSecret = events.filter((e) => e.secret_id === id).map((e) => e.event_type);
      expect(forSecret).toContain("secret.create");
      expect(forSecret).toContain("cert.issue");
    }

    const plainIssue = events.find((e) => e.event_type === "cert.issue" && e.secret_id === plainId);
    const acmeIssue = events.find((e) => e.event_type === "cert.issue" && e.secret_id === acmeId);
    expect(plainIssue?.detail?.acme).toBe(false);
    expect(acmeIssue?.detail?.acme).toBe(true);
    expect(plainIssue?.detail?.subject).toBe("CN=fixture.example.com");
  });

  it("writes a cert.issue row for a CSR-only import too", async () => {
    const { secretId } = await engine.importCertificate("csr-audit", fx("rsa-key.pem"), {
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
      subject: "CN=csr.example.com",
    });
    const issue = engine
      .queryAudit({ limit: 50 })
      .find((e) => e.event_type === "cert.issue" && e.secret_id === secretId);
    expect(issue?.detail?.acme).toBe(false);
    expect(issue?.detail?.not_after).toBeNull();
  });

  it("keeps the private key out of the cert.issue audit detail", async () => {
    const { secretId } = await engine.importCertificate("audit-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      acmeIssued: true,
    });
    const issue = engine
      .queryAudit({ limit: 50 })
      .find((e) => e.event_type === "cert.issue" && e.secret_id === secretId);
    expect(issue).toBeDefined();
    expect(JSON.stringify(issue?.detail)).not.toContain("PRIVATE KEY");
  });

  it("rejects a duplicate certificate name", async () => {
    await engine.importCertificate("dup-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    });
    await expect(
      engine.importCertificate("dup-cert", fx("rsa-key.pem"), {
        certificatePem: fx("rsa-cert.pem"),
      }),
    ).rejects.toMatchObject({ code: ErrorCode.DUPLICATE_SECRET });
  });

  it("refuses to import while the vault is locked", async () => {
    await engine.lock();
    await expect(
      engine.importCertificate("locked", fx("rsa-key.pem"), {
        certificatePem: fx("rsa-cert.pem"),
      }),
    ).rejects.toMatchObject({ code: ErrorCode.VAULT_LOCKED });
  });

  // -------------------------------------------------------------------------
  // V2 attribution parity: `create` is not grantable per secret, so the caller
  // is attribution only — but a token-bearing import must not be
  // indistinguishable from the trusted local path in the trail.
  // -------------------------------------------------------------------------

  const IMPORTER = {
    principal_type: PrincipalType.AGENT,
    principal_id: "cert-importer",
    interface: "cli",
  } as const;

  it("attributes both the secret.create and the cert.issue row to the caller", async () => {
    const { secretId } = await engine.importCertificate(
      "attributed-cert",
      fx("rsa-key.pem"),
      { certificatePem: fx("rsa-cert.pem") },
      undefined,
      IMPORTER,
    );

    const create = engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_CREATE }).at(0);
    expect(create?.principal_type).toBe(PrincipalType.AGENT);
    expect(create?.principal_id).toBe("cert-importer");
    expect(create?.detail).toMatchObject({ interface: "cli" });

    const issue = engine.queryAudit({ secretId, eventType: AuditEventType.CERT_ISSUE }).at(0);
    expect(issue?.principal_type).toBe(PrincipalType.AGENT);
    expect(issue?.principal_id).toBe("cert-importer");
    expect(issue?.detail).toMatchObject({ interface: "cli", action: "import_certificate" });
  });

  it("leaves both rows NULL-principal on the trusted caller-less path", async () => {
    const { secretId } = await engine.importCertificate("local-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    });

    const create = engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_CREATE }).at(0);
    expect(create?.principal_type).toBeNull();
    expect(create?.principal_id).toBeNull();
    expect(create?.detail).not.toHaveProperty("interface");

    const issue = engine.queryAudit({ secretId, eventType: AuditEventType.CERT_ISSUE }).at(0);
    expect(issue?.principal_type).toBeNull();
    expect(issue?.principal_id).toBeNull();
    expect(issue?.detail).not.toHaveProperty("interface");
  });

  it("attributes the denial row of a refused import", async () => {
    await expect(
      engine.importCertificate(
        "denied-cert",
        fx("other-key.pem"),
        { certificatePem: fx("rsa-cert.pem") },
        undefined,
        IMPORTER,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_PRIVATE_KEY_MISMATCH });

    const denials = engine
      .queryAudit({ eventType: AuditEventType.CERT_ISSUE })
      .filter((e) => !e.success);
    expect(denials.length).toBe(1);
    expect(denials[0]?.principal_type).toBe(PrincipalType.AGENT);
    expect(denials[0]?.principal_id).toBe("cert-importer");
    expect(denials[0]?.detail).toMatchObject({ interface: "cli" });
  });

  it("carries the caller into a CSR-only import as well", async () => {
    const { secretId } = await engine.importCertificate(
      "attributed-csr",
      fx("rsa-key.pem"),
      {
        csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
        subject: "CN=csr.example.com",
      },
      undefined,
      { principal_type: PrincipalType.TOOL, principal_id: "csr-bot", interface: "rest" },
    );

    const issue = engine.queryAudit({ secretId, eventType: AuditEventType.CERT_ISSUE }).at(0);
    expect(issue?.principal_type).toBe(PrincipalType.TOOL);
    expect(issue?.principal_id).toBe("csr-bot");
    expect(issue?.detail).toMatchObject({ interface: "rest" });
  });
});

// ---------------------------------------------------------------------------
// Certificate secrets on the generic value paths
// ---------------------------------------------------------------------------

/**
 * A vault-managed certificate's secrets-row payload is empty by construction,
 * so the generic value paths must refuse rather than hand out or inject a
 * zero-length credential. Both the read accessor and the use/injection path
 * are pinned.
 */
describe("certificate secrets are refused on the generic value paths", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.importCertificate("tls-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    });
  });

  it("refuses useSecret with an http action before any request is made", async () => {
    const before = requestCount;
    try {
      await engine.useSecret("secret://tls-cert", {
        type: "http",
        method: "GET",
        url: `${targetUrl}/x`,
        injection: { type: "bearer" },
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as { code: string }).code).toBe(ErrorCode.CERT_VALUE_UNSUPPORTED);
    }
    expect(requestCount).toBe(before);

    const denied = engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .find((e) => e.detail?.error === "CERT_VALUE_UNSUPPORTED");
    expect(denied?.success).toBe(false);
  });

  it("refuses useSecret with a process action before any spawn", async () => {
    await expect(
      engine.useSecret("secret://tls-cert", {
        type: "process",
        command: "node",
        args: ["-e", ""],
        env_var: "TOKEN",
      }),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_VALUE_UNSUPPORTED });
  });

  it("refuses the direct value accessor", async () => {
    await expect(engine.getSecretValue("secret://tls-cert")).rejects.toMatchObject({
      code: ErrorCode.CERT_VALUE_UNSUPPORTED,
    });

    const denied = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find((e) => e.detail?.error === "CERT_VALUE_UNSUPPORTED");
    expect(denied?.success).toBe(false);
  });

  it("never leaks key material in the refusal message", async () => {
    const err = await engine.getSecretValue("secret://tls-cert").catch((e: unknown) => e);
    expect((err as Error).message).not.toContain("PRIVATE KEY");
    expect((err as Error).message).toBe(
      "Certificate secrets cannot be used as a raw value: secret://tls-cert",
    );
  });

  it("still allows metadata reads of the certificate secret", async () => {
    const info = await engine.getSecretInfo("secret://tls-cert");
    expect(info.type).toBe("certificate");
    expect(info.status).toBe("active");
  });
});

// ---------------------------------------------------------------------------
// Backward compatibility: generic certificate-typed secrets
// ---------------------------------------------------------------------------

/**
 * `certificate` has always been a legal type on the generic create paths
 * (`secret set -t certificate`, REST createSecretSchema, the MCP create-secret
 * tool), and those secrets carry a real payload. They have no `certificates`
 * row, so the refusal must not touch them — otherwise this tranche strands
 * every credential created that way before it existed.
 */
describe("generic certificate-typed secrets keep working", () => {
  // Single-line: a multi-line PEM is not a legal HTTP header value, and the
  // point here is the value path, not what a caller chose to store.
  const legacyValue = "legacy-certificate-credential";

  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "legacy-cert",
      type: SecretType.CERTIFICATE,
      value: new Uint8Array(Buffer.from(legacyValue, "utf8")),
    });
  });

  it("has no certificates row, which is what distinguishes it from an import", () => {
    const id = engine.listSecrets().find((x) => x.name === "legacy-cert")?.handle;
    expect(id).toBe("secret://legacy-cert");
    const db = new Database(dbPath, { readonly: true });
    const rows = db.prepare("SELECT COUNT(*) AS n FROM certificates").get() as { n: number };
    db.close();
    expect(rows.n).toBe(0);
  });

  it("returns its value from the direct accessor", async () => {
    const value = await engine.getSecretValue("secret://legacy-cert");
    expect(Buffer.from(value).toString("utf8")).toBe(legacyValue);
  });

  it("injects its value through a useSecret http action", async () => {
    const res = await engine.useSecret("secret://legacy-cert", {
      type: "http",
      method: "GET",
      url: `${targetUrl}/legacy`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(requestCount).toBe(1);
    expect(lastAuthHeader).toBe(`Bearer ${legacyValue}`);
  });

  it("keeps working alongside an imported certificate in the same vault", async () => {
    await engine.importCertificate("managed-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    });

    const legacy = await engine.getSecretValue("secret://legacy-cert");
    expect(Buffer.from(legacy).toString("utf8")).toBe(legacyValue);

    await expect(engine.getSecretValue("secret://managed-cert")).rejects.toMatchObject({
      code: ErrorCode.CERT_VALUE_UNSUPPORTED,
    });
  });
});

// ---------------------------------------------------------------------------
// Certificate read accessors + ACME account storage
// ---------------------------------------------------------------------------

describe("certificate accessors", () => {
  let secretId: string;

  beforeEach(async () => {
    await engine.initVault("password");
    ({ secretId } = await engine.importCertificate("acc-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      renewBeforeDays: 30,
    }));
  });

  it("getCertificateStatus reports metadata without decrypting", () => {
    const st = engine.getCertificateStatus(secretId);
    expect(st.secret_id).toBe(secretId);
    expect(st.subject).toContain("fixture.example.com");
    expect(st.issuer).toBe("CN=fixture.example.com");
    expect(st.not_before).toBeLessThanOrEqual(Date.now());
    expect(st.not_after).toBeGreaterThan(Date.now());
    expect(st.auto_renew).toBe(false);
    expect(st.renewal_status).toBe("ok");
  });

  it("reports auto_renew from the stored row", async () => {
    const { secretId: autoId } = await engine.importCertificate("auto-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      autoRenew: true,
    });
    expect(engine.getCertificateStatus(autoId).auto_renew).toBe(true);
  });

  it("renewal_status is expiring_soon inside renew_before_days", async () => {
    const { secretId: soonId } = await engine.importCertificate("soon-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      renewBeforeDays: 30,
    });
    setNotAfter(soonId, Date.now() + 10 * 86_400_000);
    expect(engine.getCertificateStatus(soonId).renewal_status).toBe("expiring_soon");
  });

  it("renewal_status is expired past not_after", async () => {
    const { secretId: expId } = await engine.importCertificate("exp-cert", fx("expired-key.pem"), {
      certificatePem: fx("expired-cert.pem"),
    });
    expect(engine.getCertificateStatus(expId).renewal_status).toBe("expired");
  });

  it("renewal_status is no_certificate for a CSR-only import", async () => {
    const { secretId: csrId } = await engine.importCertificate("csr-status", fx("rsa-key.pem"), {
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
      subject: "CN=pending.example.com",
    });
    const st = engine.getCertificateStatus(csrId);
    expect(st.renewal_status).toBe("no_certificate");
    expect(st.not_after).toBeNull();
    expect(st.not_before).toBeNull();
    expect(st.issuer).toBeNull();
  });

  it("getCertificateStatus writes no audit row on the trusted (caller-less) path", () => {
    engine.getCertificateStatus(secretId);
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_READ }).length).toBe(0);
  });

  it("getCertificatePrivateKey returns the PEM and writes one secret.read audit row", async () => {
    const pem = await engine.getCertificatePrivateKey(secretId);
    expect(pem).toContain("PRIVATE KEY");
    expect(pem).toBe(fx("rsa-key.pem"));

    const reads = engine
      .queryAudit({ limit: 50 })
      .filter((e) => e.event_type === "secret.read" && e.secret_id === secretId);
    expect(reads.length).toBe(1);
    expect(reads[0]?.success).toBe(true);
    expect(reads[0]?.detail).toMatchObject({ config: "certificate_private_key" });
    expect(JSON.stringify(reads[0]?.detail)).not.toContain("PRIVATE KEY");
  });

  it("getCertificatePrivateKey round-trips an EC key too", async () => {
    const { secretId: ecId } = await engine.importCertificate("ec-acc", fx("ec-key.pem"), {
      certificatePem: fx("ec-cert.pem"),
    });
    expect(await engine.getCertificatePrivateKey(ecId)).toBe(fx("ec-key.pem"));
  });

  it("getCertificatePem returns cert, chain and csr without auditing a read", () => {
    const pems = engine.getCertificatePem(secretId);
    expect(pems.certificatePem).toBe(fx("rsa-cert.pem"));
    expect(pems.chainPem).toBeNull();
    expect(pems.csrPem).toBeNull();
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_READ }).length).toBe(0);
  });

  it("getCertificatePem returns the stored chain and csr when present", async () => {
    const csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";
    const { secretId: fullId } = await engine.importCertificate("full-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      chainPem: fx("ec-cert.pem"),
      csrPem: csr,
    });
    const pems = engine.getCertificatePem(fullId);
    expect(pems.chainPem).toBe(fx("ec-cert.pem"));
    expect(pems.csrPem).toBe(csr);
  });

  it("getCertificateStatus on a non-certificate secret throws CERT_NOT_CONFIGURED", async () => {
    await engine.createSecret({
      name: "plain",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("plain-value", "utf8")),
    });
    const plainId = await engine.resolveSecretId("secret://plain");
    expect(() => engine.getCertificateStatus(plainId)).toThrow(
      expect.objectContaining({ code: ErrorCode.CERT_NOT_CONFIGURED }),
    );
  });

  it("every accessor refuses a secret without a certificates row", async () => {
    await engine.createSecret({
      name: "plain2",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("v", "utf8")),
    });
    const plainId = await engine.resolveSecretId("secret://plain2");
    const notConfigured = expect.objectContaining({ code: ErrorCode.CERT_NOT_CONFIGURED });

    expect(() => engine.getCertificatePem(plainId)).toThrow(notConfigured);
    await expect(engine.getCertificatePrivateKey(plainId)).rejects.toMatchObject({
      code: ErrorCode.CERT_NOT_CONFIGURED,
    });
    expect(() => engine.storeAcmeAccount(plainId, "{}")).toThrow(notConfigured);
    expect(() => engine.getAcmeAccount(plainId)).toThrow(notConfigured);
  });

  it("ACME account roundtrips through KEK encryption and is stored encrypted", () => {
    expect(engine.getAcmeAccount(secretId)).toBeNull();

    engine.storeAcmeAccount(secretId, JSON.stringify({ privateKeyPem: "k", accountUrl: "u" }));
    expect(JSON.parse(engine.getAcmeAccount(secretId) as string)).toEqual({
      privateKeyPem: "k",
      accountUrl: "u",
    });

    const row = storedCert(secretId) as StoredCertRow;
    expect(row.acme_account_encrypted).not.toBeNull();
    expect((row.acme_account_encrypted as Buffer).toString("utf8")).not.toContain("accountUrl");
  });

  it("storeAcmeAccount overwrites a previously stored account", () => {
    engine.storeAcmeAccount(secretId, "first-account");
    engine.storeAcmeAccount(secretId, "second-account");
    expect(engine.getAcmeAccount(secretId)).toBe("second-account");
  });

  it("storeAcmeAccount writes one policy.grant row and bumps the secret's updated_at", () => {
    backdateSecret(secretId);
    engine.storeAcmeAccount(secretId, JSON.stringify({ privateKeyPem: "k", accountUrl: "u" }));

    expect(storedSecretUpdatedAt(secretId)).toBeGreaterThan(0);

    const rows = engine
      .queryAudit({ eventType: AuditEventType.POLICY_GRANT })
      .filter((e) => e.secret_id === secretId);
    expect(rows.length).toBe(1);
    expect(rows[0]?.success).toBe(true);
    expect(rows[0]?.detail).toEqual({ config: "acme_account" });
    expect(JSON.stringify(rows[0]?.detail)).not.toContain("privateKeyPem");
  });

  it("storeAcmeAccount audits every write, not only the first", () => {
    engine.storeAcmeAccount(secretId, "first-account");
    engine.storeAcmeAccount(secretId, "second-account");
    const rows = engine
      .queryAudit({ eventType: AuditEventType.POLICY_GRANT })
      .filter((e) => e.secret_id === secretId);
    expect(rows.length).toBe(2);
  });

  it("storeAcmeAccount rolls the account write back when the audit write fails", () => {
    failAuditInsertAfter(0);

    expect(() => engine.storeAcmeAccount(secretId, "unaudited-account")).toThrow(
      "audit unavailable",
    );

    vi.restoreAllMocks();
    expect(storedCert(secretId)?.acme_account_encrypted).toBeNull();
    expect(engine.getAcmeAccount(secretId)).toBeNull();
  });

  it("getAcmeAccount writes one secret.read row for a stored account", () => {
    engine.storeAcmeAccount(secretId, JSON.stringify({ privateKeyPem: "k", accountUrl: "u" }));
    expect(engine.getAcmeAccount(secretId)).toContain("accountUrl");

    const reads = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((e) => e.secret_id === secretId);
    expect(reads.length).toBe(1);
    expect(reads[0]?.success).toBe(true);
    expect(reads[0]?.detail).toMatchObject({ config: "acme_account" });
    expect(JSON.stringify(reads[0]?.detail)).not.toContain("privateKeyPem");
  });

  it("getAcmeAccount writes no read row when no account is stored", () => {
    expect(engine.getAcmeAccount(secretId)).toBeNull();
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_READ }).length).toBe(0);
  });

  it("an ACME account blob is bound to its own secret by AAD", async () => {
    engine.storeAcmeAccount(secretId, JSON.stringify({ accountUrl: "u" }));
    const { secretId: otherId } = await engine.importCertificate("other-acme", fx("ec-key.pem"), {
      certificatePem: fx("ec-cert.pem"),
    });
    transplantAcmeBlob(secretId, otherId);
    expect(() => engine.getAcmeAccount(otherId)).toThrow(
      expect.objectContaining({ code: ErrorCode.ENCRYPTION_ERROR }),
    );
  });

  it("getExpiringCertificates finds the expired fixture within 30 days", async () => {
    await engine.importCertificate("exp2", fx("expired-key.pem"), {
      certificatePem: fx("expired-cert.pem"),
    });
    const rows = engine.getExpiringCertificates(30);
    expect(rows.some((r) => r.subject.includes("expired.example.com"))).toBe(true);
    expect(rows.some((r) => r.subject.includes("fixture.example.com"))).toBe(false);
  });

  it("getExpiringCertificates widens with the window", () => {
    expect(engine.getExpiringCertificates(30).length).toBe(0);
    const wide = engine.getExpiringCertificates(4000);
    expect(wide.some((r) => r.subject.includes("fixture.example.com"))).toBe(true);
  });

  it("getExpiringCertificates skips a CSR-only certificate", async () => {
    await engine.importCertificate("csr-expiring", fx("rsa-key.pem"), {
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
      subject: "CN=csr-expiring.example.com",
    });
    const rows = engine.getExpiringCertificates(4000);
    expect(rows.some((r) => r.subject.includes("csr-expiring.example.com"))).toBe(false);
  });

  it("every accessor refuses while the vault is locked", async () => {
    await engine.lock();
    const locked = expect.objectContaining({ code: ErrorCode.VAULT_LOCKED });

    expect(() => engine.getCertificateStatus(secretId)).toThrow(locked);
    expect(() => engine.getCertificatePem(secretId)).toThrow(locked);
    await expect(engine.getCertificatePrivateKey(secretId)).rejects.toMatchObject({
      code: ErrorCode.VAULT_LOCKED,
    });
    expect(() => engine.getExpiringCertificates(30)).toThrow(locked);
    expect(() => engine.storeAcmeAccount(secretId, "{}")).toThrow(locked);
    expect(() => engine.getAcmeAccount(secretId)).toThrow(locked);
  });
});

// ---------------------------------------------------------------------------
// Certificate secrets on the generic value-write path
// ---------------------------------------------------------------------------

/**
 * The read side already refuses (`getSecretValue`); both write sides must too.
 * Without it `secret set` hands a CSR-pending certificate an unrelated payload
 * and flips it ACTIVE — a certificate that reports itself issued while the
 * certificates row still has no leaf — and `secret rotate` plants an
 * unreachable payload under a `secret.rotate` row claiming the credential
 * changed. A certificate is re-credentialed through `updateCertificate` only.
 */
describe("certificate secrets are refused on the generic value-write path", () => {
  const CSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";

  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("refuses setSecretValue on a CSR-pending certificate and leaves it PENDING", async () => {
    const { secretId } = await engine.importCertificate("csr-set", fx("rsa-key.pem"), {
      csrPem: CSR,
      subject: "CN=pending.example.com",
    });

    await expect(
      engine.setSecretValue("secret://csr-set", new Uint8Array(Buffer.from("attacker", "utf8"))),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_VALUE_UNSUPPORTED });

    expect(engine.listSecrets().find((x) => x.name === "csr-set")?.status).toBe("pending");

    // The denial row is addressed by secret id, not only by its detail.
    const denials = engine
      .queryAudit({ secretId, eventType: AuditEventType.SECRET_CREATE })
      .filter((e) => !e.success);
    expect(denials.length).toBe(1);
    expect(denials[0]?.detail).toMatchObject({
      handle: "secret://csr-set",
      action: "set_value",
      error: ErrorCode.CERT_VALUE_UNSUPPORTED,
    });
  });

  it("refuses setSecretValue on an active imported certificate too", async () => {
    const { secretId } = await engine.importCertificate("active-set", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    });

    await expect(
      engine.setSecretValue("secret://active-set", new Uint8Array(Buffer.from("x", "utf8"))),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_VALUE_UNSUPPORTED });

    expect(
      engine
        .queryAudit({ secretId, eventType: AuditEventType.SECRET_CREATE })
        .filter((e) => !e.success).length,
    ).toBe(1);
  });

  it("refuses rotateSecret on an imported certificate", async () => {
    const { secretId } = await engine.importCertificate("rotate-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    });

    await expect(
      engine.rotateSecret("secret://rotate-cert", new Uint8Array(Buffer.from("planted", "utf8"))),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_VALUE_UNSUPPORTED });

    // No misleading success row, and the denial carries the secret id.
    const rotates = engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_ROTATE });
    expect(rotates.length).toBe(1);
    expect(rotates[0]?.success).toBe(false);
    expect(rotates[0]?.detail).toMatchObject({
      handle: "secret://rotate-cert",
      error: ErrorCode.CERT_VALUE_UNSUPPORTED,
    });

    // The key is untouched and still the legitimate read path's answer.
    expect(await engine.getCertificatePrivateKey(secretId)).toBe(fx("rsa-key.pem"));
  });

  it("still rotates a certificate-typed secret with no certificates row", async () => {
    await engine.createSecret({
      name: "legacy-rotate",
      type: SecretType.CERTIFICATE,
      value: new Uint8Array(Buffer.from("legacy-v1", "utf8")),
    });

    await engine.rotateSecret(
      "secret://legacy-rotate",
      new Uint8Array(Buffer.from("legacy-v2", "utf8")),
    );

    const value = await engine.getSecretValue("secret://legacy-rotate");
    expect(Buffer.from(value).toString("utf8")).toBe("legacy-v2");
    expect(
      engine.queryAudit({ eventType: AuditEventType.SECRET_ROTATE }).filter((e) => e.success)
        .length,
    ).toBe(1);
  });

  it("never leaks key material in the refusal message", async () => {
    await engine.importCertificate("msg-set", fx("rsa-key.pem"), { csrPem: CSR, subject: "CN=m" });
    const err = await engine
      .setSecretValue("secret://msg-set", new Uint8Array(Buffer.from("x", "utf8")))
      .catch((e: unknown) => e);
    expect((err as Error).message).toBe(
      "Certificate secrets cannot be used as a raw value: secret://msg-set",
    );
  });

  it("still accepts a value for a certificate-typed secret with no certificates row", async () => {
    await engine.createSecret({ name: "legacy-pending", type: SecretType.CERTIFICATE });

    await engine.setSecretValue(
      "secret://legacy-pending",
      new Uint8Array(Buffer.from("legacy-value", "utf8")),
    );

    expect(engine.listSecrets().find((x) => x.name === "legacy-pending")?.status).toBe("active");
    const value = await engine.getSecretValue("secret://legacy-pending");
    expect(Buffer.from(value).toString("utf8")).toBe("legacy-value");
  });
});

// ---------------------------------------------------------------------------
// updateCertificate
// ---------------------------------------------------------------------------

describe("updateCertificate", () => {
  const CSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";

  beforeEach(async () => {
    await engine.initVault("password");
  });

  /**
   * A CSR-pending import — the state an issuance completion lands on. The
   * placeholder subject deliberately differs from every fixture certificate's
   * subject, so "the parsed certificate overwrites the CSR's subject" is
   * observable rather than coincidentally equal.
   */
  async function pending(name: string, keyFixture = "rsa-key.pem"): Promise<string> {
    const { secretId } = await engine.importCertificate(name, fx(keyFixture), {
      csrPem: CSR,
      subject: "CN=pending-other.example.com",
    });
    return secretId;
  }

  it("attaches a certificate to a CSR-pending secret and activates it", async () => {
    const secretId = await pending("csr-then-cert");
    expect(storedCert(secretId)?.subject).toBe("CN=pending-other.example.com");

    await engine.updateCertificate(secretId, fx("rsa-cert.pem"));

    const info = engine.listSecrets().find((x) => x.name === "csr-then-cert");
    expect(info?.status).toBe("active");
    expect(engine.getCertificateStatus(secretId).renewal_status).toBe("ok");

    const row = storedCert(secretId) as StoredCertRow;
    expect(row.certificate_pem).toBe(fx("rsa-cert.pem"));
    // Rewritten from the parsed leaf, not the CSR placeholder above.
    expect(row.subject).toBe("CN=fixture.example.com");
    expect(row.issuer).toBe("CN=fixture.example.com");
    expect(row.serial_number).toBeTruthy();
    expect(row.not_before).toBeLessThanOrEqual(Date.now());
    expect(row.not_after).toBeGreaterThan(Date.now());
    expect(info?.expiresAt).toBe(row.not_after);
    // The CSR stays: renewal reuses it.
    expect(row.csr_pem).toBe(CSR);
  });

  it("bumps the secret's updated_at", async () => {
    const secretId = await pending("touch-cert");
    backdateSecret(secretId);
    await engine.updateCertificate(secretId, fx("rsa-cert.pem"));
    expect(storedSecretUpdatedAt(secretId)).toBeGreaterThan(0);
  });

  it("refuses a certificate that does not match the stored key and writes nothing", async () => {
    const secretId = await pending("renew-mismatch", "other-key.pem");

    await expect(engine.updateCertificate(secretId, fx("rsa-cert.pem"))).rejects.toMatchObject({
      code: ErrorCode.CERT_PRIVATE_KEY_MISMATCH,
    });

    expect(storedCert(secretId)?.certificate_pem).toBeNull();
    expect(engine.listSecrets().find((x) => x.name === "renew-mismatch")?.status).toBe("pending");
    // The verification really read the key, so the read stays on the record.
    expect(engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_READ }).length).toBe(1);

    const denials = engine
      .queryAudit({ secretId, eventType: AuditEventType.CERT_ISSUE })
      .filter((e) => !e.success);
    expect(denials.length).toBe(1);
    expect(denials[0]?.detail).toMatchObject({
      action: "update_certificate",
      error: ErrorCode.CERT_PRIVATE_KEY_MISMATCH,
    });
  });

  it("audits every pre-write refusal", async () => {
    const csrId = await pending("audited-refusals");
    await engine.revokeSecret("secret://audited-refusals");
    await expect(engine.updateCertificate(csrId, fx("rsa-cert.pem"))).rejects.toMatchObject({
      code: ErrorCode.SECRET_REVOKED,
    });
    expect(
      engine
        .queryAudit({ secretId: csrId, eventType: AuditEventType.CERT_ISSUE })
        .filter((e) => !e.success)
        .map((e) => e.detail?.error),
    ).toEqual([ErrorCode.SECRET_REVOKED]);

    const parseId = await pending("audited-parse");
    await expect(
      engine.updateCertificate(parseId, "-----BEGIN CERTIFICATE-----\nx\n", undefined, {
        renewed: true,
      }),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_INVALID });
    const parseDenials = engine
      .queryAudit({ secretId: parseId, eventType: AuditEventType.CERT_RENEW })
      .filter((e) => !e.success);
    expect(parseDenials.length).toBe(1);
    expect(parseDenials[0]?.detail).toMatchObject({
      action: "update_certificate",
      error: ErrorCode.CERT_INVALID,
    });

    await engine.createSecret({
      name: "audited-noconfig",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("v", "utf8")),
    });
    const plainId = await engine.resolveSecretId("secret://audited-noconfig");
    await expect(engine.updateCertificate(plainId, fx("rsa-cert.pem"))).rejects.toMatchObject({
      code: ErrorCode.CERT_NOT_CONFIGURED,
    });
    const noConfig = engine
      .queryAudit({ secretId: plainId, eventType: AuditEventType.CERT_ISSUE })
      .filter((e) => !e.success);
    expect(noConfig.length).toBe(1);
    expect(noConfig[0]?.detail).toMatchObject({ error: ErrorCode.CERT_NOT_CONFIGURED });
  });

  it("replaces an existing leaf with a new one for the same key", async () => {
    const { secretId } = await engine.importCertificate("real-renewal", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    });
    const before = storedCert(secretId) as StoredCertRow;

    await engine.updateCertificate(secretId, fx("rsa-cert-renewed.pem"), undefined, {
      renewed: true,
    });

    const after = storedCert(secretId) as StoredCertRow;
    expect(after.certificate_pem).toBe(fx("rsa-cert-renewed.pem"));
    expect(after.serial_number).not.toBe(before.serial_number);
    expect(after.not_after).toBeGreaterThan(before.not_after as number);
    expect(after.subject).toBe("CN=fixture.example.com");

    const info = engine.listSecrets().find((x) => x.name === "real-renewal");
    expect(info?.status).toBe("active");
    expect(info?.expiresAt).toBe(after.not_after);
    // The stored key is unchanged — a renewal re-certifies it, never replaces it.
    expect(await engine.getCertificatePrivateKey(secretId)).toBe(fx("rsa-key.pem"));

    const renews = engine.queryAudit({ secretId, eventType: AuditEventType.CERT_RENEW });
    expect(renews.length).toBe(1);
    expect(renews[0]?.detail?.not_after).toBe(after.not_after);
  });

  it("refuses an unparseable certificate before the private key is read", async () => {
    const secretId = await pending("renew-garbage");

    await expect(
      engine.updateCertificate(
        secretId,
        "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.CERT_INVALID });

    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_READ }).length).toBe(0);
  });

  it("logs cert.renew when opts.renewed", async () => {
    const secretId = await pending("renew-me");
    await engine.updateCertificate(secretId, fx("rsa-cert.pem"), undefined, { renewed: true });

    const renews = engine.queryAudit({ secretId, eventType: AuditEventType.CERT_RENEW });
    expect(renews.length).toBe(1);
    expect(renews[0]?.success).toBe(true);
    expect(renews[0]?.detail).toMatchObject({ subject: "CN=fixture.example.com" });
    expect(renews[0]?.detail?.not_after).toBeGreaterThan(Date.now());
  });

  it("logs cert.issue when the completion is not a renewal", async () => {
    const secretId = await pending("complete-me");
    // The CSR-only import already wrote one cert.issue (order placed, no leaf).
    expect(engine.queryAudit({ secretId, eventType: AuditEventType.CERT_ISSUE }).length).toBe(1);

    await engine.updateCertificate(secretId, fx("rsa-cert.pem"));

    const issues = engine.queryAudit({ secretId, eventType: AuditEventType.CERT_ISSUE });
    expect(issues.length).toBe(2);
    expect(engine.queryAudit({ secretId, eventType: AuditEventType.CERT_RENEW }).length).toBe(0);

    // The `action` discriminator is what separates the two rows: the CSR
    // import's (no leaf, no not_after) from this completion's.
    const byAction = issues.map((e) => e.detail?.action).sort();
    expect(byAction).toEqual(["import_certificate", "update_certificate"]);
    const completion = issues.find((e) => e.detail?.action === "update_certificate");
    expect(completion?.detail?.not_after).toBeGreaterThan(Date.now());
    const imported = issues.find((e) => e.detail?.action === "import_certificate");
    expect(imported?.detail?.not_after).toBeNull();
  });

  it("keeps key and certificate material out of the audit detail", async () => {
    const secretId = await pending("renew-audit");
    await engine.updateCertificate(secretId, fx("rsa-cert.pem"), fx("ec-cert.pem"), {
      renewed: true,
    });

    const renew = engine.queryAudit({ secretId, eventType: AuditEventType.CERT_RENEW })[0];
    const detail = JSON.stringify(renew?.detail);
    expect(detail).not.toContain("PRIVATE KEY");
    expect(detail).not.toContain("BEGIN CERTIFICATE");
  });

  it("keeps the stored chain when chainPem is omitted and replaces it when given", async () => {
    const { secretId } = await engine.importCertificate("chain-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      chainPem: fx("ec-cert.pem"),
    });

    await engine.updateCertificate(secretId, fx("rsa-cert.pem"));
    expect(storedCert(secretId)?.chain_pem).toBe(fx("ec-cert.pem"));

    await engine.updateCertificate(secretId, fx("rsa-cert.pem"), fx("expired-cert.pem"));
    expect(storedCert(secretId)?.chain_pem).toBe(fx("expired-cert.pem"));
  });

  it("an already-expired replacement stays inside the ordinary expiry machinery", async () => {
    const secretId = await pending("stale-renewal", "expired-key.pem");
    await engine.updateCertificate(secretId, fx("expired-cert.pem"), undefined, { renewed: true });

    expect(engine.listSecrets().find((x) => x.name === "stale-renewal")?.status).toBe("expired");
    expect(engine.getCertificateStatus(secretId).renewal_status).toBe("expired");
  });

  it("refuses to revive a revoked secret", async () => {
    const secretId = await pending("revoked-renewal");
    await engine.revokeSecret("secret://revoked-renewal");

    await expect(engine.updateCertificate(secretId, fx("rsa-cert.pem"))).rejects.toMatchObject({
      code: ErrorCode.SECRET_REVOKED,
    });

    expect(storedCert(secretId)?.certificate_pem).toBeNull();
    expect(engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_READ }).length).toBe(0);
  });

  it("refuses a secret without a certificates row", async () => {
    await engine.createSecret({
      name: "plain-update",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("v", "utf8")),
    });
    const plainId = await engine.resolveSecretId("secret://plain-update");

    await expect(engine.updateCertificate(plainId, fx("rsa-cert.pem"))).rejects.toMatchObject({
      code: ErrorCode.CERT_NOT_CONFIGURED,
    });
  });

  it("refuses while the vault is locked", async () => {
    const secretId = await pending("locked-update");
    await engine.lock();

    await expect(engine.updateCertificate(secretId, fx("rsa-cert.pem"))).rejects.toMatchObject({
      code: ErrorCode.VAULT_LOCKED,
    });
  });

  it("refuses an ungranted caller before the private key is read", async () => {
    const secretId = await pending("gated-renewal");
    registerAgents("renewer");
    engine.grantPolicy(
      {
        secretId,
        principalType: PrincipalType.AGENT,
        principalId: "renewer",
        permissions: ["rotate"] as Permission[],
      },
      "test-setup",
    );

    await expect(
      engine.updateCertificate(secretId, fx("rsa-cert.pem"), undefined, undefined, {
        principal_type: PrincipalType.AGENT,
        principal_id: "other-agent",
        interface: "cli",
      }),
    ).rejects.toMatchObject({ code: ErrorCode.ACCESS_DENIED });

    expect(engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_READ }).length).toBe(0);
    expect(storedCert(secretId)?.certificate_pem).toBeNull();

    const denials = engine
      .queryAudit({ secretId, eventType: AuditEventType.CERT_ISSUE })
      .filter((e) => !e.success);
    expect(denials.length).toBe(1);
    expect(denials[0]?.principal_id).toBe("other-agent");
    expect(denials[0]?.detail).toMatchObject({ action: "update_certificate" });
  });

  it("lets a rotate-granted caller complete the renewal and attributes the row", async () => {
    const secretId = await pending("granted-renewal");
    registerAgents("renewer");
    engine.grantPolicy(
      {
        secretId,
        principalType: PrincipalType.AGENT,
        principalId: "renewer",
        permissions: ["rotate"] as Permission[],
      },
      "test-setup",
    );

    await engine.updateCertificate(
      secretId,
      fx("rsa-cert.pem"),
      undefined,
      { renewed: true },
      { principal_type: PrincipalType.AGENT, principal_id: "renewer", interface: "cli" },
    );

    expect(engine.listSecrets().find((x) => x.name === "granted-renewal")?.status).toBe("active");

    const renews = engine.queryAudit({ secretId, eventType: AuditEventType.CERT_RENEW });
    expect(renews.length).toBe(1);
    expect(renews[0]?.principal_id).toBe("renewer");
    expect(renews[0]?.detail).toMatchObject({ interface: "cli" });
  });

  it("rolls the certificate and status write back when the audit write fails", async () => {
    const secretId = await pending("atomic-renewal");
    // Pass 1 = the secret.read row the internal private-key read writes.
    failAuditInsertAfter(1);

    await expect(engine.updateCertificate(secretId, fx("rsa-cert.pem"))).rejects.toThrow(
      "audit unavailable",
    );

    vi.restoreAllMocks();
    expect(storedCert(secretId)?.certificate_pem).toBeNull();
    expect(engine.listSecrets().find((x) => x.name === "atomic-renewal")?.status).toBe("pending");
    expect(engine.queryAudit({ secretId, eventType: AuditEventType.CERT_ISSUE }).length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Caller policy enforcement on the certificate accessors
// ---------------------------------------------------------------------------

describe("certificate accessors — caller policy enforcement", () => {
  let secretId: string;

  beforeEach(async () => {
    await engine.initVault("password");
    ({ secretId } = await engine.importCertificate("pol-cert", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
    }));
    // Presence-gates the secret: any caller now needs a matching grant.
    registerAgents("reader");
    engine.grantPolicy(
      {
        secretId,
        principalType: PrincipalType.AGENT,
        principalId: "reader",
        permissions: ["read"] as Permission[],
      },
      "test-setup",
    );
  });

  it("getCertificateStatus refuses an ungranted caller and allows a read-granted one", () => {
    let thrown: unknown;
    try {
      engine.getCertificateStatus(secretId, {
        principal_type: PrincipalType.AGENT,
        principal_id: "other-agent",
        interface: "cli",
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toMatchObject({ code: ErrorCode.ACCESS_DENIED });

    const denials = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((e) => !e.success);
    expect(denials.length).toBe(1);
    expect(denials[0]?.principal_id).toBe("other-agent");
    expect(denials[0]?.detail).toMatchObject({ config: "certificate_status" });

    const st = engine.getCertificateStatus(secretId, {
      principal_type: PrincipalType.AGENT,
      principal_id: "reader",
      interface: "cli",
    });
    expect(st.subject).toBe("CN=fixture.example.com");
    expect(engine.getCertificateStatus(secretId).subject).toBe("CN=fixture.example.com");
  });

  it("getCertificatePrivateKey refuses an ungranted caller before decrypting", async () => {
    await expect(
      engine.getCertificatePrivateKey(secretId, {
        principal_type: PrincipalType.AGENT,
        principal_id: "other-agent",
        interface: "cli",
      }),
    ).rejects.toMatchObject({ code: ErrorCode.ACCESS_DENIED });

    const denials = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((e) => !e.success);
    expect(denials.length).toBe(1);
    expect(denials[0]?.detail).toMatchObject({ config: "certificate_private_key" });
    expect(JSON.stringify(denials[0]?.detail)).not.toContain("PRIVATE KEY");
  });

  it("getCertificatePrivateKey attributes the granted read to its caller", async () => {
    const pem = await engine.getCertificatePrivateKey(secretId, {
      principal_type: PrincipalType.AGENT,
      principal_id: "reader",
      interface: "cli",
    });
    expect(pem).toBe(fx("rsa-key.pem"));

    const reads = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((e) => e.success);
    expect(reads.length).toBe(1);
    expect(reads[0]?.principal_id).toBe("reader");
    expect(reads[0]?.detail).toMatchObject({
      config: "certificate_private_key",
      interface: "cli",
    });
  });

  it("getAcmeAccount refuses an ungranted caller before decrypting", () => {
    engine.storeAcmeAccount(secretId, JSON.stringify({ privateKeyPem: "k" }));

    expect(() =>
      engine.getAcmeAccount(secretId, {
        principal_type: PrincipalType.AGENT,
        principal_id: "other-agent",
        interface: "cli",
      }),
    ).toThrow(expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }));

    const denials = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((e) => !e.success);
    expect(denials.length).toBe(1);
    expect(denials[0]?.detail).toMatchObject({ config: "acme_account" });
    expect(JSON.stringify(denials[0]?.detail)).not.toContain("privateKeyPem");
  });

  it("getAcmeAccount attributes the granted read to its caller", () => {
    engine.storeAcmeAccount(secretId, "account-blob");

    expect(
      engine.getAcmeAccount(secretId, {
        principal_type: PrincipalType.AGENT,
        principal_id: "reader",
        interface: "cli",
      }),
    ).toBe("account-blob");

    const reads = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((e) => e.success);
    expect(reads.length).toBe(1);
    expect(reads[0]?.principal_id).toBe("reader");
    expect(reads[0]?.detail).toMatchObject({ config: "acme_account", interface: "cli" });
  });

  it("getCertificatePem refuses an ungranted caller and stays unaudited when granted", () => {
    expect(() =>
      engine.getCertificatePem(secretId, {
        principal_type: PrincipalType.AGENT,
        principal_id: "other-agent",
        interface: "cli",
      }),
    ).toThrow(expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }));

    const denials = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((e) => !e.success);
    expect(denials.length).toBe(1);
    expect(denials[0]?.detail).toMatchObject({ config: "certificate_pem" });

    const pems = engine.getCertificatePem(secretId, {
      principal_type: PrincipalType.AGENT,
      principal_id: "reader",
      interface: "cli",
    });
    expect(pems.certificatePem).toBe(fx("rsa-cert.pem"));
    // Public material: the granted read deliberately writes no row.
    expect(
      engine.queryAudit({ eventType: AuditEventType.SECRET_READ }).filter((e) => e.success).length,
    ).toBe(0);
  });

  it("no caller stays the trusted path", async () => {
    expect(engine.getCertificateStatus(secretId).renewal_status).toBe("ok");
    await expect(engine.getCertificatePrivateKey(secretId)).resolves.toContain("PRIVATE KEY");
    expect(engine.getCertificatePem(secretId).certificatePem).toBe(fx("rsa-cert.pem"));
    expect(engine.getAcmeAccount(secretId)).toBeNull();
  });
});
