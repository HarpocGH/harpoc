import { X509Certificate } from "node:crypto";
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import type {
  CallerContext,
  ExpiringCertificateInfo,
  ExpiringOAuthTokenInfo,
  OAuthProviderConfig,
  Permission,
  PrincipalType,
} from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";

/**
 * D5 — the expiring-status projections hand out metadata only: no encrypted
 * column ever leaves core, and the result is policy-filtered exactly like
 * `listSecrets` (W2), silently.
 */

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

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__", "certs");
const fx = (name: string): string => readFileSync(join(FIXTURES, name), "utf8");

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 86_400_000;

let tempDir: string;
let dbPath: string;
let engine: VaultEngine;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-expiring-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  engine = new VaultEngine({ dbPath, sessionPath: join(tempDir, "session.json") });
  await engine.initVault("password");
});

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

function oauthConfig(overrides?: Partial<OAuthProviderConfig>): OAuthProviderConfig {
  return {
    provider: "github",
    grant_type: "authorization_code",
    token_endpoint: "https://github.com/login/oauth/access_token",
    auth_endpoint: "https://github.com/login/oauth/authorize",
    client_id: "my-client-id",
    client_secret: "my-client-secret",
    scopes: ["repo"],
    ...overrides,
  };
}

function agent(id: string, project?: string): CallerContext {
  const caller: CallerContext = { principal_type: "agent", principal_id: id };
  if (project) caller.project = project;
  return caller;
}

function grant(
  secretId: string,
  principalType: PrincipalType,
  principalId: string,
  permissions: Permission[],
): void {
  engine.grantPolicy({ secretId, principalType, principalId, permissions }, "test-admin");
}

/**
 * A renewal window covering the fixture's remaining validity: whole days to its
 * `validTo` plus a one-day margin, floored at 1 (the checked-in pair is already
 * expired) and clamped at 365 — the engine's `renew_before_days` ceiling, which
 * refuses anything wider. Derived rather than hardcoded so a regenerated
 * fixture stays covered, up to that ceiling.
 */
function windowDaysCovering(certPem: string): number {
  const validToMs = new Date(new X509Certificate(certPem).validTo).getTime();
  return Math.min(365, Math.max(1, Math.ceil((validToMs - Date.now()) / DAY_MS) + 1));
}

/**
 * Fixture surgery: every checked-in certificate is either long expired or valid
 * for a decade, so none of them lands strictly inside the scheduler's wide net
 * with its own renewal window still ahead. Moving `not_after` out-of-band is the
 * only way to exercise the per-row window filter.
 *
 * The row count is asserted: an UPDATE matching nothing is silent, and the
 * caller would go on asserting about the fixture's own imported validity window
 * while believing it had moved it.
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

// ---------------------------------------------------------------------------
// getExpiringOAuthTokenStatuses
// ---------------------------------------------------------------------------

describe("getExpiringOAuthTokenStatuses", () => {
  it("projects expiring OAuth tokens to metadata only", async () => {
    const { secretId } = await engine.createOAuthSecret("gh", oauthConfig());
    await engine.completeOAuthFlow(secretId, "at-1", "rt-1", Date.now() + 30 * MINUTE_MS);

    const items = engine.getExpiringOAuthTokenStatuses(HOUR_MS);

    expect(items).toHaveLength(1);
    expect(Object.keys(items[0] as object).sort()).toEqual([
      "access_token_expires_at",
      "handle",
      "has_refresh_token",
      "name",
      "project",
      "provider",
      "refresh_status",
    ]);
    expect(items[0]).toMatchObject({
      handle: "secret://gh",
      name: "gh",
      project: null,
      provider: "github",
      has_refresh_token: true,
      // Inside the caller's 1 h window but outside the 5 min refresh buffer.
      refresh_status: "ok",
    });
  });

  it("carries neither the encrypted columns nor the token values", async () => {
    const { secretId } = await engine.createOAuthSecret("gh", oauthConfig());
    await engine.completeOAuthFlow(secretId, "at-1", "rt-1", Date.now() + 30 * MINUTE_MS);

    const serialized = JSON.stringify(engine.getExpiringOAuthTokenStatuses(HOUR_MS));
    expect(serialized).not.toContain("encrypted");
    expect(serialized).not.toContain("at-1");
    expect(serialized).not.toContain("rt-1");
    expect(serialized).not.toContain("my-client-id");
    expect(serialized).not.toContain("my-client-secret");
    expect(serialized).not.toContain("secret_id");
  });

  it("carries the project on a project-scoped secret", async () => {
    const { secretId } = await engine.createOAuthSecret("gh", oauthConfig(), "api");
    await engine.completeOAuthFlow(secretId, "at-1", "rt-1", Date.now() + 30 * MINUTE_MS);

    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS)[0]).toMatchObject({
      handle: "secret://api/gh",
      name: "gh",
      project: "api",
    });
  });

  it("excludes a token expiring beyond the window", async () => {
    const { secretId } = await engine.createOAuthSecret("later", oauthConfig());
    await engine.completeOAuthFlow(secretId, "at-1", "rt-1", Date.now() + 4 * HOUR_MS);

    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS)).toEqual([]);
    expect(engine.getExpiringOAuthTokenStatuses(5 * HOUR_MS)).toHaveLength(1);
  });

  it("excludes a token with no recorded expiry", async () => {
    const { secretId } = await engine.createOAuthSecret("no-expiry", oauthConfig());
    await engine.completeOAuthFlow(secretId, "at-1", "rt-1");

    expect(engine.getExpiringOAuthTokenStatuses(365 * DAY_MS)).toEqual([]);
  });

  it("derives refresh_status the way getOAuthTokenStatus does", async () => {
    const cases: { name: string; refresh?: string; expiresAt: number; expected: string }[] = [
      { name: "no-refresh", expiresAt: Date.now() + 30 * MINUTE_MS, expected: "no_refresh_token" },
      { name: "gone", refresh: "rt", expiresAt: Date.now() - MINUTE_MS, expected: "expired" },
      {
        name: "soon",
        refresh: "rt",
        expiresAt: Date.now() + 2 * MINUTE_MS,
        expected: "expiring_soon",
      },
      { name: "fine", refresh: "rt", expiresAt: Date.now() + 60 * MINUTE_MS, expected: "ok" },
    ];

    for (const c of cases) {
      const { secretId } = await engine.createOAuthSecret(c.name, oauthConfig());
      await engine.completeOAuthFlow(secretId, "at", c.refresh, c.expiresAt);

      const projected = engine
        .getExpiringOAuthTokenStatuses(2 * HOUR_MS)
        .find((i) => i.name === c.name);
      expect(projected?.refresh_status).toBe(c.expected);
      expect(projected?.refresh_status).toBe(engine.getOAuthTokenStatus(secretId).refresh_status);
    }
  });

  it("keeps the store's soonest-first order", async () => {
    const later = await engine.createOAuthSecret("later", oauthConfig());
    await engine.completeOAuthFlow(later.secretId, "at", "rt", Date.now() + 50 * MINUTE_MS);
    const sooner = await engine.createOAuthSecret("sooner", oauthConfig());
    await engine.completeOAuthFlow(sooner.secretId, "at", "rt", Date.now() + 10 * MINUTE_MS);

    expect(engine.getExpiringOAuthTokenStatuses(2 * HOUR_MS).map((i) => i.name)).toEqual([
      "sooner",
      "later",
    ]);
  });

  it("silently drops policy-gated secrets for a token-derived caller", async () => {
    const { secretId } = await engine.createOAuthSecret("gated", oauthConfig());
    await engine.completeOAuthFlow(secretId, "at-1", "rt-1", Date.now() + 30 * MINUTE_MS);
    grant(secretId, "agent", "alice", ["use"]);

    const before = engine.queryAudit({}).length;
    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS, agent("mallory"))).toEqual([]);
    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS, agent("alice"))).toEqual([]);
    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS)).toHaveLength(1);
    expect(engine.queryAudit({}).length).toBe(before);
  });

  it("a `list` grant restores the row for its principal only", async () => {
    const { secretId } = await engine.createOAuthSecret("gated", oauthConfig());
    await engine.completeOAuthFlow(secretId, "at-1", "rt-1", Date.now() + 30 * MINUTE_MS);
    grant(secretId, "agent", "alice", ["list"]);

    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS, agent("alice"))).toHaveLength(1);
    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS, agent("mallory"))).toEqual([]);
  });

  it("derives the project principal like every other enumeration surface", async () => {
    const { secretId } = await engine.createOAuthSecret("gated", oauthConfig(), "api");
    await engine.completeOAuthFlow(secretId, "at-1", "rt-1", Date.now() + 30 * MINUTE_MS);
    grant(secretId, "project", "api", ["list"]);

    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS, agent("any", "api"))).toHaveLength(1);
    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS, agent("any"))).toEqual([]);
  });

  it("an ungated secret stays visible to a token-derived caller", async () => {
    const { secretId } = await engine.createOAuthSecret("open", oauthConfig());
    await engine.completeOAuthFlow(secretId, "at-1", "rt-1", Date.now() + 30 * MINUTE_MS);

    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS, agent("anyone"))).toHaveLength(1);
  });

  it("refuses while the vault is locked", async () => {
    await engine.lock();
    expect(() => engine.getExpiringOAuthTokenStatuses(HOUR_MS)).toThrow(
      expect.objectContaining({ code: ErrorCode.VAULT_LOCKED }),
    );
  });
});

// ---------------------------------------------------------------------------
// getExpiringCertificateStatuses
// ---------------------------------------------------------------------------

describe("getExpiringCertificateStatuses", () => {
  it("projects certificates inside their own window to metadata only", async () => {
    await engine.importCertificate("expired-leaf", fx("expired-key.pem"), {
      certificatePem: fx("expired-cert.pem"),
      renewBeforeDays: windowDaysCovering(fx("expired-cert.pem")),
    });

    const items = engine.getExpiringCertificateStatuses();

    expect(items).toHaveLength(1);
    expect(Object.keys(items[0] as object).sort()).toEqual([
      "auto_renew",
      "handle",
      "name",
      "not_after",
      "project",
      "renew_before_days",
      "renewal_status",
      "subject",
    ]);
    expect(items[0]).toMatchObject({
      handle: "secret://expired-leaf",
      name: "expired-leaf",
      project: null,
      auto_renew: false,
      renew_before_days: 1,
      renewal_status: "expired",
    });
    expect((items[0] as ExpiringCertificateInfo).subject).toContain("expired.example.com");
  });

  it("carries neither the encrypted columns nor the key material", async () => {
    await engine.importCertificate("expired-leaf", fx("expired-key.pem"), {
      certificatePem: fx("expired-cert.pem"),
      autoRenew: true,
      renewBeforeDays: 1,
    });

    const serialized = JSON.stringify(engine.getExpiringCertificateStatuses());
    expect(serialized).not.toContain("encrypted");
    expect(serialized).not.toContain("PRIVATE KEY");
    expect(serialized).not.toContain("BEGIN CERTIFICATE");
    expect(serialized).not.toContain("secret_id");
    expect(serialized).not.toContain("acme");
  });

  it("applies each row's own renew_before_days, not one shared window", async () => {
    const narrow = await engine.importCertificate("narrow", fx("expired-key.pem"), {
      certificatePem: fx("expired-cert.pem"),
      renewBeforeDays: 1,
    });
    const wide = await engine.importCertificate("wide", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      renewBeforeDays: 200,
    });
    // Both rows land 100 days out — inside the scheduler's wide net, so only the
    // per-row window can separate them.
    const notAfter = Date.now() + 100 * DAY_MS;
    setNotAfter(narrow.secretId, notAfter);
    setNotAfter(wide.secretId, notAfter);

    const items = engine.getExpiringCertificateStatuses();
    expect(items.map((i) => i.name)).toEqual(["wide"]);
    expect(items[0]).toMatchObject({ renew_before_days: 200, renewal_status: "expiring_soon" });
  });

  it("ignores a certificate beyond the scheduler's wide net", async () => {
    await engine.importCertificate("decade", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      renewBeforeDays: 365,
    });

    expect(engine.getExpiringCertificateStatuses()).toEqual([]);
  });

  it("ignores a CSR-only row that has no validity window yet", async () => {
    await engine.importCertificate("pending", fx("rsa-key.pem"), {
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
      subject: "CN=pending.example.com",
      renewBeforeDays: 365,
    });

    expect(engine.getExpiringCertificateStatuses()).toEqual([]);
  });

  it("carries the project on a project-scoped secret", async () => {
    await engine.importCertificate(
      "expired-leaf",
      fx("expired-key.pem"),
      { certificatePem: fx("expired-cert.pem"), renewBeforeDays: 1 },
      "api",
    );

    expect(engine.getExpiringCertificateStatuses()[0]).toMatchObject({
      handle: "secret://api/expired-leaf",
      name: "expired-leaf",
      project: "api",
    });
  });

  it("derives renewal_status the way getCertificateStatus does", async () => {
    const { secretId } = await engine.importCertificate("expired-leaf", fx("expired-key.pem"), {
      certificatePem: fx("expired-cert.pem"),
      renewBeforeDays: 1,
    });

    const projected = engine.getExpiringCertificateStatuses()[0] as ExpiringCertificateInfo;
    expect(projected.renewal_status).toBe(engine.getCertificateStatus(secretId).renewal_status);
    expect(projected.not_after).toBe(engine.getCertificateStatus(secretId).not_after);
    expect(projected.auto_renew).toBe(engine.getCertificateStatus(secretId).auto_renew);
  });

  it("silently drops policy-gated secrets for a token-derived caller", async () => {
    const { secretId } = await engine.importCertificate("gated", fx("expired-key.pem"), {
      certificatePem: fx("expired-cert.pem"),
      renewBeforeDays: 1,
    });
    grant(secretId, "agent", "alice", ["use"]);

    const before = engine.queryAudit({}).length;
    expect(engine.getExpiringCertificateStatuses(agent("mallory"))).toEqual([]);
    expect(engine.getExpiringCertificateStatuses(agent("alice"))).toEqual([]);
    expect(engine.getExpiringCertificateStatuses()).toHaveLength(1);
    expect(engine.queryAudit({}).length).toBe(before);
  });

  it("a `list` grant restores the row for its principal only", async () => {
    const { secretId } = await engine.importCertificate("gated", fx("expired-key.pem"), {
      certificatePem: fx("expired-cert.pem"),
      renewBeforeDays: 1,
    });
    grant(secretId, "agent", "alice", ["list"]);

    expect(engine.getExpiringCertificateStatuses(agent("alice"))).toHaveLength(1);
    expect(engine.getExpiringCertificateStatuses(agent("mallory"))).toEqual([]);
  });

  it("refuses while the vault is locked", async () => {
    await engine.lock();
    expect(() => engine.getExpiringCertificateStatuses()).toThrow(
      expect.objectContaining({ code: ErrorCode.VAULT_LOCKED }),
    );
  });
});

// ---------------------------------------------------------------------------
// Inclusive edges — pinned from both sides against a frozen clock
// ---------------------------------------------------------------------------

/**
 * Every threshold on these paths is `<=`. Each case writes its fixture exactly
 * on the edge and asserts the inclusive outcome, then moves it 1 ms past and
 * asserts the opposite — a one-sided assertion holds just as well for a `<`.
 *
 * The clock is frozen before the fixture is written: with a real one the
 * milliseconds between the write and the read shift the edge under the test.
 */
describe("inclusive window and status edges", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("includes an OAuth token expiring exactly at the caller's window edge", async () => {
    const { secretId } = await engine.createOAuthSecret("edge", oauthConfig());

    await engine.completeOAuthFlow(secretId, "at", "rt", Date.now() + HOUR_MS);
    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS)).toHaveLength(1);

    await engine.completeOAuthFlow(secretId, "at", "rt", Date.now() + HOUR_MS + 1);
    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS)).toEqual([]);
  });

  it("reports expiring_soon exactly at the 5 min refresh buffer", async () => {
    const { secretId } = await engine.createOAuthSecret("buffer", oauthConfig());

    await engine.completeOAuthFlow(secretId, "at", "rt", Date.now() + 5 * MINUTE_MS);
    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS)[0]?.refresh_status).toBe("expiring_soon");

    await engine.completeOAuthFlow(secretId, "at", "rt", Date.now() + 5 * MINUTE_MS + 1);
    expect(engine.getExpiringOAuthTokenStatuses(HOUR_MS)[0]?.refresh_status).toBe("ok");
  });

  it("includes a certificate landing exactly on its own renew_before_days edge", async () => {
    const { secretId } = await engine.importCertificate("edge", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      renewBeforeDays: 30,
    });

    setNotAfter(secretId, Date.now() + 30 * DAY_MS);
    expect(engine.getExpiringCertificateStatuses().map((i) => i.name)).toEqual(["edge"]);

    setNotAfter(secretId, Date.now() + 30 * DAY_MS + 1);
    expect(engine.getExpiringCertificateStatuses()).toEqual([]);
  });

  it("reports expired exactly at not_after", async () => {
    const { secretId } = await engine.importCertificate("edge", fx("rsa-key.pem"), {
      certificatePem: fx("rsa-cert.pem"),
      renewBeforeDays: 30,
    });

    setNotAfter(secretId, Date.now());
    expect(engine.getExpiringCertificateStatuses()[0]?.renewal_status).toBe("expired");

    setNotAfter(secretId, Date.now() + 1);
    expect(engine.getExpiringCertificateStatuses()[0]?.renewal_status).toBe("expiring_soon");
  });
});

// ---------------------------------------------------------------------------
// The projections agree with the existing row accessors
// ---------------------------------------------------------------------------

describe("projection/accessor agreement", () => {
  it("the OAuth projection covers exactly the rows the scheduler accessor returns", async () => {
    const { secretId } = await engine.createOAuthSecret("gh", oauthConfig());
    await engine.completeOAuthFlow(secretId, "at-1", "rt-1", Date.now() + 30 * MINUTE_MS);

    const rows = engine.getExpiringOAuthTokens(HOUR_MS);
    const projected: ExpiringOAuthTokenInfo[] = engine.getExpiringOAuthTokenStatuses(HOUR_MS);
    expect(projected).toHaveLength(rows.length);
    expect(projected[0]?.access_token_expires_at).toBe(rows[0]?.access_token_expires_at);
  });
});
