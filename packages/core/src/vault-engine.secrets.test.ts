import { createServer } from "node:http";
import type { Server } from "node:http";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { CallerContext } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

// Test HTTP server
let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    const auth = (req.headers["authorization"] ?? "none") as string;
    if (req.url?.startsWith("/redirect-hop")) {
      res.writeHead(302, { Location: `http://${req.headers.host ?? "127.0.0.1"}/target` });
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    if (req.url?.startsWith("/enc")) {
      // Echo the bearer token in encoded forms (sanitizer-bypass probes)
      const token = auth.replace("Bearer ", "");
      res.end(
        JSON.stringify({
          b64: Buffer.from(token).toString("base64"),
          hex: Buffer.from(token).toString("hex"),
          pct: encodeURIComponent(token),
        }),
      );
      return;
    }
    res.end(JSON.stringify({ authorization: auth, path: req.url }));
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as { port: number };
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(() => {
  server.close();
});

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-ve-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("secrets", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("creates and lists secrets", async () => {
    await engine.createSecret({
      name: "test-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("secret-value")),
    });

    const list = engine.listSecrets();
    expect(list.length).toBe(1);
    expect(list[0]?.name).toBe("test-key");
  });

  it("creates and retrieves secret info", async () => {
    await engine.createSecret({
      name: "info-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });

    const info = await engine.getSecretInfo("secret://info-key");
    expect(info.name).toBe("info-key");
    expect(info.status).toBe("active");
  });

  it("creates and retrieves secret value", async () => {
    await engine.createSecret({
      name: "get-val",
      type: "api_key",
      value: new Uint8Array(Buffer.from("the-secret")),
    });

    const value = await engine.getSecretValue("secret://get-val");
    expect(Buffer.from(value).toString()).toBe("the-secret");
  });

  it("rotates a secret", async () => {
    await engine.createSecret({
      name: "rotate-me",
      type: "api_key",
      value: new Uint8Array(Buffer.from("old")),
    });

    await engine.rotateSecret("secret://rotate-me", new Uint8Array(Buffer.from("new")));

    const info = await engine.getSecretInfo("secret://rotate-me");
    expect(info.version).toBe(2);

    const value = await engine.getSecretValue("secret://rotate-me");
    expect(Buffer.from(value).toString()).toBe("new");
  });

  it("revokes a secret", async () => {
    await engine.createSecret({
      name: "rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await engine.revokeSecret("secret://rev");

    const info = await engine.getSecretInfo("secret://rev");
    expect(info.status).toBe("revoked");
  });
});

describe("error propagation through VaultEngine", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("getSecretInfo throws SECRET_NOT_FOUND for non-existent handle", async () => {
    await expectVaultError(
      () => engine.getSecretInfo("secret://nonexistent"),
      ErrorCode.SECRET_NOT_FOUND,
    );
  });

  it("getSecretValue throws SECRET_NOT_FOUND for non-existent handle", async () => {
    await expectVaultError(
      () => engine.getSecretValue("secret://nonexistent"),
      ErrorCode.SECRET_NOT_FOUND,
    );
  });

  it("getSecretInfo throws INVALID_HANDLE for malformed handle", async () => {
    await expectVaultError(() => engine.getSecretInfo("not-a-handle"), ErrorCode.INVALID_HANDLE);
  });

  it("getSecretValue throws SECRET_REVOKED for revoked secret", async () => {
    await engine.createSecret({
      name: "rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await engine.revokeSecret("secret://rev");

    await expectVaultError(() => engine.getSecretValue("secret://rev"), ErrorCode.SECRET_REVOKED);
  });

  it("getSecretValue throws SECRET_VALUE_REQUIRED for pending secret", async () => {
    await engine.createSecret({ name: "pend", type: "api_key" });

    await expectVaultError(
      () => engine.getSecretValue("secret://pend"),
      ErrorCode.SECRET_VALUE_REQUIRED,
    );
  });

  it("createSecret throws DUPLICATE_SECRET for duplicate name", async () => {
    await engine.createSecret({
      name: "dup",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await expectVaultError(
      () =>
        engine.createSecret({
          name: "dup",
          type: "api_key",
          value: new Uint8Array(Buffer.from("v2")),
        }),
      ErrorCode.DUPLICATE_SECRET,
    );
  });

  it("rotateSecret throws SECRET_REVOKED for revoked secret", async () => {
    await engine.createSecret({
      name: "rot-rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await engine.revokeSecret("secret://rot-rev");

    await expectVaultError(
      () => engine.rotateSecret("secret://rot-rev", new Uint8Array(Buffer.from("new"))),
      ErrorCode.SECRET_REVOKED,
    );
  });

  it("useSecret throws SECRET_NOT_FOUND for non-existent handle", async () => {
    await expectVaultError(
      () =>
        engine.useSecret("secret://nonexistent", {
          type: "http",
          method: "GET",
          url: `${baseUrl}/test`,
          injection: { type: "bearer" },
        }),
      ErrorCode.SECRET_NOT_FOUND,
    );
  });

  it("useSecret throws SECRET_REVOKED for revoked secret", async () => {
    await engine.createSecret({
      name: "use-rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await engine.revokeSecret("secret://use-rev");

    await expectVaultError(
      () =>
        engine.useSecret("secret://use-rev", {
          type: "http",
          method: "GET",
          url: `${baseUrl}/test`,
          injection: { type: "bearer" },
        }),
      ErrorCode.SECRET_REVOKED,
    );
  });

  it("useSecret refuses an unparseable URL through the allowlist (URL_NOT_ALLOWED precedes the validator)", async () => {
    await engine.createSecret({
      name: "url-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await engine.setInjectionPolicy("secret://url-test", {
      url_allowlist: ["https://api.example.com/*"],
    });

    await expectVaultError(
      () =>
        engine.useSecret("secret://url-test", {
          type: "http",
          method: "GET",
          url: "not-a-url",
          injection: { type: "bearer" },
        }),
      ErrorCode.URL_NOT_ALLOWED,
    );
  });

  it("useSecret throws SSRF_BLOCKED for private IP", async () => {
    await engine.createSecret({
      name: "ssrf-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await engine.setInjectionPolicy("secret://ssrf-test", {
      url_allowlist: ["https://10.0.0.1/*"],
    });

    await expectVaultError(
      () =>
        engine.useSecret("secret://ssrf-test", {
          type: "http",
          method: "GET",
          url: "https://10.0.0.1/api",
          injection: { type: "bearer" },
        }),
      ErrorCode.SSRF_BLOCKED,
    );
  });
});

describe("policies", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    registerAgents(engine, "agent-1");
    await engine.createSecret({
      name: "policy-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
  });

  it("grants and lists policies", async () => {
    const secretId = await engine.resolveSecretId("secret://policy-test");

    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: "agent",
        principalId: "agent-1",
        permissions: ["read", "use"],
      },
      "admin",
    );

    expect(policy.id).toBeTruthy();

    const policies = engine.listPolicies(secretId);
    expect(policies.length).toBe(1);
  });

  it("revokes a policy", async () => {
    const secretId = await engine.resolveSecretId("secret://policy-test");

    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: "agent",
        principalId: "agent-1",
        permissions: ["read"],
      },
      "admin",
    );

    engine.revokePolicy(policy.id);
    expect(engine.listPolicies(secretId).length).toBe(0);
  });
});

describe("secrets through VaultEngine — additional coverage", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("lists secrets filtered by project", async () => {
    await engine.createSecret({
      name: "a",
      type: "api_key",
      project: "proj-a",
      value: new Uint8Array(Buffer.from("va")),
    });
    await engine.createSecret({
      name: "b",
      type: "api_key",
      project: "proj-b",
      value: new Uint8Array(Buffer.from("vb")),
    });
    await engine.createSecret({
      name: "c",
      type: "api_key",
      value: new Uint8Array(Buffer.from("vc")),
    });

    const projA = engine.listSecrets("proj-a");
    expect(projA.length).toBe(1);
    expect(projA[0]?.name).toBe("a");

    const all = engine.listSecrets();
    expect(all.length).toBe(3);
  });

  it("creates a pending secret and sets its value", async () => {
    await engine.createSecret({ name: "deferred", type: "api_key" });

    const infoBefore = await engine.getSecretInfo("secret://deferred");
    expect(infoBefore.status).toBe("pending");

    await engine.setSecretValue("secret://deferred", new Uint8Array(Buffer.from("set-later")));

    const infoAfter = await engine.getSecretInfo("secret://deferred");
    expect(infoAfter.status).toBe("active");

    const value = await engine.getSecretValue("secret://deferred");
    expect(Buffer.from(value).toString()).toBe("set-later");
  });
});

describe("lazy expiry in info/list", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("getSecretInfo returns expired status for past-expiry secret", async () => {
    await engine.createSecret({
      name: "exp-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      expiresAt: Date.now() - 1000, // Already expired
    });

    const info = await engine.getSecretInfo("secret://exp-test");
    expect(info.status).toBe("expired");
  });

  it("listSecrets returns expired status for past-expiry secret", async () => {
    await engine.createSecret({
      name: "exp-list",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      expiresAt: Date.now() - 1000,
    });

    const list = engine.listSecrets();
    const found = list.find((s) => s.name === "exp-list");
    expect(found?.status).toBe("expired");
  });
});

describe("lazy expiry never rewrites a revoked secret (Q2)", () => {
  const MINUTE_MS = 60_000;

  beforeEach(async () => {
    await engine.initVault("password");
    vi.useFakeTimers({ toFake: ["Date"] });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  async function revokedPastExpiry(name: string): Promise<string> {
    await engine.createSecret({
      name,
      type: "api_key",
      value: new Uint8Array(Buffer.from("S3CRET-TOKEN-xyz")),
      expiresAt: Date.now() + MINUTE_MS,
    });
    const id = await engine.resolveSecretId(`secret://${name}`);
    await engine.revokeSecret(`secret://${name}`);
    vi.setSystemTime(Date.now() + 2 * MINUTE_MS);
    return id;
  }

  function storedStatus(id: string): string {
    const db = new Database(dbPath, { readonly: true });
    try {
      return (db.prepare("SELECT status FROM secrets WHERE id = ?").get(id) as { status: string })
        .status;
    } finally {
      db.close();
    }
  }

  function storedExpiresAt(id: string): number | null {
    const db = new Database(dbPath, { readonly: true });
    try {
      return (
        db.prepare("SELECT expires_at FROM secrets WHERE id = ?").get(id) as {
          expires_at: number | null;
        }
      ).expires_at;
    } finally {
      db.close();
    }
  }

  function trail(id: string): [string, boolean][] {
    return engine
      .queryAudit({ secretId: id })
      .map((r): [string, boolean] => [r.event_type, r.success])
      .reverse();
  }

  it("getSecretInfo and listSecrets report a revoked secret past its expiry as revoked", async () => {
    await revokedPastExpiry("rev-info");

    expect((await engine.getSecretInfo("secret://rev-info")).status).toBe("revoked");
    expect(engine.listSecrets().find((s) => s.name === "rev-info")?.status).toBe("revoked");
  });

  it("getSecretValue answers SECRET_REVOKED, the stored status stays revoked and no secret.expire row is written", async () => {
    const id = await revokedPastExpiry("rev-value");

    await expectVaultError(
      () => engine.getSecretValue("secret://rev-value"),
      ErrorCode.SECRET_REVOKED,
    );
    expect(storedStatus(id)).toBe("revoked");
    expect(trail(id)).toEqual([
      [AuditEventType.SECRET_CREATE, true],
      [AuditEventType.SECRET_REVOKE, true],
      [AuditEventType.SECRET_READ, false],
    ]);
  });

  it("useSecret on a revoked secret past expiry answers SECRET_REVOKED and writes no status", async () => {
    const id = await revokedPastExpiry("rev-use");

    await expectVaultError(
      () =>
        engine.useSecret("secret://rev-use", {
          type: "http",
          method: "GET",
          url: "http://127.0.0.1:9/never",
          injection: { type: "bearer" },
        }),
      ErrorCode.SECRET_REVOKED,
    );
    expect(storedStatus(id)).toBe("revoked");
    expect(trail(id)).toEqual([
      [AuditEventType.SECRET_CREATE, true],
      [AuditEventType.SECRET_REVOKE, true],
      [AuditEventType.SECRET_USE, false],
    ]);
  });

  it("rotateSecret answers SECRET_REVOKED", async () => {
    const id = await revokedPastExpiry("rev-rotate");

    await expectVaultError(
      () =>
        engine.rotateSecret("secret://rev-rotate", new Uint8Array(Buffer.from("S3CRET-TOKEN-new"))),
      ErrorCode.SECRET_REVOKED,
    );
    expect(storedStatus(id)).toBe("revoked");
  });

  it("after a value read the name can be created again", async () => {
    await revokedPastExpiry("rev-recreate");
    await expectVaultError(
      () => engine.getSecretValue("secret://rev-recreate"),
      ErrorCode.SECRET_REVOKED,
    );

    await engine.createSecret({
      name: "rev-recreate",
      type: "api_key",
      value: new Uint8Array(Buffer.from("S3CRET-TOKEN-new")),
    });
    expect((await engine.getSecretInfo("secret://rev-recreate")).status).toBe("active");
  });

  it("after a value read a further revoke still answers SECRET_REVOKED", async () => {
    const id = await revokedPastExpiry("rev-again");
    await expectVaultError(
      () => engine.getSecretValue("secret://rev-again"),
      ErrorCode.SECRET_REVOKED,
    );

    await expectVaultError(
      () => engine.revokeSecret("secret://rev-again"),
      ErrorCode.SECRET_REVOKED,
    );
    expect(storedStatus(id)).toBe("revoked");
  });

  it("an active secret past its expiry still expires on a value read, with one secret.expire row", async () => {
    await engine.createSecret({
      name: "act-past",
      type: "api_key",
      value: new Uint8Array(Buffer.from("S3CRET-TOKEN-xyz")),
      expiresAt: Date.now() + MINUTE_MS,
    });
    const id = await engine.resolveSecretId("secret://act-past");
    vi.setSystemTime(Date.now() + 2 * MINUTE_MS);

    await expectVaultError(
      () => engine.getSecretValue("secret://act-past"),
      ErrorCode.SECRET_EXPIRED,
    );
    expect(storedStatus(id)).toBe("expired");
    expect(trail(id)).toEqual([
      [AuditEventType.SECRET_CREATE, true],
      [AuditEventType.SECRET_EXPIRE, true],
      [AuditEventType.SECRET_READ, false],
    ]);
  });

  it("a pending secret past its expiry reads expired and expires on a value read, unchanged", async () => {
    await engine.createSecret({
      name: "pend-past",
      type: "api_key",
      expiresAt: Date.now() + MINUTE_MS,
    });
    const id = await engine.resolveSecretId("secret://pend-past");
    vi.setSystemTime(Date.now() + 2 * MINUTE_MS);

    expect((await engine.getSecretInfo("secret://pend-past")).status).toBe("expired");
    expect(storedStatus(id)).toBe("pending");
    await expectVaultError(
      () => engine.getSecretValue("secret://pend-past"),
      ErrorCode.SECRET_EXPIRED,
    );
    expect(storedStatus(id)).toBe("expired");
  });

  it("a pending secret past expiry still accepts setSecretValue before any value read, stored active with the past expires_at, and the next value read expires it (C4-t control)", async () => {
    const expiresAt = Date.now() + MINUTE_MS;
    await engine.createSecret({ name: "pend-set", type: "api_key", expiresAt });
    const id = await engine.resolveSecretId("secret://pend-set");
    vi.setSystemTime(Date.now() + 2 * MINUTE_MS);

    await engine.setSecretValue(
      "secret://pend-set",
      new Uint8Array(Buffer.from("S3CRET-TOKEN-xyz")),
    );
    expect(storedStatus(id)).toBe("active");
    expect(storedExpiresAt(id)).toBe(expiresAt);

    await expectVaultError(
      () => engine.getSecretValue("secret://pend-set"),
      ErrorCode.SECRET_EXPIRED,
    );
    expect(storedStatus(id)).toBe("expired");
    expect(trail(id)).toEqual([
      [AuditEventType.SECRET_CREATE, true],
      [AuditEventType.SECRET_CREATE, true],
      [AuditEventType.SECRET_EXPIRE, true],
      [AuditEventType.SECRET_READ, false],
    ]);
  });

  it("a pending secret past expiry expired by a value read refuses setSecretValue with INVALID_INPUT and is still revocable (C4-t control)", async () => {
    await engine.createSecret({
      name: "pend-read",
      type: "api_key",
      expiresAt: Date.now() + MINUTE_MS,
    });
    const id = await engine.resolveSecretId("secret://pend-read");
    vi.setSystemTime(Date.now() + 2 * MINUTE_MS);

    await expectVaultError(
      () => engine.getSecretValue("secret://pend-read"),
      ErrorCode.SECRET_EXPIRED,
    );
    expect(storedStatus(id)).toBe("expired");

    await expectVaultError(
      () =>
        engine.setSecretValue(
          "secret://pend-read",
          new Uint8Array(Buffer.from("S3CRET-TOKEN-xyz")),
        ),
      ErrorCode.INVALID_INPUT,
    );

    await engine.revokeSecret("secret://pend-read");
    expect(storedStatus(id)).toBe("revoked");
    expect(trail(id)).toEqual([
      [AuditEventType.SECRET_CREATE, true],
      [AuditEventType.SECRET_EXPIRE, true],
      [AuditEventType.SECRET_READ, false],
      [AuditEventType.SECRET_CREATE, false],
      [AuditEventType.SECRET_REVOKE, true],
    ]);
  });
});

describe("rotateSecret refuses an empty value (Q3, TC-18)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("the trusted path answers INVALID_INPUT, keeps version 1 and its value, and writes one failed secret.rotate row carrying the id", async () => {
    await engine.createSecret({
      name: "rot-empty",
      type: "api_key",
      value: new Uint8Array(Buffer.from("S3CRET-TOKEN-xyz")),
    });
    const id = await engine.resolveSecretId("secret://rot-empty");

    const err = await expectVaultError(
      () => engine.rotateSecret("secret://rot-empty", new Uint8Array(0)),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe("Secret secret://rot-empty cannot be rotated to an empty value");

    expect((await engine.getSecretInfo("secret://rot-empty")).version).toBe(1);
    expect(Buffer.from(await engine.getSecretValue("secret://rot-empty")).toString()).toBe(
      "S3CRET-TOKEN-xyz",
    );
    const rows = engine.queryAudit({ eventType: AuditEventType.SECRET_ROTATE });
    expect(
      rows.map((r) => ({
        success: r.success,
        secret_id: r.secret_id,
        principal_id: r.principal_id,
        detail: r.detail,
      })),
    ).toEqual([
      {
        success: false,
        secret_id: id,
        principal_id: null,
        detail: { handle: "secret://rot-empty", error: ErrorCode.INVALID_INPUT },
      },
    ]);
  });

  it("a rotate-granted token caller answers INVALID_INPUT and its failed row carries the id, the principal and the interface", async () => {
    await engine.createSecret({
      name: "rot-empty-agent",
      type: "api_key",
      value: new Uint8Array(Buffer.from("S3CRET-TOKEN-xyz")),
    });
    const id = await engine.resolveSecretId("secret://rot-empty-agent");
    registerAgents(engine, "rotator");
    engine.grantPolicy(
      { secretId: id, principalType: "agent", principalId: "rotator", permissions: ["rotate"] },
      "test-admin",
    );
    const caller: CallerContext = {
      principal_type: "agent",
      principal_id: "rotator",
      interface: "rest",
    };

    await expectVaultError(
      () => engine.rotateSecret("secret://rot-empty-agent", new Uint8Array(0), caller),
      ErrorCode.INVALID_INPUT,
    );

    expect((await engine.getSecretInfo("secret://rot-empty-agent")).version).toBe(1);
    const rows = engine.queryAudit({ eventType: AuditEventType.SECRET_ROTATE });
    expect(
      rows.map((r) => ({
        success: r.success,
        secret_id: r.secret_id,
        principal_type: r.principal_type,
        principal_id: r.principal_id,
        detail: r.detail,
      })),
    ).toEqual([
      {
        success: false,
        secret_id: id,
        principal_type: "agent",
        principal_id: "rotator",
        detail: {
          handle: "secret://rot-empty-agent",
          error: ErrorCode.INVALID_INPUT,
          interface: "rest",
        },
      },
    ]);
  });
});
