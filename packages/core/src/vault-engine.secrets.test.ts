import { createServer } from "node:http";
import type { Server } from "node:http";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
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
