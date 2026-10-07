import { createServer } from "node:http";
import type { Server } from "node:http";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import { validateUrl } from "./injection/url-validator.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const UNRESOLVED = vi.hoisted(() => ({
  host: "unresolved.pinned.test",
  url: "https://unresolved.pinned.test/api",
}));

vi.mock("./injection/url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./injection/url-validator.js")>();
  const shared = await import("@harpoc/shared");
  return {
    ...actual,
    validateUrl: vi.fn(async (...args: Parameters<typeof actual.validateUrl>) => {
      if (args[0] === UNRESOLVED.url) {
        throw new shared.VaultError(
          shared.ErrorCode.DNS_RESOLUTION_FAILED,
          `DNS resolution failed for ${UNRESOLVED.host}: getaddrinfo ENOTFOUND ${UNRESOLVED.host}`,
        );
      }
      return actual.validateUrl(...args);
    }),
  };
});

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

// Test HTTP server
let server: Server;
let baseUrl: string;
let requestCount = 0;

beforeAll(async () => {
  server = createServer((req, res) => {
    requestCount++;
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

describe("useSecret (HTTP injection)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("injects bearer token and returns response", async () => {
    await engine.createSecret({
      name: "api-token",
      type: "api_key",
      value: new Uint8Array(Buffer.from("my-bearer-token")),
    });
    await engine.setInjectionPolicy("secret://api-token", {
      url_allowlist: [`${baseUrl}/*`],
    });

    const response = await engine.useSecret("secret://api-token", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/test`,
      injection: { type: "bearer" },
    });

    expect(response.type).toBe("http");
    if (response.type !== "http") throw new Error("expected http result");
    expect(response.status).toBe(200);
    const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
    // Exact-match redaction scrubs the secret value from reflected responses
    expect(body.authorization).toBe("Bearer [REDACTED]");
  });
});

describe("URL allowlist enforcement (HTTP)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "url-al",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
  });

  it("allows a request matching the allowlist", async () => {
    await engine.setInjectionPolicy("secret://url-al", {
      url_allowlist: [`${baseUrl}/*`],
      command_allowlist: [],
      env_allowlist: [],
    });
    const res = await engine.useSecret("secret://url-al", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/ok`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
  });

  it("blocks a request not matching the allowlist", async () => {
    await engine.setInjectionPolicy("secret://url-al", {
      url_allowlist: [`${baseUrl}/allowed/*`],
      command_allowlist: [],
      env_allowlist: [],
    });
    await expectVaultError(
      () =>
        engine.useSecret("secret://url-al", {
          type: "http",
          method: "GET",
          url: `${baseUrl}/blocked`,
          injection: { type: "bearer" },
        }),
      ErrorCode.URL_NOT_ALLOWED,
    );
  });

  it("audits a blocked URL with success=false", async () => {
    await engine.setInjectionPolicy("secret://url-al", {
      url_allowlist: [`${baseUrl}/allowed/*`],
      command_allowlist: [],
      env_allowlist: [],
    });
    try {
      await engine.useSecret("secret://url-al", {
        type: "http",
        method: "GET",
        url: `${baseUrl}/blocked`,
        injection: { type: "bearer" },
      });
    } catch {
      // expected
    }
    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    const denied = events.find((e) => e.detail?.error === "URL_NOT_ALLOWED");
    expect(denied?.success).toBe(false);
  });

  it("re-validates every redirect hop against the allowlist (thesis §4.5.2)", async () => {
    await engine.setInjectionPolicy("secret://url-al", {
      url_allowlist: [`${baseUrl}/redirect-hop*`],
      command_allowlist: [],
      env_allowlist: [],
    });
    const before = requestCount;
    await expectVaultError(
      () =>
        engine.useSecret("secret://url-al", {
          type: "http",
          method: "GET",
          url: `${baseUrl}/redirect-hop`,
          injection: { type: "bearer" },
          follow_redirects: "any",
        }),
      ErrorCode.URL_NOT_ALLOWED,
    );
    // The credential-bearing request never followed the redirect: only the
    // 302 itself was fetched, /target was not.
    expect(requestCount - before).toBe(1);
    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    const denied = events.find((e) => e.detail?.error === "URL_NOT_ALLOWED");
    expect(denied?.success).toBe(false);
  });
});

describe("use_secret action dispatch", () => {
  it("rejects an unknown action type at runtime (never-typed default arm)", async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "dispatch",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    const err = await expectVaultError(
      () =>
        engine.useSecret("secret://dispatch", { type: "ftp" } as unknown as Parameters<
          VaultEngine["useSecret"]
        >[1]),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toContain("Unsupported action type: ftp");
  });
});

describe("response mode enforcement (HTTP)", () => {
  const secretValue = "rm-secret-value-2026";

  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "rm",
      type: "api_key",
      value: new Uint8Array(Buffer.from(secretValue)),
    });
    await engine.setInjectionPolicy("secret://rm", { url_allowlist: [`${baseUrl}/*`] });
  });

  it("defaults to filtered: body and headers returned, value redacted", async () => {
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(res.headers).toBeDefined();
    const body = JSON.parse(res.body ?? "{}") as Record<string, string>;
    expect(body.authorization).toBe("Bearer [REDACTED]");
  });

  it("filtered redacts encoded echoes (base64, hex)", async () => {
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/enc`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.body).toBeDefined();
    expect(res.body).not.toContain(Buffer.from(secretValue).toString("base64"));
    expect(res.body).not.toContain(Buffer.from(secretValue).toString("hex"));
    expect(res.body).toContain("[REDACTED]");
  });

  it("status_only policy strips body and headers", async () => {
    await engine.setInjectionPolicy("secret://rm", {
      url_allowlist: [`${baseUrl}/*`],
      response_mode: "status_only",
    });
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(res.body).toBeUndefined();
    expect(res.headers).toBeUndefined();
  });

  it("status_only returns only allowlisted headers", async () => {
    await engine.setInjectionPolicy("secret://rm", {
      url_allowlist: [`${baseUrl}/*`],
      response_mode: "status_only",
      response_header_allowlist: ["Content-Type"],
    });
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.headers).toEqual({ "content-type": "application/json" });
    expect(res.body).toBeUndefined();
  });

  it("a per-invocation override may tighten the default floor", async () => {
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
      response_mode: "status_only",
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(res.body).toBeUndefined();
  });

  it("an equal-mode override is accepted", async () => {
    await engine.setInjectionPolicy("secret://rm", {
      url_allowlist: [`${baseUrl}/*`],
      response_mode: "status_only",
    });
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
      response_mode: "status_only",
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
  });

  it("rejects a loosening override without executing the request", async () => {
    await engine.setInjectionPolicy("secret://rm", {
      url_allowlist: [`${baseUrl}/*`],
      response_mode: "status_only",
    });
    const before = requestCount;
    await expectVaultError(
      () =>
        engine.useSecret("secret://rm", {
          type: "http",
          method: "GET",
          url: `${baseUrl}/x`,
          injection: { type: "bearer" },
          response_mode: "full",
        }),
      ErrorCode.RESPONSE_MODE_NOT_ALLOWED,
    );
    expect(requestCount).toBe(before);
    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    const denied = events.find((e) => e.detail?.error === "RESPONSE_MODE_NOT_ALLOWED");
    expect(denied?.success).toBe(false);
    expect(denied?.detail?.requested_mode).toBe("full");
    expect(denied?.detail?.policy_mode).toBe("status_only");
  });

  it("rejects requesting full against the default filtered floor", async () => {
    await expectVaultError(
      () =>
        engine.useSecret("secret://rm", {
          type: "http",
          method: "GET",
          url: `${baseUrl}/x`,
          injection: { type: "bearer" },
          response_mode: "full",
        }),
      ErrorCode.RESPONSE_MODE_NOT_ALLOWED,
    );
  });

  it("full policy returns the raw echo unredacted", async () => {
    await engine.setInjectionPolicy("secret://rm", {
      url_allowlist: [`${baseUrl}/*`],
      response_mode: "full",
    });
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    const body = JSON.parse(res.body ?? "{}") as Record<string, string>;
    expect(body.authorization).toBe(`Bearer ${secretValue}`);
  });

  it("full policy may be tightened to filtered per invocation", async () => {
    await engine.setInjectionPolicy("secret://rm", {
      url_allowlist: [`${baseUrl}/*`],
      response_mode: "full",
    });
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
      response_mode: "filtered",
    });
    if (res.type !== "http") throw new Error("expected http result");
    const body = JSON.parse(res.body ?? "{}") as Record<string, string>;
    expect(body.authorization).toBe("Bearer [REDACTED]");
  });

  it("checks the URL allowlist before the response mode", async () => {
    await engine.setInjectionPolicy("secret://rm", {
      url_allowlist: [`${baseUrl}/allowed/*`],
      response_mode: "status_only",
    });
    await expectVaultError(
      () =>
        engine.useSecret("secret://rm", {
          type: "http",
          method: "GET",
          url: `${baseUrl}/blocked`,
          injection: { type: "bearer" },
          response_mode: "full",
        }),
      ErrorCode.URL_NOT_ALLOWED,
    );
  });
});

describe("audit trail for failed useSecret", () => {
  let secretId: string;

  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "audit-use",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });
    await engine.setInjectionPolicy("secret://audit-use", {
      url_allowlist: [`https://${UNRESOLVED.host}/*`, `${baseUrl}/*`, "http://127.0.0.1:2/*"],
    });
    secretId = await engine.resolveSecretId("secret://audit-use");
  });

  it("logs DNS failure with success=false", async () => {
    const response = await engine.useSecret("secret://audit-use", {
      type: "http",
      method: "GET",
      url: UNRESOLVED.url,
      injection: { type: "bearer" },
    });

    expect(validateUrl).toHaveBeenCalledWith(UNRESOLVED.url);
    expect(response).toMatchObject({ status: null, error: ErrorCode.DNS_RESOLUTION_FAILED });
    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      success: false,
      secret_id: secretId,
      detail: { context: "http", error: ErrorCode.DNS_RESOLUTION_FAILED },
    });
  });

  it("logs successful request with success=true", async () => {
    await engine.useSecret("secret://audit-use", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/test`,
      injection: { type: "bearer" },
    });

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      success: true,
      secret_id: secretId,
      detail: { context: "http", method: "GET", status: 200 },
    });
  });

  it("logs connection refused with success=false", async () => {
    const response = await engine.useSecret("secret://audit-use", {
      type: "http",
      method: "GET",
      url: "http://127.0.0.1:2/api",
      timeout_ms: 5000,
      injection: { type: "bearer" },
    });

    expect(response).toMatchObject({ status: null, error: ErrorCode.CONNECTION_REFUSED });
    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      success: false,
      secret_id: secretId,
      detail: { context: "http", error: ErrorCode.CONNECTION_REFUSED },
    });
  });
});
