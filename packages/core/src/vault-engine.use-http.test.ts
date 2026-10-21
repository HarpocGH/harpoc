import { createServer } from "node:http";
import type { IncomingHttpHeaders, Server } from "node:http";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { InjectionConfig } from "@harpoc/shared";
import { AuditEventType, ErrorCode, MAX_HTTP_RESPONSE_BYTES } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import { validateUrl } from "./injection/url-validator.js";
import { retainDecryptedValues } from "./__fixtures__/engine-seams.js";

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
// I9: a request to /hold records its Authorization header on arrival and is
// answered only once the test resolves `holdGate`.
const holdArrivals: string[] = [];
let holdGate: Promise<void> | null = null;
let onHoldArrival: (() => void) | null = null;
// I14, M-P2-18: a request to /echo is recorded as it arrived and echoed back
// as JSON — the wire and the redaction of the echo, side by side.
interface EchoArrival {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  body: string;
}
const echoArrivals: EchoArrival[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    requestCount++;
    const auth = (req.headers["authorization"] ?? "none") as string;
    if (req.url?.startsWith("/hold")) {
      holdArrivals.push(auth);
      onHoldArrival?.();
      const gate = holdGate ?? Promise.resolve();
      holdGate = null;
      void gate.then(() => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ path: req.url }));
      });
      return;
    }
    if (req.url?.startsWith("/echo")) {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const arrival: EchoArrival = {
          method: req.method ?? "",
          url: req.url ?? "",
          headers: { ...req.headers },
          body: Buffer.concat(chunks).toString("utf8"),
        };
        echoArrivals.push(arrival);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(arrival));
      });
      return;
    }
    if (req.url?.startsWith("/big")) {
      // M-P2-18: one byte past the cap, streamed with no Content-Length, so
      // only the bounded read can refuse it.
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(Buffer.alloc(MAX_HTTP_RESPONSE_BYTES + 1, 0x61));
      return;
    }
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

// C5 (test-review-2026-10-09): useSecret's `finally { wipeBuffer(value) }`.
// The seam keeps the buffer the secret manager hands the engine, by reference.
describe("useSecret wipes the decrypted plaintext when it settles (C5)", () => {
  const PLAINTEXT = "c5-plaintext-credential";
  const allZero = (buf: Uint8Array): boolean => buf.every((b) => b === 0);
  let retained: Uint8Array[];

  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "wipe",
      type: "api_key",
      value: new Uint8Array(Buffer.from(PLAINTEXT)),
    });
    await engine.setInjectionPolicy("secret://wipe", {
      url_allowlist: [`${baseUrl}/allowed/*`],
    });
    retained = retainDecryptedValues(engine);
  });

  it("after a successful use against the loopback server", async () => {
    const res = await engine.useSecret("secret://wipe", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/allowed/ok`,
      injection: { type: "bearer" },
    });

    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(retained).toHaveLength(1);
    expect(retained[0]?.length).toBe(PLAINTEXT.length);
    expect(allZero(retained[0] as Uint8Array)).toBe(true);
  });

  it("after a policy refusal past the decrypt (URL_NOT_ALLOWED)", async () => {
    await expectVaultError(
      () =>
        engine.useSecret("secret://wipe", {
          type: "http",
          method: "GET",
          url: `${baseUrl}/blocked`,
          injection: { type: "bearer" },
        }),
      ErrorCode.URL_NOT_ALLOWED,
    );

    expect(retained).toHaveLength(1);
    expect(retained[0]?.length).toBe(PLAINTEXT.length);
    expect(allZero(retained[0] as Uint8Array)).toBe(true);
  });

  it("after an injector throw", async () => {
    const handed: Uint8Array[] = [];
    (
      engine as unknown as {
        httpInjector: { executeWithSecret: (...args: unknown[]) => Promise<unknown> };
      }
    ).httpInjector = {
      executeWithSecret: (...args: unknown[]) => {
        handed.push(args[1] as Uint8Array);
        return Promise.reject(new Error("connect ECONNRESET (forced)"));
      },
    };

    await expectVaultError(
      () =>
        engine.useSecret("secret://wipe", {
          type: "http",
          method: "GET",
          url: `${baseUrl}/allowed/ok`,
          injection: { type: "bearer" },
        }),
      ErrorCode.INTERNAL_ERROR,
    );

    expect(retained).toHaveLength(1);
    expect(handed).toEqual([retained[0]]);
    expect(handed[0]).toBe(retained[0]);
    expect(retained[0]?.length).toBe(PLAINTEXT.length);
    expect(allZero(retained[0] as Uint8Array)).toBe(true);
  });
});

// I9 (test-review-2026-10-09): "a request already in flight at the moment of
// rotation completes with the pre-rotation credential" (thesis 04:236).
describe("rotation while a use is in flight (I9)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "inflight",
      type: "api_key",
      value: new Uint8Array(Buffer.from("pre-rotation-value")),
    });
    await engine.setInjectionPolicy("secret://inflight", {
      url_allowlist: [`${baseUrl}/hold*`],
    });
    holdArrivals.length = 0;
  });

  afterEach(() => {
    holdGate = null;
    onHoldArrival = null;
  });

  function useHold(): ReturnType<VaultEngine["useSecret"]> {
    return engine.useSecret("secret://inflight", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/hold`,
      injection: { type: "bearer" },
    });
  }

  it("the in-flight request carries the pre-rotation value and the next use the rotated one", async () => {
    let release: () => void = () => undefined;
    holdGate = new Promise<void>((resolve) => (release = resolve));
    const arrived = new Promise<void>((resolve) => (onHoldArrival = resolve));

    const inFlight = useHold();
    try {
      await arrived;
      await engine.rotateSecret(
        "secret://inflight",
        new Uint8Array(Buffer.from("post-rotation-value")),
      );
      expect(holdArrivals).toEqual(["Bearer pre-rotation-value"]);

      release();
      const first = await inFlight;
      const second = await useHold();

      if (first.type !== "http" || second.type !== "http") throw new Error("expected http results");
      expect([first.status, second.status]).toEqual([200, 200]);
      expect(holdArrivals).toEqual(["Bearer pre-rotation-value", "Bearer post-rotation-value"]);
    } finally {
      release();
    }
  });
});

// I14 (test-review-2026-10-09): the header, query and basic_auth modes through
// the engine — the credential where the mode puts it on the wire, and redacted
// in the echoed result.
describe("HTTP injection modes on the wire (I14)", () => {
  const VALUE = "i14-user:i14-wire-credential";

  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "modes",
      type: "api_key",
      value: new Uint8Array(Buffer.from(VALUE)),
    });
    await engine.setInjectionPolicy("secret://modes", { url_allowlist: [`${baseUrl}/echo*`] });
    echoArrivals.length = 0;
  });

  async function useEcho(
    injection: InjectionConfig,
  ): Promise<{ arrival: EchoArrival; echoed: EchoArrival }> {
    const res = await engine.useSecret("secret://modes", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/echo`,
      injection,
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(echoArrivals).toHaveLength(1);
    const raw = res.body ?? "";
    expect(raw).not.toContain(VALUE);
    expect(raw).not.toContain(Buffer.from(VALUE).toString("base64"));
    expect(raw).not.toContain(encodeURIComponent(VALUE));
    return { arrival: echoArrivals[0] as EchoArrival, echoed: JSON.parse(raw) as EchoArrival };
  }

  function useRow(): { success: boolean; detail: Record<string, unknown> | null } {
    const rows = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(rows).toHaveLength(1);
    return { success: rows[0]?.success as boolean, detail: rows[0]?.detail ?? null };
  }

  it("header: the named header carries the value, nothing else does, and the echo is redacted", async () => {
    const { arrival, echoed } = await useEcho({ type: "header", header_name: "X-Api-Key" });

    expect(arrival.headers["x-api-key"]).toBe(VALUE);
    expect(arrival.headers.authorization).toBeUndefined();
    expect(arrival.url).toBe("/echo");
    expect(echoed.headers["x-api-key"]).toBe("[REDACTED]");
    expect(useRow()).toMatchObject({
      success: true,
      detail: { context: "http", status: 200, injection_type: "header" },
    });
  });

  it("query: the named parameter carries the value in the URL the server saw, and the echo is redacted", async () => {
    const { arrival, echoed } = await useEcho({ type: "query", query_param: "api_key" });

    expect(new URL(arrival.url, baseUrl).searchParams.get("api_key")).toBe(VALUE);
    expect(arrival.headers.authorization).toBeUndefined();
    expect(echoed.url).toBe("/echo?api_key=[REDACTED]");
    expect(useRow()).toMatchObject({
      success: true,
      detail: { context: "http", status: 200, injection_type: "query" },
    });
  });

  it("basic_auth: Authorization is Basic and decodes to the value, and the echo is redacted", async () => {
    const { arrival, echoed } = await useEcho({ type: "basic_auth" });

    const auth = arrival.headers.authorization ?? "";
    expect(auth).toMatch(/^Basic /);
    expect(Buffer.from(auth.slice("Basic ".length), "base64").toString("utf8")).toBe(VALUE);
    expect(arrival.url).toBe("/echo");
    expect(echoed.headers.authorization).toBe("Basic [REDACTED]");
    expect(useRow()).toMatchObject({
      success: true,
      detail: { context: "http", status: 200, injection_type: "basic_auth" },
    });
  });
});

// M-P2-18 (test-review-2026-10-09): the HTTP context's methods with a body,
// request headers, the response cap and the scheme floor through the engine.
describe("HTTP bodies, request headers, the response cap and the scheme floor (M-P2-18)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "p218",
      type: "api_key",
      value: new Uint8Array(Buffer.from("p218-credential")),
    });
    await engine.setInjectionPolicy("secret://p218", {
      url_allowlist: [`${baseUrl}/*`, "http://192.0.2.1/*"],
    });
    echoArrivals.length = 0;
  });

  function failedRow(): Record<string, unknown> | null | undefined {
    const rows = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    return rows[0]?.detail;
  }

  it.each(["PUT", "PATCH"] as const)("%s delivers its body verbatim", async (method) => {
    const body = JSON.stringify({ method, items: [1, 2, 3], note: "ünïcode ✓" });
    const res = await engine.useSecret("secret://p218", {
      type: "http",
      method,
      url: `${baseUrl}/echo/resource`,
      headers: { "Content-Type": "application/json" },
      body,
      injection: { type: "bearer" },
    });

    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(echoArrivals).toHaveLength(1);
    expect(echoArrivals[0]?.method).toBe(method);
    expect(echoArrivals[0]?.body).toBe(body);
    expect(echoArrivals[0]?.headers["content-type"]).toBe("application/json");
  });

  it("delivers the action's request headers as sent, beside the credential", async () => {
    const res = await engine.useSecret("secret://p218", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/echo`,
      headers: { "X-Request-Id": "p218-trace-7", Accept: "application/vnd.harpoc+json" },
      injection: { type: "bearer" },
    });

    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(echoArrivals[0]?.headers).toMatchObject({
      "x-request-id": "p218-trace-7",
      accept: "application/vnd.harpoc+json",
      authorization: "Bearer p218-credential",
    });
  });

  it("refuses a body one byte past the cap RESPONSE_TOO_LARGE, with a failed row", async () => {
    await expectVaultError(
      () =>
        engine.useSecret("secret://p218", {
          type: "http",
          method: "GET",
          url: `${baseUrl}/big`,
          injection: { type: "bearer" },
        }),
      ErrorCode.RESPONSE_TOO_LARGE,
    );

    expect(failedRow()).toMatchObject({
      context: "http",
      url: `${baseUrl}/big`,
      error: ErrorCode.RESPONSE_TOO_LARGE,
    });
  });

  // 192.0.2.1 (RFC 5737 TEST-NET-1) is a public-classified literal that routes
  // nowhere: the scheme check is the only guard that refuses it, and no
  // resolver runs.
  it("refuses plain http to a non-loopback address URL_HTTPS_REQUIRED before any request", async () => {
    const before = requestCount;
    await expectVaultError(
      () =>
        engine.useSecret("secret://p218", {
          type: "http",
          method: "GET",
          url: "http://192.0.2.1/api",
          timeout_ms: 1000,
          injection: { type: "bearer" },
        }),
      ErrorCode.URL_HTTPS_REQUIRED,
    );

    expect(validateUrl).toHaveBeenCalledWith("http://192.0.2.1/api");
    expect(requestCount).toBe(before);
    expect(failedRow()).toMatchObject({
      context: "http",
      url: "http://192.0.2.1/api",
      error: ErrorCode.URL_HTTPS_REQUIRED,
    });
  });
});

describe("the SSRF floor and the header sink through the engine (S8, S11)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "floor",
      type: "api_key",
      value: new Uint8Array(Buffer.from("S3CRET-TOKEN-xyz")),
    });
  });

  function useRows(): { success: boolean; detail: Record<string, unknown> | null }[] {
    return engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .map((row) => ({ success: row.success, detail: row.detail ?? null }));
  }

  it("refuses an allowlisted https://[::]/api SSRF_BLOCKED with a failed secret.use row (S8)", async () => {
    await engine.setInjectionPolicy("secret://floor", { url_allowlist: ["https://[::]/*"] });
    await expectVaultError(
      () =>
        engine.useSecret("secret://floor", {
          type: "http",
          method: "GET",
          url: "https://[::]/api",
          timeout_ms: 1000,
          injection: { type: "bearer" },
        }),
      ErrorCode.SSRF_BLOCKED,
    );
    expect(useRows()).toEqual([
      {
        success: false,
        detail: expect.objectContaining({
          context: "http",
          url: "https://[::]/api",
          error: ErrorCode.SSRF_BLOCKED,
        }),
      },
    ]);
  });

  it("refuses header_name __proto__ INVALID_INJECTION_CONFIG with a failed row, nothing sent (S11)", async () => {
    await engine.setInjectionPolicy("secret://floor", { url_allowlist: [`${baseUrl}/*`] });
    const before = requestCount;
    await expectVaultError(
      () =>
        engine.useSecret("secret://floor", {
          type: "http",
          method: "GET",
          url: `${baseUrl}/echo`,
          injection: { type: "header", header_name: "__proto__" },
        }),
      ErrorCode.INVALID_INJECTION_CONFIG,
    );
    expect(requestCount).toBe(before);
    expect(useRows()).toEqual([
      {
        success: false,
        detail: expect.objectContaining({
          context: "http",
          error: ErrorCode.INVALID_INJECTION_CONFIG,
          injection_type: "header",
        }),
      },
    ]);
  });
});
