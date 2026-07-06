import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

/**
 * HTTP execution context — response modes (thesis §4.5.2, §6 sec:attack-i2a-bypass).
 *
 * End-to-end coverage of the structural I2a defense: `status_only` removes the
 * response-body channel entirely, `filtered` (the default) redacts the
 * credential and its encodings, and `full` is the policy-gated raw opt-out.
 * The tighten-only override rule is exercised over the real KEK-encrypted
 * policy blob with a real Argon2 vault.
 */

const PASSWORD = "integration-test-pw";
const SECRET = "sk-http-secret-2b4d6f8a0c1e";

let server: Server;
let baseUrl: string;
let requestCount = 0;

beforeAll(async () => {
  server = createServer((req, res) => {
    requestCount++;
    const auth = (req.headers["authorization"] ?? "") as string;
    const token = auth.replace("Bearer ", "");
    res.writeHead(200, { "content-type": "application/json" });
    if (req.url?.startsWith("/enc")) {
      // Encoded-echo probe endpoint (evaluation bypass class 1)
      res.end(
        JSON.stringify({
          b64: Buffer.from(token).toString("base64"),
          hex: Buffer.from(token).toString("hex"),
        }),
      );
      return;
    }
    res.end(JSON.stringify({ echoed: token }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
});

describe("HTTP context — response modes (structural I2a)", () => {
  let vault: TestVault;
  let handle: string;

  beforeEach(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    const created = await vault.engine.createSecret({
      name: "http-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from(SECRET, "utf8")),
    });
    handle = created.handle;
  });

  afterEach(async () => {
    await destroyTestVault(vault);
  });

  it("status_only returns the outcome alone over the real policy round-trip", async () => {
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "status_only",
      response_header_allowlist: ["Content-Type"],
    });

    const res = await vault.engine.useSecret(handle, {
      type: "http",
      method: "GET",
      url: `${baseUrl}/create`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(res.body).toBeUndefined();
    expect(res.headers).toEqual({ "content-type": "application/json" });
  });

  it("rejects a loosening override; the request never leaves the vault", async () => {
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "status_only",
      response_header_allowlist: [],
    });

    const before = requestCount;
    await expect(
      vault.engine.useSecret(handle, {
        type: "http",
        method: "GET",
        url: `${baseUrl}/x`,
        injection: { type: "bearer" },
        response_mode: "full",
      }),
    ).rejects.toMatchObject({ code: ErrorCode.RESPONSE_MODE_NOT_ALLOWED });
    expect(requestCount).toBe(before);

    const events = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    const denied = events.find((e) => e.detail?.error === "RESPONSE_MODE_NOT_ALLOWED");
    expect(denied?.success).toBe(false);
    expect(denied?.detail?.requested_mode).toBe("full");
    expect(denied?.detail?.policy_mode).toBe("status_only");
  });

  it("filtered (default, no policy row) redacts the raw credential echo", async () => {
    const res = await vault.engine.useSecret(handle, {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.body).toContain("[REDACTED]");
    expect(res.body).not.toContain(SECRET);
  });

  it("filtered redacts encoded echoes (base64 / hex)", async () => {
    const res = await vault.engine.useSecret(handle, {
      type: "http",
      method: "GET",
      url: `${baseUrl}/enc`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.body).not.toContain(Buffer.from(SECRET).toString("base64"));
    expect(res.body).not.toContain(Buffer.from(SECRET).toString("hex"));
    expect(res.body).toContain("[REDACTED]");
  });

  it("full is the policy-gated raw opt-out", async () => {
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "full",
      response_header_allowlist: [],
    });

    const res = await vault.engine.useSecret(handle, {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.body).toContain(SECRET);
  });

  it("an agent may tighten the default floor to status_only per invocation", async () => {
    const res = await vault.engine.useSecret(handle, {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
      response_mode: "status_only",
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(res.body).toBeUndefined();
    expect(res.headers).toBeUndefined();
  });
});
