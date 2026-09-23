import { createServer } from "node:https";
import type { Server } from "node:https";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { LOOPBACK_CERT_PEM, LOOPBACK_HOST, LOOPBACK_KEY_PEM } from "./helpers/loopback-cert.js";

describe("http.ca_pem pins a private CA for the HTTP context (D2h)", () => {
  let vault: TestVault;
  let server: Server;
  let base: string;
  let handle: string;

  beforeAll(async () => {
    server = createServer({ cert: LOOPBACK_CERT_PEM, key: LOOPBACK_KEY_PEM }, (_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end('{"ok":true}');
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `https://${LOOPBACK_HOST}:${(server.address() as AddressInfo).port}`;
    vault = createTestVault();
    await vault.engine.initVault("http-ca-pin-pw");
    const created = await vault.engine.createSecret({
      name: "api",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("k")),
    });
    handle = created.handle;
    await vault.engine.setInjectionPolicy(handle, { url_allowlist: [`${base}/*`] });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await destroyTestVault(vault);
  });

  const action = () => ({
    type: "http" as const,
    method: "GET" as const,
    url: `${base}/`,
    injection: { type: "bearer" as const },
  });
  const lastUseRow = () =>
    vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .filter((r) => r.detail?.context === "http")
      .at(0);

  it("unpinned: TLS_ERROR and a failed secret.use row without ca_pinned", async () => {
    const result = await vault.engine.useSecret(handle, action());
    expect(result).toMatchObject({ type: "http", status: null, error: ErrorCode.TLS_ERROR });
    expect(lastUseRow()?.success).toBe(false);
    expect(lastUseRow()?.detail).not.toHaveProperty("ca_pinned");
  });

  it("pinned: the grant row has_http, 200, and the secret.use row ca_pinned", async () => {
    await vault.engine.setConnectionConfig(handle, { http: { ca_pem: LOOPBACK_CERT_PEM } });
    const grant = vault.engine
      .queryAudit({ eventType: AuditEventType.POLICY_GRANT })
      .filter((r) => r.detail?.policy === "connection")
      .at(0);
    expect(grant?.detail).toMatchObject({ has_http: true, has_git: false });
    const result = await vault.engine.useSecret(handle, action());
    expect(result).toMatchObject({ type: "http", status: 200 });
    expect(lastUseRow()?.detail).toMatchObject({ context: "http", status: 200, ca_pinned: true });
  });
});
