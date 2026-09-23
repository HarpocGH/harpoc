import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";

const PASSWORD = "scope-refusal-audit-pw";

describe("every REST scope refusal writes an access.denied row (D2g)", () => {
  let vault: TestVault;
  let server: TestServer;
  let projectScoped: string;
  let readOnly: string;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "scoped-agent");
    registerAgents(vault.engine, "reader");
    for (const project of ["other", "acme"]) {
      await vault.engine.createSecret({
        name: "db",
        project,
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from("v")),
      });
    }
    projectScoped = vault.engine.createToken("scoped-agent", ["read", "list"], 600_000, {
      project: "acme",
    });
    readOnly = vault.engine.createToken("reader", ["read", "list"], 600_000);
    server = startTestServer(vault.engine);
  });

  afterAll(async () => {
    await server?.close();
    await destroyTestVault(vault).catch(() => {});
  });

  const denied = () => vault.engine.queryAudit({ eventType: AuditEventType.ACCESS_DENIED });

  async function call(method: string, path: string, token: string): Promise<Response> {
    return fetch(`${server.baseUrl}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: method === "POST" ? "{}" : undefined,
    });
  }

  it("a project-scoped token on another project's handle: 403 and one row with reason project and the encoded path", async () => {
    const res = await call("GET", "/api/v1/secrets/other%2Fdb", projectScoped);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);
    const rows = denied().filter((r) => r.detail?.operation === "GET /api/v1/secrets/other%2Fdb");
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.secret_id).toBeNull();
    expect(rows[0]?.principal_type).toBe("agent");
    expect(rows[0]?.principal_id).toBe("scoped-agent");
    expect(rows[0]?.ip_address).toBe("127.0.0.1");
    expect(rows[0]?.detail).toEqual({
      operation: "GET /api/v1/secrets/other%2Fdb",
      error: ErrorCode.ACCESS_DENIED,
      reason: "project",
      interface: "rest",
    });
  });

  it("a read-only token on POST …/rotate: 403 and one row with reason permission", async () => {
    const res = await call("POST", "/api/v1/secrets/acme%2Fdb/rotate", readOnly);
    expect(res.status).toBe(403);
    const rows = denied().filter(
      (r) => r.detail?.operation === "POST /api/v1/secrets/acme%2Fdb/rotate",
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.principal_id).toBe("reader");
    expect(rows[0]?.detail).toMatchObject({ reason: "permission", interface: "rest" });
  });

  it("an admitted call leaves no access.denied row", async () => {
    const before = denied().length;
    expect((await call("GET", "/api/v1/secrets", readOnly)).status).toBe(200);
    expect(denied()).toHaveLength(before);
  });
});
