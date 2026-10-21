import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import type { IssuedToken } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";
import { runCli } from "./helpers/spawn-cli.js";
import { silenceAuditLines } from "@harpoc/test-utils";

silenceAuditLines();

const PASSWORD = "governance-scope-integration-pw";
const MESSAGE = "governance requires an unscoped admin token";

describe("Governance refuses a project-claimed admin token (R11/N12)", () => {
  let vault: TestVault;
  let server: TestServer;
  let unscoped: string;
  let scoped: string;
  let scopedJti: string;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "gov-admin");
    unscoped = vault.engine.createToken("gov-admin", ["admin"]);
    // Ten minutes, not the case budget: three CLI spawns plus the REST calls
    // must never race the token's own expiry on a loaded runner.
    scoped = vault.engine.createToken("gov-admin", ["admin"], 600_000, {
      project: "acme",
    });
    const rows = vault.engine.listIssuedTokens();
    scopedJti = (rows.find((row) => row.project === "acme") as IssuedToken).jti;
    server = startTestServer(vault.engine);
  });

  afterAll(async () => {
    await server?.close();
    await destroyTestVault(vault);
  });

  async function get(path: string, token: string): Promise<Response> {
    return fetch(`${server.baseUrl}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  }

  it("REST: both governance groups answer 403 before the engine, the secrets routes still 200", async () => {
    for (const path of ["/api/v1/agents", "/api/v1/tokens"]) {
      const res = await get(path, scoped);
      expect(res.status, path).toBe(403);
      const body = (await res.json()) as { error: string; message: string };
      expect(body.error).toBe("ACCESS_DENIED");
      expect(body.message).toContain(MESSAGE);
    }
    expect((await get("/api/v1/secrets", scoped)).status).toBe(200);
    expect((await get("/api/v1/agents", unscoped)).status).toBe(200);
  });

  it("REST: a project-claimed token cannot revoke an issued token — 403 ACCESS_DENIED and the token stays live", async () => {
    const res = await fetch(`${server.baseUrl}/api/v1/tokens/${scopedJti}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${scoped}` },
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);
    expect(vault.engine.isTokenRevoked(scopedJti)).toBe(false);
  });

  it("CLI: agent list and auth list refuse the same token, and admit the unscoped one", async () => {
    const opts = { vaultDir: vault.tmpDir };
    const agentList = await runCli(["agent", "list", "--token", scoped], opts);
    expect(agentList.code).toBe(1);
    expect(agentList.stderr).toContain(MESSAGE);
    const authList = await runCli(["auth", "list", "--token", scoped], opts);
    expect(authList.code).toBe(1);
    expect(authList.stderr).toContain(MESSAGE);
    const admitted = await runCli(["agent", "list", "--token", unscoped], opts);
    expect(admitted.code).toBe(0);
    expect(admitted.stdout).toContain("gov-admin");
  }, 60_000);

  // D4/R32: `access.denied` has existed since v1.0 with no product writer. The
  // governance refusal is its first: whichever layer answers — this middleware
  // at the REST edge, the engine assertion in direct mode — the trail carries
  // exactly one row naming the principal and the operation.
  it("REST: the 403 leaves one access.denied row naming the principal and the operation", async () => {
    const res = await get("/api/v1/agents/gov-admin", scoped);
    expect(res.status).toBe(403);

    const rows = vault.engine
      .queryAudit({ eventType: AuditEventType.ACCESS_DENIED })
      .filter((r) => r.detail?.operation === "GET /api/v1/agents/gov-admin");
    expect(rows).toHaveLength(1);
    const row = rows[0];
    expect(row?.success).toBe(false);
    expect(row?.principal_type).toBe("agent");
    expect(row?.principal_id).toBe("gov-admin");
    expect(row?.secret_id).toBeNull();
    expect(row?.detail).toMatchObject({
      error: ErrorCode.ACCESS_DENIED,
      reason: "governance",
      interface: "rest",
    });
    // The listener is loopback, so D9's peer normaliser is what makes a
    // dual-stack `::ffff:127.0.0.1` read as the dotted form here.
    expect(row?.ip_address).toBe("127.0.0.1");
  });
});

describe("Governance refuses a secrets-claimed admin token (S3)", () => {
  let vault: TestVault;
  let server: TestServer;
  let unscoped: string;
  let named: string;
  let starred: string;
  let namedUser: string;
  let victimJti: string;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "gov-admin", "matrix-target");
    await vault.engine.createSecret({
      name: "db-main",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("S3CRET-TOKEN-xyz")),
    });
    unscoped = vault.engine.createToken("gov-admin", ["admin"]);
    // Ten minutes, as above: three CLI spawns plus the REST calls.
    named = vault.engine.createToken("gov-admin", ["admin"], 600_000, { secrets: ["db-*"] });
    starred = vault.engine.createToken("gov-admin", ["admin"], 600_000, { secrets: ["*"] });
    namedUser = vault.engine.createToken("ops", ["admin"], 600_000, {
      secrets: ["db-*"],
      principalType: "user",
    });
    vault.engine.createToken("matrix-target", ["read"], 600_000);
    const rows = vault.engine.listIssuedTokens();
    victimJti = (rows.find((row) => row.subject === "matrix-target") as IssuedToken).jti;
    server = startTestServer(vault.engine);
  });

  afterAll(async () => {
    await server?.close();
    await destroyTestVault(vault);
  });

  async function get(path: string, token: string): Promise<Response> {
    return fetch(`${server.baseUrl}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  }

  it('REST: both governance groups answer 403 to a secrets: ["db-*"] and a secrets: ["*"] token, the secrets routes still 200', async () => {
    for (const token of [named, starred]) {
      for (const path of ["/api/v1/agents", "/api/v1/tokens"]) {
        const res = await get(path, token);
        expect(res.status, path).toBe(403);
        const body = (await res.json()) as { error: string; message: string };
        expect(body.error).toBe("ACCESS_DENIED");
        expect(body.message).toContain(MESSAGE);
      }
      expect((await get("/api/v1/secrets", token)).status).toBe(200);
    }
    expect((await get("/api/v1/agents", unscoped)).status).toBe(200);
  });

  it("REST: a secrets-claimed token cannot revoke another principal's token — 403 ACCESS_DENIED and that token stays live", async () => {
    const res = await fetch(`${server.baseUrl}/api/v1/tokens/${victimJti}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${named}` },
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);
    expect(vault.engine.isTokenRevoked(victimJti)).toBe(false);
  });

  // A user-type admin is exempt from per-secret grants (R7), so before S3 the
  // name-gated cell admitted this token and wrote the grant.
  it("REST: the permission-matrix cell refuses a name-scoped user admin token whose pattern matches the handle, and no grant is written", async () => {
    const res = await fetch(
      `${server.baseUrl}/api/v1/agents/matrix-target/secrets/db-main/permissions`,
      {
        method: "PUT",
        headers: { Authorization: `Bearer ${namedUser}`, "content-type": "application/json" },
        body: JSON.stringify({ permissions: ["read"] }),
      },
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);
    expect(vault.engine.listAgentPolicies("matrix-target")).toEqual([]);
  });

  it("CLI: agent list and auth list refuse a secrets-claimed token with one engine row each, and admit the unscoped one", async () => {
    const opts = { vaultDir: vault.tmpDir };
    const agentList = await runCli(["agent", "list", "--token", named], opts);
    expect(agentList.code).toBe(1);
    expect(agentList.stderr).toContain(MESSAGE);
    const authList = await runCli(["auth", "list", "--token", named], opts);
    expect(authList.code).toBe(1);
    expect(authList.stderr).toContain(MESSAGE);
    const admitted = await runCli(["agent", "list", "--token", unscoped], opts);
    expect(admitted.code).toBe(0);
    expect(admitted.stdout).toContain("gov-admin");

    const denied = vault.engine.queryAudit({ eventType: AuditEventType.ACCESS_DENIED });
    for (const operation of ["listAgents", "listIssuedTokens"]) {
      const rows = denied.filter(
        (r) => r.detail?.operation === operation && r.detail?.interface === "cli",
      );
      expect(rows, operation).toHaveLength(1);
      expect(rows[0]?.principal_id).toBe("gov-admin");
      expect(rows[0]?.detail).toMatchObject({
        error: ErrorCode.ACCESS_DENIED,
        reason: "governance",
      });
    }
  }, 60_000);

  it("REST: the 403 leaves one access.denied row naming the principal and the operation", async () => {
    const res = await get("/api/v1/agents/gov-admin", named);
    expect(res.status).toBe(403);

    const rows = vault.engine
      .queryAudit({ eventType: AuditEventType.ACCESS_DENIED })
      .filter((r) => r.detail?.operation === "GET /api/v1/agents/gov-admin");
    expect(rows).toHaveLength(1);
    const row = rows[0];
    expect(row?.success).toBe(false);
    expect(row?.principal_type).toBe("agent");
    expect(row?.principal_id).toBe("gov-admin");
    expect(row?.secret_id).toBeNull();
    expect(row?.detail).toMatchObject({
      error: ErrorCode.ACCESS_DENIED,
      reason: "governance",
      interface: "rest",
    });
    expect(row?.ip_address).toBe("127.0.0.1");
  });
});
