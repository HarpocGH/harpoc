import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { IssuedToken } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startTestServer } from "./helpers/rest-helpers.js";
import type { TestServer } from "./helpers/rest-helpers.js";
import { runCli } from "./helpers/spawn-cli.js";

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
    await destroyTestVault(vault).catch(() => {});
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

  it("REST: a project-claimed token cannot revoke a token it can see in the audit trail", async () => {
    const res = await fetch(`${server.baseUrl}/api/v1/tokens/${scopedJti}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${scoped}` },
    });
    expect(res.status).toBe(403);
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
      interface: "rest",
    });
    // The listener is loopback, so D9's peer normaliser is what makes a
    // dual-stack `::ffff:127.0.0.1` read as the dotted form here.
    expect(row?.ip_address).toBe("127.0.0.1");
  });
});
