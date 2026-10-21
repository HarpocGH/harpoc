import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createApp } from "@harpoc/rest-api";
import { SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { silenceAuditLines } from "@harpoc/test-utils";

silenceAuditLines();

const PASSWORD = "audit-visibility-pw";

interface AuditRow {
  event_type: string;
  secret_id: string | null;
  detail?: Record<string, unknown> | null;
}

/**
 * L10 end-to-end over the real REST stack: the audit surface enforced only the
 * permission dimension of the 3-dimensional token scope, so a project- or
 * name-pattern-scoped admin token read audit detail — handles, principals,
 * configuration changes — for every secret in the vault, with `?secret_id=`
 * as a targeted oracle over the one surface that returns decrypted detail.
 */
describe("audit visibility scope end-to-end (L10)", () => {
  let vault: TestVault;
  let app: ReturnType<typeof createApp>;
  let dbId: string;
  let apiId: string;
  let billingId: string;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(
      vault.engine,
      "full-admin",
      "pattern-admin",
      "pattern-admin-2",
      "pattern-admin-3",
      "project-admin",
    );

    for (const [name, project] of [
      ["db-prod", undefined],
      ["api-key", undefined],
      ["billing", "finance"],
    ] as [string, string | undefined][]) {
      await vault.engine.createSecret({
        name,
        type: SecretType.API_KEY,
        project,
        value: new Uint8Array(Buffer.from(`${name}-value`)),
      });
    }
    dbId = await vault.engine.resolveSecretId("secret://db-prod");
    apiId = await vault.engine.resolveSecretId("secret://api-key");
    billingId = await vault.engine.resolveSecretId("secret://finance/billing");

    // Rows to be filtered: reads of each secret.
    await vault.engine.getSecretInfo("secret://db-prod");
    await vault.engine.getSecretInfo("secret://api-key");
    await vault.engine.getSecretInfo("secret://finance/billing");

    app = createApp(vault.engine);
  });

  afterAll(async () => {
    await destroyTestVault(vault);
  });

  async function readAudit(token: string, query = ""): Promise<AuditRow[]> {
    const res = await app.request(`/api/v1/audit${query}`, {
      headers: { authorization: `Bearer ${token}`, host: "localhost" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: AuditRow[] };
    return body.data;
  }

  it("a name-pattern-scoped admin token sees no rows about other secrets", async () => {
    const token = vault.engine.createToken("pattern-admin", ["admin"], undefined, {
      secrets: ["db-*"],
    });
    const ids = (await readAudit(token)).map((r) => r.secret_id);

    expect(ids).toContain(dbId);
    expect(ids).not.toContain(apiId);
    expect(ids).not.toContain(billingId);
  });

  it("the targeted secret_id oracle returns nothing for an out-of-scope secret", async () => {
    const token = vault.engine.createToken("pattern-admin-2", ["admin"], undefined, {
      secrets: ["db-*"],
    });
    expect(await readAudit(token, `?secret_id=${apiId}`)).toEqual([]);
    expect((await readAudit(token, `?secret_id=${dbId}`)).length).toBeGreaterThan(0);
  });

  it("a project-scoped admin token sees only its project's rows", async () => {
    const token = vault.engine.createToken("project-admin", ["admin"], undefined, {
      project: "finance",
    });
    const ids = (await readAudit(token)).map((r) => r.secret_id);

    expect(ids).toContain(billingId);
    expect(ids).not.toContain(dbId);
    expect(ids).not.toContain(apiId);
  });

  it("vault-level rows stay visible — they carry no per-secret metadata (D2)", async () => {
    const token = vault.engine.createToken("pattern-admin-3", ["admin"], undefined, {
      secrets: ["db-*"],
    });
    const rows = await readAudit(token);
    expect(rows.some((r) => r.event_type === "vault.unlock")).toBe(true);
  });

  it("control: an unrestricted admin token still sees every secret's rows", async () => {
    const token = vault.engine.createToken("full-admin", ["admin"]);
    const ids = (await readAudit(token)).map((r) => r.secret_id);

    expect(ids).toContain(dbId);
    expect(ids).toContain(apiId);
    expect(ids).toContain(billingId);
  });

  it("control: the audit chain is unaffected by the filtering", () => {
    expect(vault.engine.verifyAuditChain().valid).toBe(true);
  });
});

/**
 * S6 (review 2026-10-15) over the real REST stack: a failed row without a
 * `secret_id` can still name a handle in its detail — a D2g scope refusal's
 * operation, a resolution failure's handle, and until Q14 the failed re-revoke —
 * so a scoped reader no longer sees such rows; the re-revoke row carries the
 * secret's id and follows that secret's visibility.
 */
describe("failed rows that name an out-of-scope handle (S6, Q14)", () => {
  let vault: TestVault;
  let app: ReturnType<typeof createApp>;
  let hrId: string;
  let dbId: string;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    registerAgents(vault.engine, "db-admin", "pay-agent", "full-admin");
    for (const name of ["hr-salaries", "db-prod"]) {
      await vault.engine.createSecret({
        name,
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from("S3CRET-TOKEN-xyz")),
      });
    }
    hrId = await vault.engine.resolveSecretId("secret://hr-salaries");
    dbId = await vault.engine.resolveSecretId("secret://db-prod");
    app = createApp(vault.engine);

    const payToken = vault.engine.createToken("pay-agent", ["read"], undefined, {
      secrets: ["pay-*"],
    });
    expect((await request("GET", "/api/v1/secrets/hr-salaries/value", payToken)).status).toBe(403);

    const rootToken = vault.engine.createToken("root-admin", ["admin"], undefined, {
      principalType: "user",
    });
    expect(
      (await request("DELETE", "/api/v1/secrets/hr-salaries?confirm=true", rootToken)).status,
    ).toBe(200);
    expect(
      (await request("DELETE", "/api/v1/secrets/hr-salaries?confirm=true", rootToken)).status,
    ).toBe(410);
  });

  afterAll(async () => {
    await destroyTestVault(vault);
  });

  function request(method: string, path: string, token: string): Promise<Response> {
    return Promise.resolve(
      app.request(path, {
        method,
        headers: { authorization: `Bearer ${token}`, host: "localhost" },
      }),
    );
  }

  async function readAudit(token: string, query = ""): Promise<AuditRow[]> {
    const res = await request("GET", `/api/v1/audit${query}`, token);
    expect(res.status).toBe(200);
    return ((await res.json()) as { data: AuditRow[] }).data;
  }

  const namesHrSalaries = (row: AuditRow): boolean =>
    JSON.stringify(row.detail ?? {}).includes("hr-salaries");

  it("a name-pattern-scoped reader sees neither the refusal naming hr-salaries nor its failed re-revoke", async () => {
    const reader = vault.engine.createToken("db-admin", ["admin"], undefined, {
      secrets: ["db-*"],
    });
    const rows = await readAudit(reader);
    expect(rows.filter(namesHrSalaries)).toEqual([]);
    expect(rows.some((r) => r.event_type === "access.denied")).toBe(false);
    expect(rows.map((r) => r.secret_id)).toContain(dbId);
    expect(rows.some((r) => r.event_type === "vault.unlock")).toBe(true);
  });

  it("an unrestricted reader sees both rows, the failed re-revoke under the secret's id", async () => {
    const reader = vault.engine.createToken("full-admin", ["admin"]);
    const rows = await readAudit(reader);
    const refusal = rows.find((r) => r.event_type === "access.denied" && namesHrSalaries(r));
    expect(refusal?.secret_id).toBeNull();
    expect(refusal?.detail).toMatchObject({
      operation: "GET /api/v1/secrets/hr-salaries/value",
      reason: "secret",
    });
    const reRevoke = rows.find((r) => r.event_type === "secret.revoke" && r.detail?.error);
    expect(reRevoke?.secret_id).toBe(hrId);
    expect(reRevoke?.detail).toMatchObject({
      handle: "secret://hr-salaries",
      error: "SECRET_REVOKED",
    });
  });

  it("the unrestricted reader's per-secret read returns the failed re-revoke (Q14)", async () => {
    const reader = vault.engine.createToken("full-admin", ["admin"]);
    const rows = await readAudit(reader, `?secret_id=${hrId}`);
    expect(
      rows.filter((r) => r.event_type === "secret.revoke").map((r) => r.detail?.error),
    ).toEqual(["SECRET_REVOKED", undefined]);
  });

  it("unchanged: the scoped reader's targeted read of the out-of-scope id still answers nothing", async () => {
    const reader = vault.engine.createToken("db-admin", ["admin"], undefined, {
      secrets: ["db-*"],
    });
    expect(await readAudit(reader, `?secret_id=${hrId}`)).toEqual([]);
  });
});
