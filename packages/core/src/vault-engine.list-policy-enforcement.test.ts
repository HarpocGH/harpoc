import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { vi } from "vitest";
import type { CallerContext, Permission, PrincipalType } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { DecryptedAuditEvent } from "./audit/audit-query.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";
import { nonReadAuditCount, registerAgents } from "./__fixtures__/engine-seams.js";

/**
 * W2 — `list` as live policy vocabulary: enumeration is filtered by the
 * secret's own policies, so a read-gated secret's metadata row cannot be
 * recovered from a listing. Same explicit-grant semantics as V1's point
 * checks (R1, 2026-09-01), evaluated in batch.
 */

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let engine: VaultEngine;

const VALUE = new Uint8Array(Buffer.from("super-secret-value", "utf8"));

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-lpe-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function agent(id: string, project?: string): CallerContext {
  const caller: CallerContext = { principal_type: "agent", principal_id: id };
  if (project) caller.project = project;
  return caller;
}

async function makeSecret(name: string, project?: string): Promise<string> {
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    project,
    value: new Uint8Array(VALUE),
  });
  return engine.resolveSecretId(project ? `secret://${project}/${name}` : `secret://${name}`);
}

function grant(
  secretId: string,
  principalType: PrincipalType,
  principalId: string,
  permissions: Permission[],
  expiresAt?: number,
): void {
  if (principalType === "agent") registerAgents(engine, principalId);
  engine.grantPolicy(
    { secretId, principalType, principalId, permissions, expiresAt },
    "test-admin",
  );
}

function listedNames(caller?: CallerContext, project?: string): string[] {
  return engine
    .listSecrets(project, caller)
    .map((s) => s.name)
    .sort();
}

function listingRows(): DecryptedAuditEvent[] {
  return engine
    .queryAudit({ eventType: AuditEventType.VAULT_READ })
    .filter((row) => row.detail?.operation === "list_secrets");
}

describe("explicit grant (R1)", () => {
  it("a vault without policy rows enumerates nothing for a token caller", async () => {
    await makeSecret("alpha");
    await makeSecret("beta");

    expect(listedNames(agent("anyone"))).toEqual([]);
    expect(listedNames()).toEqual(["alpha", "beta"]);
  });

  it("only a list or admin grant makes a secret enumerable — rows for other permissions do not", async () => {
    const gated = await makeSecret("gated");
    await makeSecret("open");
    grant(gated, "agent", "alice", ["use"]);

    expect(listedNames(agent("bob"))).toEqual([]);
    expect(listedNames(agent("alice"))).toEqual([]);
  });

  it("expired rows count for nothing", async () => {
    const id = await makeSecret("expired-rows");
    grant(id, "agent", "alice", ["list"], Date.now() - 1000);

    expect(listedNames(agent("alice"))).toEqual([]);
  });

  it("revoking the last row closes enumeration", async () => {
    const id = await makeSecret("reopen");
    registerAgents(engine, "alice");
    const policy = engine.grantPolicy(
      { secretId: id, principalType: "agent", principalId: "alice", permissions: ["list"] },
      "test-admin",
    );
    expect(listedNames(agent("alice"))).toEqual(["reopen"]);

    engine.revokePolicy(policy.id);
    expect(listedNames(agent("alice"))).toEqual([]);
  });
});

describe("permission granularity", () => {
  it("a `list` grant reveals the row", async () => {
    const id = await makeSecret("db-prod");
    grant(id, "agent", "alice", ["list"]);

    expect(listedNames(agent("alice"))).toEqual(["db-prod"]);
  });

  it("a `use`-only grant does NOT reveal the row — the strict D2 rule", async () => {
    const id = await makeSecret("db-prod");
    grant(id, "agent", "alice", ["use"]);

    expect(listedNames(agent("alice"))).toEqual([]);
  });

  it("a `read`-only grant does not reveal the row either", async () => {
    const id = await makeSecret("db-prod");
    grant(id, "agent", "alice", ["read"]);

    // The point check opens for `read`…
    await expect(engine.getSecretInfo("secret://db-prod", agent("alice"))).resolves.toMatchObject({
      name: "db-prod",
    });
    // …but enumeration is governed by `list` alone.
    expect(listedNames(agent("alice"))).toEqual([]);
  });

  it("`admin` implies enumeration", async () => {
    const id = await makeSecret("db-prod");
    grant(id, "agent", "alice", ["admin"]);

    expect(listedNames(agent("alice"))).toEqual(["db-prod"]);
  });

  it("the grant is per principal — another agent stays blind", async () => {
    const id = await makeSecret("db-prod");
    grant(id, "agent", "alice", ["list"]);

    expect(listedNames(agent("mallory"))).toEqual([]);
  });

  it("principal type is load-bearing: a tool grant does not admit the agent of the same name", async () => {
    const id = await makeSecret("db-prod");
    grant(id, "tool", "alice", ["list"]);

    expect(listedNames(agent("alice"))).toEqual([]);
    expect(listedNames({ principal_type: "tool", principal_id: "alice" })).toEqual(["db-prod"]);
  });
});

describe("project principal derivation", () => {
  it("a (project, api) grant reveals the row to every caller carrying that project", async () => {
    const id = await makeSecret("api-key", "api");
    grant(id, "project", "api", ["list"]);

    expect(listedNames(agent("any-agent", "api"))).toEqual(["api-key"]);
    expect(listedNames(agent("any-agent"))).toEqual([]);
  });

  it("name collision negative control: an agent named like the project is not the project", async () => {
    const id = await makeSecret("api-key", "api");
    grant(id, "project", "api", ["list"]);

    expect(listedNames(agent("api"))).toEqual([]);
  });

  it("the project filter and the policy filter compose", async () => {
    const gated = await makeSecret("api-key", "api");
    await makeSecret("api-open", "api");
    await makeSecret("other", "web");
    grant(gated, "agent", "alice", ["list"]);

    expect(listedNames(agent("alice"), "api")).toEqual(["api-key"]);
    expect(listedNames(agent("bob"), "api")).toEqual([]);
  });
});

describe("trusted local path", () => {
  it("no caller ⇒ the full listing, even on a fully gated vault", async () => {
    const a = await makeSecret("alpha");
    const b = await makeSecret("beta");
    grant(a, "agent", "alice", ["use"]);
    grant(b, "tool", "ci", ["read"]);

    expect(listedNames()).toEqual(["alpha", "beta"]);
  });
});

describe("filter/gate agreement (shared principal set)", () => {
  it("every principal shape that opens the point check also reveals the row", async () => {
    const bySubject = await makeSecret("by-subject");
    const byProject = await makeSecret("by-project", "api");
    const byAdmin = await makeSecret("by-admin");

    grant(bySubject, "agent", "alice", ["list", "read"]);
    grant(byProject, "project", "api", ["list", "read"]);
    grant(byAdmin, "agent", "alice", ["admin"]);

    const alice = agent("alice");
    const aliceInApi = agent("alice", "api");

    await expect(engine.getSecretInfo("secret://by-subject", alice)).resolves.toBeDefined();
    expect(listedNames(alice)).toContain("by-subject");

    await expect(
      engine.getSecretInfo("secret://api/by-project", aliceInApi),
    ).resolves.toBeDefined();
    expect(listedNames(aliceInApi)).toContain("by-project");

    await expect(engine.getSecretInfo("secret://by-admin", alice)).resolves.toBeDefined();
    expect(listedNames(alice)).toContain("by-admin");
  });

  it("a hidden row is also concealed by the point check (SECRET_NOT_FOUND) when no permission is granted", async () => {
    const id = await makeSecret("hidden");
    grant(id, "agent", "alice", ["use"]);

    expect(listedNames(agent("mallory"))).toEqual([]);
    await expect(engine.getSecretInfo("secret://hidden", agent("mallory"))).rejects.toMatchObject({
      code: ErrorCode.SECRET_NOT_FOUND,
    });
  });
});

describe("audit", () => {
  it("a restricted enumeration writes one vault.read row a listing, the filtered secret counted as withheld, and no other row", async () => {
    const id = await makeSecret("quiet");
    grant(id, "agent", "alice", ["use"]);

    const before = nonReadAuditCount(engine);
    expect(listedNames(agent("mallory"))).toEqual([]);
    expect(listedNames(agent("alice"))).toEqual([]);
    expect(nonReadAuditCount(engine)).toBe(before);
    expect(listingRows().map((row) => [row.principal_id, row.detail])).toEqual([
      ["alice", { operation: "list_secrets", count: 0, withheld: 1 }],
      ["mallory", { operation: "list_secrets", count: 0, withheld: 1 }],
    ]);
  });

  it("the audit chain stays valid across a mixed sequence", async () => {
    const id = await makeSecret("chain-mix");
    grant(id, "agent", "alice", ["list"]);
    listedNames(agent("alice"));
    listedNames(agent("mallory"));
    await engine.getSecretInfo("secret://chain-mix", agent("alice")).catch(() => undefined);

    expect(engine.verifyAuditChain().valid).toBe(true);
  });
});

describe("the listing's vault.read row (A4)", () => {
  const NAMES = ["ledger", "payroll", "invoices", "budget", "forecast"];
  const LISTER: CallerContext = {
    principal_type: "agent",
    principal_id: "alice",
    interface: "rest",
    remote_address: "127.0.0.1",
  };
  const OPERATOR: CallerContext = {
    principal_type: "user",
    principal_id: "operator",
    interface: "rest",
    admin_scope: true,
  };

  function liveStore(): SqliteStore {
    return (engine as unknown as { store: SqliteStore }).store;
  }

  it("a token with two of five grants: one row after the read — count 2, withheld 3, the caller's principal — naming no secret", async () => {
    const ids: string[] = [];
    for (const name of NAMES) ids.push(await makeSecret(name));
    grant(ids[0] as string, "agent", "alice", ["list"]);
    grant(ids[3] as string, "agent", "alice", ["admin"]);
    const before = nonReadAuditCount(engine);

    const listed = engine.listSecrets(undefined, LISTER);

    expect(listed.map((s) => s.name).sort()).toEqual(["budget", "ledger"]);
    expect(nonReadAuditCount(engine)).toBe(before);
    const rows = listingRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      event_type: AuditEventType.VAULT_READ,
      secret_id: null,
      principal_type: "agent",
      principal_id: "alice",
      ip_address: "127.0.0.1",
      success: true,
    });
    expect(rows[0]?.detail).toEqual({
      operation: "list_secrets",
      count: 2,
      withheld: 3,
      interface: "rest",
    });
    for (const name of NAMES) {
      expect(JSON.stringify(rows[0]?.detail).includes(name)).toBe(false);
    }
  });

  it("a project filter the vault holds is recorded verbatim, count and withheld taken within that project", async () => {
    const granted = await makeSecret("ledger", "finance");
    await makeSecret("payroll", "finance");
    await makeSecret("forecast");
    grant(granted, "agent", "alice", ["list"]);

    expect(listedNames(LISTER, "finance")).toEqual(["ledger"]);

    const [row] = listingRows();
    expect(row?.detail).toEqual({
      operation: "list_secrets",
      project: "finance",
      count: 1,
      withheld: 1,
      interface: "rest",
    });
    for (const name of ["ledger", "payroll", "forecast"]) {
      expect(JSON.stringify(row?.detail).includes(name)).toBe(false);
    }
  });

  it("a project the vault does not hold is recorded as its presence only; a held project stays verbatim though the filter withholds all of it (TW-R1)", async () => {
    const typed = "typed-not-held-7c1";
    await makeSecret("ledger", "finance");

    expect(listedNames(LISTER, typed)).toEqual([]);
    expect(listedNames(LISTER, "finance")).toEqual([]);

    const [held, unheld] = listingRows();
    expect(JSON.stringify(unheld?.detail).includes(typed)).toBe(false);
    expect(unheld?.detail).toEqual({
      operation: "list_secrets",
      project: true,
      count: 0,
      withheld: 0,
      interface: "rest",
    });
    expect(held?.detail).toEqual({
      operation: "list_secrets",
      project: "finance",
      count: 0,
      withheld: 1,
      interface: "rest",
    });
  });

  it("a caller the filter does not apply to records withheld 0: the trusted path with NULL principal columns and no interface key, an admin-scoped user token with its own", async () => {
    const id = await makeSecret("ledger");
    await makeSecret("payroll");
    grant(id, "agent", "alice", ["use"]);

    expect(listedNames()).toEqual(["ledger", "payroll"]);
    expect(listedNames(OPERATOR)).toEqual(["ledger", "payroll"]);

    expect(listingRows().map((row) => [row.principal_type, row.principal_id, row.detail])).toEqual([
      ["user", "operator", { operation: "list_secrets", count: 2, withheld: 0, interface: "rest" }],
      [null, null, { operation: "list_secrets", count: 2, withheld: 0 }],
    ]);
  });

  it.each([
    ["a token caller", LISTER],
    ["the trusted path", undefined],
  ])(
    "for %s the listing throws the logger's error and returns nothing when its row cannot be written",
    async (_label, caller) => {
      const id = await makeSecret("ledger");
      grant(id, "agent", "alice", ["list"]);
      const before = listingRows().length;
      vi.spyOn(liveStore(), "insertAuditEvent").mockImplementationOnce(() => {
        throw new Error("audit unavailable");
      });

      let answer: unknown;
      expect(() => {
        answer = engine.listSecrets(undefined, caller);
      }).toThrow("audit unavailable");
      expect(answer).toBeUndefined();
      expect(listingRows()).toHaveLength(before);
    },
  );

  it("a caller of one project lists; an admin scoped to another project finds no vault.read row on the trail, an unscoped read finds it (A-2)", async () => {
    const id = await makeSecret("ledger", "finance");
    grant(id, "project", "finance", ["list"]);
    const financeAgent: CallerContext = {
      principal_type: "agent",
      principal_id: "fin-bot",
      project: "finance",
      interface: "rest",
    };
    const webAdmin: CallerContext = {
      principal_type: "agent",
      principal_id: "web-admin",
      project: "web",
      admin_scope: true,
      interface: "rest",
    };

    expect(listedNames(financeAgent, "finance")).toEqual(["ledger"]);

    const scoped = engine.queryAudit({}, { project: "web" }, webAdmin);
    expect(scoped.length).toBeGreaterThan(0);
    expect(scoped.filter((row) => row.event_type === AuditEventType.VAULT_READ)).toEqual([]);
    const unscoped = engine.queryAudit({}, undefined, OPERATOR);
    const listings = unscoped.filter((row) => row.detail?.operation === "list_secrets");
    expect(listings.map((row) => [row.principal_id, row.detail])).toEqual([
      [
        "fin-bot",
        {
          operation: "list_secrets",
          project: "finance",
          count: 1,
          withheld: 0,
          interface: "rest",
        },
      ],
    ]);
  });
});

describe("grantPolicy refuses `create`", () => {
  it("rejects a permissions array containing create", async () => {
    const id = await makeSecret("no-create");

    await expectVaultError(
      () =>
        engine.grantPolicy(
          { secretId: id, principalType: "agent", principalId: "alice", permissions: ["create"] },
          "test-admin",
        ),
      ErrorCode.INVALID_INPUT,
    );

    await expectVaultError(
      () =>
        engine.grantPolicy(
          {
            secretId: id,
            principalType: "agent",
            principalId: "alice",
            permissions: ["read", "create"],
          },
          "test-admin",
        ),
      ErrorCode.INVALID_INPUT,
    );

    // Nothing written: the secret stays closed to every token caller.
    expect(engine.listPolicies(id)).toHaveLength(0);
    expect(listedNames(agent("anyone"))).toEqual([]);
  });

  it("still accepts the six per-secret permissions", async () => {
    const id = await makeSecret("six-perms");

    expect(() =>
      grant(id, "agent", "alice", ["list", "read", "use", "rotate", "revoke", "admin"]),
    ).not.toThrow();
    expect(engine.listPolicies(id)).toHaveLength(1);
  });

  it("the refusal is not audited as a grant", async () => {
    const id = await makeSecret("refused-grant");
    const before = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT }).length;

    await expectVaultError(
      () =>
        engine.grantPolicy(
          { secretId: id, principalType: "agent", principalId: "alice", permissions: ["create"] },
          "test-admin",
        ),
      ErrorCode.INVALID_INPUT,
    );

    expect(engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT }).length).toBe(before);
  });
});
