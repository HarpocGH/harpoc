import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { vi } from "vitest";
import type { CallerContext, Permission, PrincipalType } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType, VaultError } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";

/**
 * W2 — `list` as live policy vocabulary: enumeration is filtered by the
 * secret's own policies, so a read-gated secret's metadata row cannot be
 * recovered from a listing. Same presence-gated semantics as V1's point
 * checks, evaluated in batch.
 */

vi.mock("./crypto/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array) => {
      const { createHash } = await import("node:crypto");
      return new Uint8Array(createHash("sha256").update(password).update(salt).digest());
    },
  };
});

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

/**
 * Register the agent identities this suite mints tokens or grants for — the
 * v1.4 registration gate refuses an unregistered agent-typed principal.
 */
function registerAgents(...names: string[]): void {
  for (const name of names) {
    try {
      engine.registerAgent({ name });
    } catch (err) {
      if (!(err instanceof VaultError) || err.code !== ErrorCode.AGENT_EXISTS) throw err;
    }
  }
}

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
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
  if (principalType === "agent") registerAgents(principalId);
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

describe("presence gate", () => {
  it("a vault without policy rows enumerates fully for a token caller", async () => {
    await makeSecret("alpha");
    await makeSecret("beta");

    expect(listedNames(agent("anyone"))).toEqual(["alpha", "beta"]);
  });

  it("only the secrets carrying rows are restricted — the rest stay visible", async () => {
    const gated = await makeSecret("gated");
    await makeSecret("open");
    grant(gated, "agent", "alice", ["use"]);

    expect(listedNames(agent("bob"))).toEqual(["open"]);
    expect(listedNames(agent("alice"))).toEqual(["open"]);
  });

  it("expired rows count for nothing — neither grant nor presence", async () => {
    const id = await makeSecret("expired-rows");
    grant(id, "agent", "alice", ["list"], Date.now() - 1000);

    expect(listedNames(agent("bob"))).toEqual(["expired-rows"]);
  });

  it("revoking the last row reopens enumeration", async () => {
    const id = await makeSecret("reopen");
    registerAgents("alice");
    const policy = engine.grantPolicy(
      { secretId: id, principalType: "agent", principalId: "alice", permissions: ["use"] },
      "test-admin",
    );
    expect(listedNames(agent("bob"))).toEqual([]);

    engine.revokePolicy(policy.id);
    expect(listedNames(agent("bob"))).toEqual(["reopen"]);
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

    expect(listedNames(agent("alice"), "api")).toEqual(["api-key", "api-open"]);
    expect(listedNames(agent("bob"), "api")).toEqual(["api-open"]);
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

  it("a hidden row is also denied by the point check when no permission is granted", async () => {
    const id = await makeSecret("hidden");
    grant(id, "agent", "alice", ["use"]);

    expect(listedNames(agent("mallory"))).toEqual([]);
    await expect(engine.getSecretInfo("secret://hidden", agent("mallory"))).rejects.toMatchObject({
      code: ErrorCode.ACCESS_DENIED,
    });
  });
});

describe("audit", () => {
  it("filtering is silent — a restricted enumeration writes no audit row", async () => {
    const id = await makeSecret("quiet");
    grant(id, "agent", "alice", ["use"]);

    const before = engine.queryAudit({}).length;
    expect(listedNames(agent("mallory"))).toEqual([]);
    expect(listedNames(agent("alice"))).toEqual([]);
    expect(engine.queryAudit({}).length).toBe(before);
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

describe("grantPolicy refuses `create`", () => {
  it("rejects a permissions array containing create", async () => {
    const id = await makeSecret("no-create");

    expect(() =>
      engine.grantPolicy(
        { secretId: id, principalType: "agent", principalId: "alice", permissions: ["create"] },
        "test-admin",
      ),
    ).toThrow(VaultError);

    try {
      engine.grantPolicy(
        {
          secretId: id,
          principalType: "agent",
          principalId: "alice",
          permissions: ["read", "create"],
        },
        "test-admin",
      );
      expect.fail("expected INVALID_INPUT");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_INPUT);
    }

    // Nothing written: the secret stays ungated.
    expect(engine.listPolicies(id)).toHaveLength(0);
    expect(listedNames(agent("anyone"))).toEqual(["no-create"]);
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

    expect(() =>
      engine.grantPolicy(
        { secretId: id, principalType: "agent", principalId: "alice", permissions: ["create"] },
        "test-admin",
      ),
    ).toThrow();

    expect(engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT }).length).toBe(before);
  });
});
