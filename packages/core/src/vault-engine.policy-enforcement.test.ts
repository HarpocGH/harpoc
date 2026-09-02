import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { vi } from "vitest";
import type { CallerContext, Permission, PrincipalType } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType, VaultError } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";

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
  tempDir = join(tmpdir(), `harpoc-pe-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

async function makeSecret(name: string, withValue = true): Promise<string> {
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    value: withValue ? new Uint8Array(VALUE) : undefined,
  });
  return engine.resolveSecretId(`secret://${name}`);
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

async function expectDenied(promise: Promise<unknown>): Promise<void> {
  await expectVaultError(() => promise, ErrorCode.ACCESS_DENIED);
}

async function expectNotFound(promise: Promise<unknown>): Promise<VaultError> {
  return expectVaultError(() => promise, ErrorCode.SECRET_NOT_FOUND);
}

/** A use action that, once past the policy gate, fails deterministically at the
 *  fail-safe command allowlist — no network, no spawn. Gate open ⇒
 *  COMMAND_NOT_ALLOWED; gate closed ⇒ SECRET_NOT_FOUND, or ACCESS_DENIED for a
 *  caller that holds `read` or `list` (R5). */
const PROCESS_ACTION = {
  type: "process",
  command: "definitely-not-allowlisted",
  env_var: "SECRET",
} as const;

async function expectGateOpenOnUse(handle: string, caller?: CallerContext): Promise<void> {
  await expectVaultError(
    () => engine.useSecret(handle, PROCESS_ACTION, caller),
    ErrorCode.COMMAND_NOT_ALLOWED,
  );
}

describe("explicit grant (R1)", () => {
  it("a secret without policy rows refuses every op for a token caller — as not-found on the wire", async () => {
    await makeSecret("open-secret");
    const caller = agent("anyone");

    await expectNotFound(engine.getSecretInfo("secret://open-secret", caller));
    await expectNotFound(engine.getSecretValue("secret://open-secret", caller));
    await expectNotFound(engine.useSecret("secret://open-secret", PROCESS_ACTION, caller));
    await expectNotFound(
      engine.setSecretValue("secret://open-secret", new Uint8Array([1]), caller),
    );
    await expectNotFound(engine.rotateSecret("secret://open-secret", new Uint8Array([2]), caller));
    await expectNotFound(engine.revokeSecret("secret://open-secret", caller));
  });

  it("rows that are all expired leave the secret closed", async () => {
    const id = await makeSecret("stale-gate");
    grant(id, "agent", "alice", ["use"], Date.now() - 1000);

    await expectNotFound(engine.getSecretValue("secret://stale-gate", agent("bob")));
    await expectNotFound(engine.getSecretValue("secret://stale-gate", agent("alice")));
  });

  it("an expired grant beside another principal's live row does not grant", async () => {
    const id = await makeSecret("mixed-gate");
    grant(id, "agent", "alice", ["read"], Date.now() - 1000);
    grant(id, "agent", "bob", ["read"]);

    await expectNotFound(engine.getSecretValue("secret://mixed-gate", agent("alice")));
    await expect(engine.getSecretValue("secret://mixed-gate", agent("bob"))).resolves.toEqual(
      VALUE,
    );
  });
});

describe("grant matching", () => {
  it("grants the matching principal and denies others (use)", async () => {
    const id = await makeSecret("gated");
    grant(id, "agent", "alice", ["use"]);

    await expectGateOpenOnUse("secret://gated", agent("alice"));
    await expectNotFound(engine.useSecret("secret://gated", PROCESS_ACTION, agent("bob")));
  });

  it("permissions are granular — a use grant confers nothing else", async () => {
    const id = await makeSecret("use-only");
    grant(id, "agent", "alice", ["use"]);
    const alice = agent("alice");

    await expectNotFound(engine.getSecretInfo("secret://use-only", alice));
    await expectNotFound(engine.getSecretValue("secret://use-only", alice));
    await expectNotFound(engine.rotateSecret("secret://use-only", new Uint8Array([1]), alice));
    await expectNotFound(engine.setSecretValue("secret://use-only", new Uint8Array([1]), alice));
    await expectNotFound(engine.revokeSecret("secret://use-only", alice));
    await expectGateOpenOnUse("secret://use-only", alice);
  });

  it("a read grant opens info and value but not use", async () => {
    const id = await makeSecret("read-only");
    grant(id, "agent", "alice", ["read"]);
    const alice = agent("alice");

    await expect(engine.getSecretInfo("secret://read-only", alice)).resolves.toBeDefined();
    await expect(engine.getSecretValue("secret://read-only", alice)).resolves.toEqual(VALUE);
    await expectDenied(engine.useSecret("secret://read-only", PROCESS_ACTION, alice));
  });

  it("admin implies every permission", async () => {
    const id = await makeSecret("admin-all");
    grant(id, "agent", "root", ["admin"]);
    const root = agent("root");

    await expect(engine.getSecretInfo("secret://admin-all", root)).resolves.toBeDefined();
    await expect(engine.getSecretValue("secret://admin-all", root)).resolves.toEqual(VALUE);
    await expectGateOpenOnUse("secret://admin-all", root);
    // Gate open under admin ⇒ set_value reaches the manager's ACTIVE-state
    // rejection (INVALID_INPUT), not ACCESS_DENIED.
    await expect(
      engine.setSecretValue("secret://admin-all", new Uint8Array([1]), root),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
    await expect(
      engine.rotateSecret("secret://admin-all", new Uint8Array([2]), root),
    ).resolves.toBeUndefined();
    await expect(engine.revokeSecret("secret://admin-all", root)).resolves.toBeUndefined();
  });

  it("principal type is load-bearing — a tool grant does not match an agent of the same id", async () => {
    const id = await makeSecret("typed");
    grant(id, "tool", "ci", ["use"]);

    await expectNotFound(
      engine.useSecret("secret://typed", PROCESS_ACTION, {
        principal_type: "agent",
        principal_id: "ci",
      }),
    );
    await expectGateOpenOnUse("secret://typed", { principal_type: "tool", principal_id: "ci" });
  });

  it("a project grant matches via the token's project claim, never via the subject name", async () => {
    const id = await makeSecret("proj-gated");
    grant(id, "project", "api", ["read"]);

    await expect(
      engine.getSecretValue("secret://proj-gated", agent("charlie", "api")),
    ).resolves.toEqual(VALUE);
    await expectNotFound(engine.getSecretValue("secret://proj-gated", agent("charlie")));
    // An agent whose *name* collides with the project id gains nothing.
    await expectNotFound(engine.getSecretValue("secret://proj-gated", agent("api")));
  });
});

describe("trusted local path", () => {
  it("an absent caller is never policy-checked, even with live gating rows", async () => {
    const id = await makeSecret("locked-down");
    grant(id, "agent", "alice", ["use"]);

    await expect(engine.getSecretValue("secret://locked-down")).resolves.toEqual(VALUE);
    await expect(engine.getSecretInfo("secret://locked-down")).resolves.toBeDefined();
    await expect(
      engine.rotateSecret("secret://locked-down", new Uint8Array([1])),
    ).resolves.toBeUndefined();
  });
});

describe("denial ordering", () => {
  it("use denial fires before value resolution — a valueless (pending) secret still refuses, as not-found for a caller without read", async () => {
    const id = await makeSecret("pending-gated", false);
    grant(id, "agent", "alice", ["use"]);

    await expectNotFound(engine.useSecret("secret://pending-gated", PROCESS_ACTION, agent("bob")));
  });

  it("use denial fires before the injection policy is evaluated", async () => {
    const id = await makeSecret("order-pin");
    grant(id, "agent", "alice", ["use"]);

    // Gate closed ⇒ SECRET_NOT_FOUND for a caller holding nothing; had the
    // injector run first, the empty fail-safe command allowlist would have
    // produced COMMAND_NOT_ALLOWED.
    await expectNotFound(engine.useSecret("secret://order-pin", PROCESS_ACTION, agent("bob")));
  });
});

describe("audit attribution", () => {
  it("a policy denial writes the op event with success:false, principal columns and required_permission — and tells the caller not-found", async () => {
    const id = await makeSecret("audit-deny");
    grant(id, "agent", "alice", ["use"]);

    const err = await expectNotFound(
      engine.useSecret("secret://audit-deny", PROCESS_ACTION, agent("mallory")),
    );
    expect(err.message).toBe("Secret not found: secret://audit-deny");

    const rows = engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId: id });
    const denial = rows.find((r) => !r.success);
    expect(denial).toBeDefined();
    expect(denial?.principal_type).toBe("agent");
    expect(denial?.principal_id).toBe("mallory");
    expect(denial?.detail?.required_permission).toBe("use");
    expect(denial?.detail?.error).toBe(ErrorCode.ACCESS_DENIED);
  });

  it("caller-attributed successes stamp principal columns; local rows stay null", async () => {
    const id = await makeSecret("audit-attr");
    grant(id, "agent", "alice", ["read"]);

    await engine.getSecretValue("secret://audit-attr", agent("alice"));
    await engine.getSecretValue("secret://audit-attr");

    const rows = engine.queryAudit({ eventType: AuditEventType.SECRET_READ });
    const forSecret = rows.filter((r) => r.detail?.handle === "secret://audit-attr" && r.success);
    const attributed = forSecret.filter((r) => r.principal_id === "alice");
    const local = forSecret.filter((r) => r.principal_id === null);
    expect(attributed).toHaveLength(1);
    expect(attributed[0]?.principal_type).toBe("agent");
    expect(local.length).toBeGreaterThanOrEqual(1);
    expect(id).toBeTruthy();
  });

  it("the audit HMAC chain stays valid across a mixed grant/denial/success sequence", async () => {
    const id = await makeSecret("chain-mix");
    grant(id, "agent", "alice", ["read", "use"]);
    await engine.getSecretValue("secret://chain-mix", agent("alice"));
    await expectNotFound(engine.getSecretValue("secret://chain-mix", agent("eve")));
    await expectNotFound(
      engine.rotateSecret("secret://chain-mix", new Uint8Array([1]), agent("eve")),
    );

    const report = engine.verifyAuditChain();
    expect(report.valid).toBe(true);
  });
});

describe("createToken principal_type claim", () => {
  it("embeds a valid principal type and audits it", async () => {
    const token = engine.createToken("ci", ["use"], 60_000, { principalType: "tool" });
    expect(engine.verifyToken(token).principal_type).toBe("tool");

    const rows = engine.queryAudit({ eventType: AuditEventType.TOKEN_CREATE });
    expect(rows.at(-1)?.detail?.principal_type).toBe("tool");
  });

  it("no option → the claim is minted as agent, audited as agent", async () => {
    registerAgents("legacy");
    const token = engine.createToken("legacy", ["use"], 60_000);
    const payload = engine.verifyToken(token);
    expect(payload.principal_type).toBe("agent");

    const rows = engine.queryAudit({ eventType: AuditEventType.TOKEN_CREATE });
    expect(rows.at(-1)?.detail?.principal_type).toBe("agent");
  });

  it("rejects a non-issuable principal type before signing", () => {
    expect(() =>
      engine.createToken("x", ["use"], 60_000, {
        principalType: "project" as unknown as "agent",
      }),
    ).toThrowError(expect.objectContaining({ code: ErrorCode.INVALID_INPUT }) as unknown as Error);
  });
});

describe("existence oracle (R5)", () => {
  it("the not-found refusal is byte-identical to an unknown handle's", async () => {
    const id = await makeSecret("real-key");
    grant(id, "agent", "alice", ["use"]);

    const concealed = await expectNotFound(
      engine.getSecretValue("secret://real-key", agent("eve")),
    );
    const unknown = await expectNotFound(
      engine.getSecretValue("secret://no-such-key", agent("eve")),
    );
    expect(concealed.message).toBe("Secret not found: secret://real-key");
    expect(unknown.message).toBe("Secret not found: secret://no-such-key");
    expect(concealed.message.replace("real-key", "X")).toBe(
      unknown.message.replace("no-such-key", "X"),
    );
  });

  it("a caller holding read but not use is told which permission it lacks", async () => {
    const id = await makeSecret("read-only");
    grant(id, "agent", "alice", ["read"]);

    const err = await expectVaultError(
      () => engine.useSecret("secret://read-only", PROCESS_ACTION, agent("alice")),
      ErrorCode.ACCESS_DENIED,
    );
    expect(err.message).toBe("Access denied: Principal lacks 'use' permission on this secret");
  });

  it("a caller holding list but not read is told which permission it lacks", async () => {
    const id = await makeSecret("list-only");
    grant(id, "agent", "alice", ["list"]);
    await expectDenied(engine.getSecretValue("secret://list-only", agent("alice")));
  });

  it("an admin check on a zero-row secret stays ACCESS_DENIED — the matrix remedy survives", async () => {
    const id = await makeSecret("fresh");
    registerAgents("mallory", "target");
    const err = await expectVaultError(
      () =>
        Promise.resolve().then(() =>
          engine.grantPolicy(
            {
              secretId: id,
              principalType: "agent",
              principalId: "target",
              permissions: ["use"],
            },
            "mallory",
            agent("mallory"),
          ),
        ),
      ErrorCode.ACCESS_DENIED,
    );
    expect(err.message).toBe("Access denied: Principal lacks 'admin' permission on this secret");
    expect(engine.listPolicies(id)).toHaveLength(0);
  });

  it("the audit row keeps the real secret id under the concealed refusal", async () => {
    const id = await makeSecret("hidden-id");
    await expectNotFound(engine.getSecretInfo("secret://hidden-id", agent("eve")));
    const rows = engine.queryAudit({ eventType: AuditEventType.SECRET_READ, secretId: id });
    expect(rows.some((r) => !r.success && r.detail?.error === ErrorCode.ACCESS_DENIED)).toBe(true);
  });
});
