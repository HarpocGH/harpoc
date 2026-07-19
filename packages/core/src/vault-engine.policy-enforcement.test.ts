import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { vi } from "vitest";
import type { CallerContext, Permission, PrincipalType } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType, VaultError } from "@harpoc/shared";
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
  engine.grantPolicy(
    { secretId, principalType, principalId, permissions, expiresAt },
    "test-admin",
  );
}

async function expectDenied(promise: Promise<unknown>): Promise<void> {
  try {
    await promise;
    expect.fail("expected ACCESS_DENIED");
  } catch (e) {
    expect(e).toBeInstanceOf(VaultError);
    expect((e as VaultError).code).toBe(ErrorCode.ACCESS_DENIED);
  }
}

/** A use action that, once past the policy gate, fails deterministically at the
 *  fail-safe command allowlist — no network, no spawn. Gate open ⇒
 *  COMMAND_NOT_ALLOWED; gate closed ⇒ ACCESS_DENIED. */
const PROCESS_ACTION = {
  type: "process",
  command: "definitely-not-allowlisted",
  env_var: "SECRET",
} as const;

async function expectGateOpenOnUse(handle: string, caller?: CallerContext): Promise<void> {
  try {
    await engine.useSecret(handle, PROCESS_ACTION, caller);
    expect.fail("expected COMMAND_NOT_ALLOWED past the gate");
  } catch (e) {
    expect((e as VaultError).code).toBe(ErrorCode.COMMAND_NOT_ALLOWED);
  }
}

describe("presence gate", () => {
  it("a secret without policy rows is governed by token scope alone — all six ops pass the gate", async () => {
    await makeSecret("open-secret");
    const caller = agent("anyone");

    await expect(engine.getSecretInfo("secret://open-secret", caller)).resolves.toMatchObject({
      name: "open-secret",
    });
    await expect(engine.getSecretValue("secret://open-secret", caller)).resolves.toEqual(VALUE);
    await expectGateOpenOnUse("secret://open-secret", caller);
    // Gate open ⇒ set_value reaches the manager, which rejects the ACTIVE
    // state with INVALID_INPUT (set_value is the pending-secret path).
    await expect(
      engine.setSecretValue("secret://open-secret", new Uint8Array([1]), caller),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
    await expect(
      engine.rotateSecret("secret://open-secret", new Uint8Array([2]), caller),
    ).resolves.toBeUndefined();
    await expect(engine.revokeSecret("secret://open-secret", caller)).resolves.toBeUndefined();
  });

  it("rows that are all expired leave the gate open", async () => {
    const id = await makeSecret("stale-gate");
    grant(id, "agent", "alice", ["use"], Date.now() - 1000);

    await expect(engine.getSecretValue("secret://stale-gate", agent("bob"))).resolves.toEqual(
      VALUE,
    );
  });

  it("an expired grant beside another principal's live row does not grant", async () => {
    const id = await makeSecret("mixed-gate");
    grant(id, "agent", "alice", ["read"], Date.now() - 1000);
    grant(id, "agent", "bob", ["read"]);

    await expectDenied(engine.getSecretValue("secret://mixed-gate", agent("alice")));
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
    await expectDenied(engine.useSecret("secret://gated", PROCESS_ACTION, agent("bob")));
  });

  it("permissions are granular — a use grant confers nothing else", async () => {
    const id = await makeSecret("use-only");
    grant(id, "agent", "alice", ["use"]);
    const alice = agent("alice");

    await expectDenied(engine.getSecretInfo("secret://use-only", alice));
    await expectDenied(engine.getSecretValue("secret://use-only", alice));
    await expectDenied(engine.rotateSecret("secret://use-only", new Uint8Array([1]), alice));
    await expectDenied(engine.setSecretValue("secret://use-only", new Uint8Array([1]), alice));
    await expectDenied(engine.revokeSecret("secret://use-only", alice));
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

    await expectDenied(
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
    await expectDenied(engine.getSecretValue("secret://proj-gated", agent("charlie")));
    // An agent whose *name* collides with the project id gains nothing.
    await expectDenied(engine.getSecretValue("secret://proj-gated", agent("api")));
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
  it("use denial fires before value resolution — a valueless (pending) secret still denies with ACCESS_DENIED", async () => {
    const id = await makeSecret("pending-gated", false);
    grant(id, "agent", "alice", ["use"]);

    await expectDenied(engine.useSecret("secret://pending-gated", PROCESS_ACTION, agent("bob")));
  });

  it("use denial fires before the injection policy is evaluated", async () => {
    const id = await makeSecret("order-pin");
    grant(id, "agent", "alice", ["use"]);

    // Gate closed ⇒ ACCESS_DENIED; had the injector run first, the empty
    // fail-safe command allowlist would have produced COMMAND_NOT_ALLOWED.
    await expectDenied(engine.useSecret("secret://order-pin", PROCESS_ACTION, agent("bob")));
  });
});

describe("audit attribution", () => {
  it("a policy denial writes the op event with success:false, principal columns and required_permission", async () => {
    const id = await makeSecret("audit-deny");
    grant(id, "agent", "alice", ["use"]);

    await expectDenied(engine.useSecret("secret://audit-deny", PROCESS_ACTION, agent("mallory")));

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
    await expectDenied(engine.getSecretValue("secret://chain-mix", agent("eve")));
    await expectDenied(
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

  it("legacy shape: no option → no claim in the payload, audited as agent", async () => {
    const token = engine.createToken("legacy", ["use"], 60_000);
    const payload = engine.verifyToken(token);
    expect("principal_type" in payload).toBe(false);

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
