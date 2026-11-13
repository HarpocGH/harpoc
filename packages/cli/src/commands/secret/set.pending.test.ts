import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { CertManager } from "@harpoc/cert-manager";
import type { DecryptedAuditEvent, VaultEngine } from "@harpoc/core";
import { AuditEventType } from "@harpoc/shared";
import type { OAuthProviderConfig, Permission, SecretType } from "@harpoc/shared";

const { mockResolveSecretValue } = vi.hoisted(() => ({ mockResolveSecretValue: vi.fn() }));

vi.mock("../../utils/secret-value.js", () => ({ resolveSecretValue: mockResolveSecretValue }));

import { createEngine, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerSecretSetCommand } from "./set.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const TEST_PASSWORD = "test-password-123";
const VALUE = "S3CRET-TOKEN-set";
const OTHER_VALUE = "S3CRET-TOKEN-other";
const OAUTH_CONFIG: OAuthProviderConfig = {
  provider: "github",
  grant_type: "authorization_code",
  token_endpoint: "http://127.0.0.1:9/token",
  auth_endpoint: "http://127.0.0.1:9/authorize",
  client_id: "f2-client-id",
};

type TrailRow = Pick<
  DecryptedAuditEvent,
  "event_type" | "success" | "principal_type" | "principal_id" | "detail"
>;

let vaultDir: string;
let spies: CliSpies;
let handedOut: Buffer[];

beforeAll(async () => {
  vaultDir = join(tmpdir(), `harpoc-setpend-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(vaultDir, { recursive: true });
  const setup = createEngine(vaultDir);
  try {
    await setup.initVault(TEST_PASSWORD);
  } finally {
    await setup.destroy();
  }
});

afterAll(() => {
  rmSync(vaultDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

beforeEach(() => {
  vi.clearAllMocks();
  handedOut = [];
  mockResolveSecretValue.mockImplementation(async () => handOut(VALUE));
  spies = spyCli();
});

afterEach(() => {
  spies.restore();
});

/** Hands the command `text`'s bytes as the resolved value, kept so the wipe can be checked. */
function handOut(text: string): Buffer {
  const value = Buffer.from(text, "utf8");
  handedOut.push(value);
  return value;
}

/** Whether every value handed to the command was zeroed. */
function allWiped(): boolean {
  return handedOut.every((value) => value.every((byte) => byte === 0));
}

/** Runs the real `harpoc --vault-dir <vault> secret set <args>` action. */
async function set(args: string[]): Promise<void> {
  await buildCli(
    (program) => registerSecretSetCommand(program.command("secret")),
    ["--vault-dir", vaultDir, "secret", "set"],
  )(args);
}

/** Opens the vault from its session, hands it to `fn` and destroys it. */
async function withVault<T>(fn: (engine: VaultEngine) => Promise<T>): Promise<T> {
  const engine = await loadUnlockedEngine(vaultDir);
  try {
    return await fn(engine);
  } finally {
    await engine.destroy();
  }
}

/** Creates a secret without a value through the engine and returns its internal id. */
async function pendingSecret(
  secretName: string,
  type: SecretType = "api_key",
  project?: string,
): Promise<string> {
  return withVault(async (engine) => {
    const { handle } = await engine.createSecret({ name: secretName, type, project });
    return engine.resolveSecretId(handle);
  });
}

/** Every audit row of one secret, oldest first. */
async function trail(id: string): Promise<TrailRow[]> {
  return withVault(async (engine) =>
    engine
      .queryAudit({ secretId: id })
      .reverse()
      .map((row) => ({
        event_type: row.event_type,
        success: row.success,
        principal_type: row.principal_type,
        principal_id: row.principal_id,
        detail: row.detail,
      })),
  );
}

interface SqliteHandle {
  prepare(sql: string): { get(...params: unknown[]): unknown };
}

/** The number of non-read rows in the vault's audit log. */
async function auditRowCount(): Promise<number> {
  return withVault(async (engine) => {
    const { db } = (engine as unknown as { store: { db: SqliteHandle } }).store;
    const row = db
      .prepare("SELECT COUNT(*) AS count FROM audit_log WHERE event_type != ?")
      .get(AuditEventType.VAULT_READ) as { count: number };
    return row.count;
  });
}

/** The listed statuses of the secrets a handle names, sorted (a listing writes one vault.read row). */
async function statusesOf(handle: string): Promise<string[]> {
  return withVault(async (engine) =>
    engine
      .listSecrets()
      .filter((entry) => entry.handle === handle)
      .map((entry) => entry.status)
      .sort(),
  );
}

/** Whether the live secret a handle names holds `expected`'s bytes. */
async function holds(handle: string, expected: string): Promise<boolean> {
  return withVault(async (engine) =>
    Buffer.from(await engine.getSecretValue(handle)).equals(Buffer.from(expected, "utf8")),
  );
}

/** A token for a freshly registered agent, with `create` scope and the given grants on `secretId`. */
async function agentToken(agent: string, secretId: string, grants: Permission[]): Promise<string> {
  return withVault(async (engine) => {
    engine.registerAgent({ name: agent });
    if (grants.length > 0) {
      engine.grantPolicy(
        { secretId, principalType: "agent", principalId: agent, permissions: grants },
        "test-admin",
      );
    }
    return engine.createToken(agent, ["create"]);
  });
}

/** The trusted path's `secret.create` row of a create. */
function createRow(handle: string, createStatus: "pending" | "created"): TrailRow {
  return {
    event_type: AuditEventType.SECRET_CREATE,
    success: true,
    principal_type: null,
    principal_id: null,
    detail: { handle, status: createStatus },
  };
}

/** The trusted path's `secret.create` row of a pending secret's value set. */
function setValueRow(handle: string): TrailRow {
  return {
    event_type: AuditEventType.SECRET_CREATE,
    success: true,
    principal_type: null,
    principal_id: null,
    detail: { handle, action: "set_value" },
  };
}

describe("secret set gives a pending secret its value (F2)", () => {
  it("(a) sets the value of a pending secret: active, the value's bytes, one set_value secret.create row after the create's, the plain line exact", async () => {
    const id = await pendingSecret("pend-a");

    await set(["pend-a"]);

    expect(spies.exitSpy).not.toHaveBeenCalled();
    expect(spies.stderr()).toBe("OK: Secret 'pend-a' value set (secret://pend-a)");
    expect(spies.stdout()).toBe("");
    expect(mockResolveSecretValue).toHaveBeenCalledTimes(1);
    expect(allWiped()).toBe(true);
    expect(await trail(id)).toEqual([
      createRow("secret://pend-a", "pending"),
      setValueRow("secret://pend-a"),
    ]);
    expect(await statusesOf("secret://pend-a")).toEqual(["active"]);
    expect(await holds("secret://pend-a", VALUE)).toBe(true);
  });

  it("(b) --project sets the project's pending secret; an unscoped secret set of the same name beside it creates a second, unscoped secret as today", async () => {
    const projectId = await pendingSecret("pend-b", "api_key", "proj-b");
    mockResolveSecretValue
      .mockImplementationOnce(async () => handOut(OTHER_VALUE))
      .mockImplementationOnce(async () => handOut(VALUE));

    await set(["pend-b"]);
    await set(["pend-b", "--project", "proj-b"]);

    expect(spies.exitSpy).not.toHaveBeenCalled();
    expect(spies.stderr()).toBe(
      [
        "OK: Secret 'pend-b' created (secret://pend-b)",
        "OK: Secret 'pend-b' value set (secret://proj-b/pend-b)",
      ].join("\n"),
    );
    expect(allWiped()).toBe(true);
    expect(await trail(projectId)).toEqual([
      createRow("secret://proj-b/pend-b", "pending"),
      setValueRow("secret://proj-b/pend-b"),
    ]);
    expect(await statusesOf("secret://proj-b/pend-b")).toEqual(["active"]);
    expect(await statusesOf("secret://pend-b")).toEqual(["active"]);
    expect(await holds("secret://proj-b/pend-b", VALUE)).toBe(true);
    expect(await holds("secret://pend-b", OTHER_VALUE)).toBe(true);
  });

  it("(c) --json prints one document and no OK line", async () => {
    await pendingSecret("pend-c");

    await set(["pend-c", "--json"]);

    expect(spies.exitSpy).not.toHaveBeenCalled();
    expect(spies.stdout()).toBe(
      JSON.stringify(
        {
          handle: "secret://pend-c",
          status: "created",
          message: "Secret secret://pend-c value set",
        },
        null,
        2,
      ),
    );
    expect(spies.stderr()).toBe("");
    expect(await statusesOf("secret://pend-c")).toEqual(["active"]);
  });

  it("(d) a pending secret of another type refuses INVALID_INPUT before the value resolver is consulted; with its --type it is set", async () => {
    const id = await pendingSecret("pend-d", "certificate");

    await expect(set(["pend-d"])).rejects.toThrow("process.exit");

    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.stderr()).toBe(
      "Error: [INVALID_INPUT] Secret 'pend-d' is pending with type certificate; pass --type certificate to set its value",
    );
    expect(mockResolveSecretValue).toHaveBeenCalledTimes(0);
    expect(await statusesOf("secret://pend-d")).toEqual(["pending"]);
    expect(await trail(id)).toEqual([createRow("secret://pend-d", "pending")]);

    spies.errorSpy.mockClear();
    await set(["pend-d", "--type", "certificate"]);

    expect(spies.stderr()).toBe("OK: Secret 'pend-d' value set (secret://pend-d)");
    expect(mockResolveSecretValue).toHaveBeenCalledTimes(1);
    expect(allWiped()).toBe(true);
    expect(await statusesOf("secret://pend-d")).toEqual(["active"]);
    expect(await holds("secret://pend-d", VALUE)).toBe(true);
  });

  it("(e) an active secret of that name still ends DUPLICATE_SECRET after the value resolver is consulted once, and writes one failed secret.create row carrying the error alone", async () => {
    const id = await withVault(async (engine) => {
      const { handle } = await engine.createSecret({
        name: "act-e",
        type: "api_key",
        value: new Uint8Array(Buffer.from(OTHER_VALUE)),
      });
      return engine.resolveSecretId(handle);
    });
    const failedCreates = () =>
      withVault(async (engine) =>
        engine
          .queryAudit({ eventType: AuditEventType.SECRET_CREATE, success: false })
          .map((row) => [row.secret_id, row.principal_id, row.detail]),
      );
    const failedBefore = await failedCreates();
    const rowsBefore = await auditRowCount();

    await expect(set(["act-e"])).rejects.toThrow("process.exit");

    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.stderr()).toBe("Error: Secret already exists: act-e");
    expect(mockResolveSecretValue).toHaveBeenCalledTimes(1);
    expect(allWiped()).toBe(true);
    expect(await auditRowCount()).toBe(rowsBefore + 1);
    const failedAfter = await failedCreates();
    const failed = failedAfter.slice(0, failedAfter.length - failedBefore.length);
    expect(failed).toEqual([[null, null, { error: "DUPLICATE_SECRET" }]]);
    expect(JSON.stringify(failed).includes("act-e")).toBe(false);
    expect(await trail(id)).toEqual([createRow("secret://act-e", "created")]);
    expect(await holds("secret://act-e", OTHER_VALUE)).toBe(true);
  });

  it("(f) no live secret of that name: created as before", async () => {
    await set(["new-f"]);

    expect(spies.exitSpy).not.toHaveBeenCalled();
    expect(spies.stderr()).toBe("OK: Secret 'new-f' created (secret://new-f)");
    expect(mockResolveSecretValue).toHaveBeenCalledTimes(1);
    expect(allWiped()).toBe(true);
    const id = await withVault((engine) => engine.resolveSecretId("secret://new-f"));
    expect(await trail(id)).toEqual([createRow("secret://new-f", "created")]);
    expect(await holds("secret://new-f", VALUE)).toBe(true);
  });

  it("(g) a revoked secret of that name is not matched: a new secret is created as before", async () => {
    const revokedId = await pendingSecret("rev-g");
    await withVault((engine) => engine.revokeSecret("secret://rev-g"));

    await set(["rev-g"]);

    expect(spies.exitSpy).not.toHaveBeenCalled();
    expect(spies.stderr()).toBe("OK: Secret 'rev-g' created (secret://rev-g)");
    expect(await statusesOf("secret://rev-g")).toEqual(["active", "revoked"]);
    expect((await trail(revokedId)).map((row) => row.event_type)).toEqual([
      AuditEventType.SECRET_CREATE,
      AuditEventType.SECRET_REVOKE,
    ]);
    expect(await holds("secret://rev-g", VALUE)).toBe(true);
  });

  it.each([
    {
      args: ["bad.name"],
      line: "Error: [INVALID_SECRET_NAME] Invalid secret name: bad.name",
    },
    {
      args: ["good-h", "--project", "bad.proj"],
      line: "Error: [INVALID_PROJECT_NAME] Invalid project name: bad.proj",
    },
  ])(
    "(h) $args: the handle refusal still follows the value resolver, as today",
    async ({ args, line }) => {
      await expect(set(args)).rejects.toThrow("process.exit");

      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.stderr()).toBe(line);
      expect(mockResolveSecretValue).toHaveBeenCalledTimes(1);
      expect(allWiped()).toBe(true);
    },
  );

  it("(i) a pending secret an OAuth flow owns: the default type refuses before the resolver, --type oauth_token gets the engine's refusal after it, the secret still pending", async () => {
    const id = await withVault(
      async (engine) => (await engine.createOAuthSecret("oauth-i", OAUTH_CONFIG)).secretId,
    );

    await expect(set(["oauth-i"])).rejects.toThrow("process.exit");
    expect(spies.stderr()).toBe(
      "Error: [INVALID_INPUT] Secret 'oauth-i' is pending with type oauth_token; pass --type oauth_token to set its value",
    );
    expect(mockResolveSecretValue).toHaveBeenCalledTimes(0);

    spies.errorSpy.mockClear();
    await expect(set(["oauth-i", "--type", "oauth_token"])).rejects.toThrow("process.exit");

    expect(spies.exitSpy.mock.calls).toEqual([[1], [1]]);
    expect(spies.stderr()).toBe(
      "Error: [INVALID_INPUT] Secret secret://oauth-i is waiting for its OAuth flow — complete it with harpoc oauth connect",
    );
    expect(mockResolveSecretValue).toHaveBeenCalledTimes(1);
    expect(allWiped()).toBe(true);
    expect(await statusesOf("secret://oauth-i")).toEqual(["pending"]);
    expect(await trail(id)).toEqual([
      expect.objectContaining({ event_type: AuditEventType.OAUTH_AUTHORIZE, success: true }),
      {
        event_type: AuditEventType.SECRET_CREATE,
        success: false,
        principal_type: null,
        principal_id: null,
        detail: { handle: "secret://oauth-i", action: "set_value", error: "INVALID_INPUT" },
      },
    ]);
  });

  it("(j) a CSR's pending certificate with --type certificate gets the engine's certificate refusal, the secret still pending", async () => {
    await withVault(async (engine) => {
      await new CertManager(engine).generateCsr("csr-j", {
        commonName: "csr.example.test",
        algorithm: "ec",
      });
    });

    await expect(set(["csr-j", "--type", "certificate"])).rejects.toThrow("process.exit");

    expect(spies.stderr()).toBe(
      "Error: [CERT_VALUE_UNSUPPORTED] Certificate secrets cannot be used as a raw value: secret://csr-j",
    );
    expect(allWiped()).toBe(true);
    expect(await statusesOf("secret://csr-j")).toEqual(["pending"]);
  });
});

describe("secret set with a token on a pending secret (F2)", () => {
  it("a create-scoped token holding no grant on the pending secret: DUPLICATE_SECRET as today, no set_value row", async () => {
    const id = await pendingSecret("tok-none");
    const jwt = await agentToken("agent-none", id, []);

    await expect(set(["tok-none", "--token", jwt])).rejects.toThrow("process.exit");

    expect(spies.stderr()).toBe("Error: Secret already exists: tok-none");
    expect(mockResolveSecretValue).toHaveBeenCalledTimes(1);
    expect(allWiped()).toBe(true);
    expect(await trail(id)).toEqual([createRow("secret://tok-none", "pending")]);
    expect(await statusesOf("secret://tok-none")).toEqual(["pending"]);
  });

  it("a create-scoped token granted list and rotate on the pending secret sets the value, the row carrying the token's principal", async () => {
    const id = await pendingSecret("tok-granted");
    const jwt = await agentToken("agent-granted", id, ["list", "rotate"]);

    await set(["tok-granted", "--token", jwt]);

    expect(spies.exitSpy).not.toHaveBeenCalled();
    expect(spies.stderr()).toBe("OK: Secret 'tok-granted' value set (secret://tok-granted)");
    expect(allWiped()).toBe(true);
    expect(await trail(id)).toEqual([
      createRow("secret://tok-granted", "pending"),
      expect.objectContaining({ event_type: AuditEventType.POLICY_GRANT, success: true }),
      {
        event_type: AuditEventType.SECRET_CREATE,
        success: true,
        principal_type: "agent",
        principal_id: "agent-granted",
        detail: { handle: "secret://tok-granted", action: "set_value", interface: "cli" },
      },
    ]);
    expect(await holds("secret://tok-granted", VALUE)).toBe(true);
  });

  it("a token granted list but not rotate is refused by the engine's rotate gate after the resolver, the secret still pending", async () => {
    const id = await pendingSecret("tok-list");
    const jwt = await agentToken("agent-list", id, ["list"]);

    await expect(set(["tok-list", "--token", jwt])).rejects.toThrow("process.exit");

    expect(spies.stderr()).toBe(
      "Error: [ACCESS_DENIED] Access denied: Principal lacks 'rotate' permission on this secret",
    );
    expect(mockResolveSecretValue).toHaveBeenCalledTimes(1);
    expect(allWiped()).toBe(true);
    expect(await trail(id)).toEqual([
      createRow("secret://tok-list", "pending"),
      expect.objectContaining({ event_type: AuditEventType.POLICY_GRANT, success: true }),
      {
        event_type: AuditEventType.SECRET_CREATE,
        success: false,
        principal_type: "agent",
        principal_id: "agent-list",
        detail: {
          handle: "secret://tok-list",
          action: "set_value",
          required_permission: "rotate",
          error: "ACCESS_DENIED",
          interface: "cli",
        },
      },
    ]);
    expect(await statusesOf("secret://tok-list")).toEqual(["pending"]);
  });
});
