import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, McpServerConfig, Permission } from "@harpoc/shared";
import { ErrorCode, SecretType, VaultError } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";

/**
 * T7: which permission each caller-gated method demands was pinned only
 * against a `use` grant, so the literal at any single gate could be swapped
 * for another and the suite stayed green — including the `admin` gate on
 * `grantPolicy`/`revokePolicy`, which W1 made load-bearing: config
 * administrators hold `rotate`, and a `rotate`-shaped grant gate there would
 * let them grant themselves `admin` and walk past every V1/W1 check.
 *
 * The matrix drives every gated method with a caller holding exactly one
 * permission and asserts the operation is refused unless that permission is
 * the required one (or `admin`, which implies all). `create` is not in the
 * per-secret vocabulary — `grantPolicy` refuses it (W2) — and `list` governs
 * enumeration, which filters rather than throwing, so it is covered by its own
 * case below.
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
let counter = 0;

const PRINCIPAL = "matrix-agent";
const GRANTABLE: Permission[] = ["list", "read", "use", "rotate", "revoke", "admin"];

const MCP_CONFIG: McpServerConfig = {
  server_name: "docs",
  transport: "http",
  url: "https://mcp.example.com/mcp",
  auth: { type: "bearer" },
};

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-pmx-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

const caller = (): CallerContext => ({
  principal_type: "agent",
  principal_id: PRINCIPAL,
  interface: "rest",
});

/** A fresh secret carrying exactly one grant to the matrix principal. */
async function secretGranting(permission: Permission): Promise<{ handle: string; id: string }> {
  const name = `mx-${permission}-${counter++}`;
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from("value", "utf8")),
  });
  const id = await engine.resolveSecretId(`secret://${name}`);
  engine.grantPolicy(
    { secretId: id, principalType: "agent", principalId: PRINCIPAL, permissions: [permission] },
    "admin",
  );
  return { handle: `secret://${name}`, id };
}

function isAccessDenied(err: unknown): boolean {
  return err instanceof VaultError && err.code === ErrorCode.ACCESS_DENIED;
}

/**
 * Runs the operation and reports only whether the policy layer refused it.
 * Downstream failures (no allowlist, absent config, unusable secret) are not
 * the subject: the gate is, and it runs before all of them.
 */
async function refused(op: () => unknown): Promise<boolean> {
  try {
    await op();
    return false;
  } catch (err) {
    if (isAccessDenied(err)) return true;
    return false;
  }
}

interface GatedMethod {
  name: string;
  required: Permission;
  invoke: (handle: string, id: string, c: CallerContext) => unknown;
}

const METHODS: GatedMethod[] = [
  { name: "getSecretInfo", required: "read", invoke: (h, _i, c) => engine.getSecretInfo(h, c) },
  { name: "getSecretValue", required: "read", invoke: (h, _i, c) => engine.getSecretValue(h, c) },
  {
    name: "setSecretValue",
    required: "rotate",
    invoke: (h, _i, c) => engine.setSecretValue(h, new Uint8Array(Buffer.from("new")), c),
  },
  {
    name: "rotateSecret",
    required: "rotate",
    invoke: (h, _i, c) => engine.rotateSecret(h, new Uint8Array(Buffer.from("new")), c),
  },
  { name: "revokeSecret", required: "revoke", invoke: (h, _i, c) => engine.revokeSecret(h, c) },
  {
    name: "useSecret",
    required: "use",
    invoke: (h, _i, c) =>
      engine.useSecret(h, { type: "process", command: "no-such-binary", env_var: "TOKEN" }, c),
  },
  {
    name: "getInjectionPolicy",
    required: "read",
    invoke: (h, _i, c) => engine.getInjectionPolicy(h, c),
  },
  {
    name: "setInjectionPolicy",
    required: "rotate",
    invoke: (h, _i, c) => engine.setInjectionPolicy(h, { url_allowlist: ["https://ok/*"] }, {}, c),
  },
  {
    name: "getMcpServerConfig",
    required: "read",
    invoke: (h, _i, c) => engine.getMcpServerConfig(h, c),
  },
  {
    name: "setMcpServerConfig",
    required: "rotate",
    invoke: (h, _i, c) => engine.setMcpServerConfig(h, MCP_CONFIG, c),
  },
  {
    name: "deleteMcpServerConfig",
    required: "rotate",
    invoke: (h, _i, c) => engine.deleteMcpServerConfig(h, c),
  },
  {
    name: "getConnectionConfig",
    required: "read",
    invoke: (h, _i, c) => engine.getConnectionConfig(h, c),
  },
  {
    name: "setConnectionConfig",
    required: "rotate",
    invoke: (h, _i, c) => engine.setConnectionConfig(h, { database: { tls_mode: "require" } }, c),
  },
  {
    name: "deleteConnectionConfig",
    required: "rotate",
    invoke: (h, _i, c) => engine.deleteConnectionConfig(h, c),
  },
  { name: "listPolicies", required: "read", invoke: (_h, i, c) => engine.listPolicies(i, c) },
  {
    name: "grantPolicy",
    required: "admin",
    invoke: (_h, i, c) =>
      engine.grantPolicy(
        { secretId: i, principalType: "agent", principalId: "someone-else", permissions: ["read"] },
        "admin",
        c,
      ),
  },
  {
    name: "revokePolicy",
    required: "admin",
    invoke: (_h, i, c) => {
      const target = engine.grantPolicy(
        { secretId: i, principalType: "agent", principalId: "victim", permissions: ["read"] },
        "admin",
      );
      return engine.revokePolicy(target.id, c);
    },
  },
];

describe("per-secret permission matrix (T7)", () => {
  it.each(METHODS)("$name demands exactly '$required'", async ({ required, invoke }) => {
    for (const held of GRANTABLE) {
      const { handle, id } = await secretGranting(held);
      const denied = await refused(() => invoke(handle, id, caller()));
      const shouldPass = held === required || held === "admin";

      expect(
        denied,
        `holding '${held}' the call was ${denied ? "refused" : "allowed"}, expected ${
          shouldPass ? "allowed" : "refused"
        }`,
      ).toBe(!shouldPass);
    }
  });

  /**
   * The escalation the matrix exists to prevent: W1 gives configuration
   * administrators `rotate`, so if the grant gate ever demanded `rotate` the
   * config administrator could write itself an `admin` row and from there read
   * the value, use it and rewrite every allowlist.
   */
  it("a rotate-only principal cannot grant itself admin", async () => {
    const { handle, id } = await secretGranting("rotate");

    await expect(
      Promise.resolve().then(() =>
        engine.grantPolicy(
          {
            secretId: id,
            principalType: "agent",
            principalId: PRINCIPAL,
            permissions: ["admin"],
          },
          "admin",
          caller(),
        ),
      ),
    ).rejects.toMatchObject({ code: ErrorCode.ACCESS_DENIED });

    // And the escalation target really is closed: reading the value still fails.
    await expect(engine.getSecretValue(handle, caller())).rejects.toMatchObject({
      code: ErrorCode.ACCESS_DENIED,
    });
    expect(engine.listPolicies(id).filter((p) => p.permissions.includes("admin"))).toHaveLength(0);
  });

  /**
   * `list` is the one permission whose enforcement filters instead of throwing
   * (W2, D6: a per-row denial audit would scale with vault size), so it needs
   * its own shape of assertion — but it belongs to the same vocabulary and the
   * same question: does holding one permission imply another?
   */
  it("enumeration is governed by 'list' alone (read does not imply it)", async () => {
    const visibility = new Map<Permission, boolean>();
    for (const held of GRANTABLE) {
      const { handle } = await secretGranting(held);
      const name = handle.replace("secret://", "");
      visibility.set(
        held,
        engine.listSecrets(undefined, caller()).some((s) => s.name === name),
      );
    }

    expect(visibility.get("list")).toBe(true);
    expect(visibility.get("admin")).toBe(true);
    expect(visibility.get("read")).toBe(false);
    expect(visibility.get("use")).toBe(false);
    expect(visibility.get("rotate")).toBe(false);
    expect(visibility.get("revoke")).toBe(false);
  });

  /**
   * Control: with no policy rows at all the gate is not in play (V1 presence
   * rule), so none of these calls may be refused — otherwise the matrix above
   * would be passing for the wrong reason. `revokePolicy` is excluded because
   * its precondition *is* a policy row: writing one is exactly what turns the
   * presence gate on, which the next case asserts.
   */
  it("control: a secret with no policy rows refuses none of the operations", async () => {
    for (const method of METHODS) {
      if (method.name === "revokePolicy") continue;
      const name = `mx-free-${counter++}`;
      await engine.createSecret({
        name,
        type: SecretType.API_KEY,
        value: new Uint8Array(Buffer.from("value", "utf8")),
      });
      const id = await engine.resolveSecretId(`secret://${name}`);
      const denied = await refused(() => method.invoke(`secret://${name}`, id, caller()));
      expect(denied, `${method.name} was refused on an ungated secret`).toBe(false);
    }
  });

  it("the first policy row closes the gate on a caller the row does not name", async () => {
    const name = `mx-presence-${counter++}`;
    await engine.createSecret({
      name,
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("value", "utf8")),
    });
    const handle = `secret://${name}`;
    const id = await engine.resolveSecretId(handle);

    await expect(engine.getSecretInfo(handle, caller())).resolves.toBeDefined();

    engine.grantPolicy(
      { secretId: id, principalType: "agent", principalId: "someone-else", permissions: ["read"] },
      "admin",
    );

    await expect(engine.getSecretInfo(handle, caller())).rejects.toMatchObject({
      code: ErrorCode.ACCESS_DENIED,
    });
  });
});
