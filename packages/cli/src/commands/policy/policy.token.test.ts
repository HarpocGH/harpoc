import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    verifyToken: vi.fn(),
    grantPolicy: vi.fn().mockReturnValue({
      id: "pol-1",
      secret_id: "sid-1",
      principal_type: "agent",
      principal_id: "bot",
      permissions: ["use"],
      created_at: 0,
      expires_at: null,
    }),
    revokePolicy: vi.fn((policyId: string) => {
      if (policyId !== "pol-1") {
        throw new VaultError(ErrorCode.POLICY_NOT_FOUND, `Policy not found: ${policyId}`);
      }
    }),
    listPolicies: vi.fn().mockReturnValue([
      {
        id: "pol-1",
        secret_id: "sid-1",
        principal_type: "agent",
        principal_id: "bot",
        permissions: ["use"],
        created_at: 0,
        expires_at: null,
      },
    ]),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("sid-1"),
}));

import { registerPolicyGrantCommand } from "./grant.js";
import { registerPolicyRevokeCommand } from "./revoke.js";
import { registerPolicyListCommand } from "./list.js";
import { loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { buildCli, spyCli, tokenFixture, type CliSpies } from "../../__fixtures__/cli-harness.js";

const GRANT_ARGS = [
  "grant",
  "secret://k",
  "--principal-type",
  "agent",
  "--principal-id",
  "bot",
  "--permissions",
  "use",
];

describe("policy commands — token path", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  const run = buildCli(
    (program) => {
      const policy = program.command("policy");
      registerPolicyGrantCommand(policy);
      registerPolicyRevokeCommand(policy);
      registerPolicyListCommand(policy);
    },
    ["policy"],
  );

  it("grant: admin-scoped token passes the caller and stamps createdBy = token sub", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));
    await run([...GRANT_ARGS, "--token", "jwt-value"]);
    expect(mockEngine.grantPolicy).toHaveBeenCalledWith(
      expect.objectContaining({ secretId: "sid-1", principalId: "bot" }),
      "agent-1",
      expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
    );
  });

  it("grant: tokenless keeps createdBy = cli-user and no caller", async () => {
    await run(GRANT_ARGS);
    expect(mockEngine.grantPolicy).toHaveBeenCalledWith(expect.anything(), "cli-user", undefined);
  });

  it("grant: a use-scoped token is refused before handle resolution", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["use"] }));
    await expect(run([...GRANT_ARGS, "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(mockEngine.grantPolicy).not.toHaveBeenCalled();
    expect(resolveSecretId).not.toHaveBeenCalled();
  });

  it("revoke: a token without --secret is refused with guidance", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));
    await expect(run(["revoke", "pol-1", "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--secret <handle> is required"),
    );
    expect(mockEngine.revokePolicy).not.toHaveBeenCalled();
  });

  it('revoke: --secret "" with a token is refused, never the trusted path', async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));
    await expect(run(["revoke", "pol-1", "--secret", "", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--secret <handle> is required"),
    );
    expect(mockEngine.revokePolicy).not.toHaveBeenCalled();
    expect(mockEngine.listPolicies).not.toHaveBeenCalled();
  });

  it("revoke: with --secret it scope-checks and hands the engine the caller and the secret id", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));
    await run(["revoke", "pol-1", "--secret", "secret://k", "--token", "jwt-value"]);
    expect(mockEngine.listPolicies).not.toHaveBeenCalled();
    expect(mockEngine.revokePolicy).toHaveBeenCalledWith(
      "pol-1",
      expect.objectContaining({ interface: "cli" }),
      "sid-1",
    );
  });

  it("revoke: forwards --secret's id to revokePolicy and renders its refusal", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));
    await expect(
      run(["revoke", "pol-other", "--secret", "secret://k", "--token", "jwt-value"]),
    ).rejects.toThrow("process.exit");
    expect(mockEngine.listPolicies).not.toHaveBeenCalled();
    expect(mockEngine.revokePolicy).toHaveBeenCalledWith(
      "pol-other",
      expect.objectContaining({ interface: "cli" }),
      "sid-1",
    );
  });

  it("revoke: tokenless without --secret is unchanged", async () => {
    await run(["revoke", "pol-1"]);
    expect(mockEngine.revokePolicy).toHaveBeenCalledWith("pol-1", undefined, undefined);
  });

  it.each([
    {
      label: "a token without --secret",
      token: "jwt-value",
      line: "Error: [INVALID_INPUT] --secret <handle> is required when using --token: token scope is checked against the secret the policy belongs to.",
    },
    {
      label: "an empty --token, before the --secret check",
      token: "",
      line: "Error: [INVALID_INPUT] --token (or HARPOC_TOKEN) was supplied but empty. Provide a token, or omit it entirely to use the trusted local path.",
    },
  ])(
    "revoke: refuses $label INVALID_INPUT, its message unchanged (T4)",
    async ({ token, line }) => {
      mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));
      await expect(run(["revoke", "pol-1", "--token", token])).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([[line]]);
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(mockEngine.verifyToken).not.toHaveBeenCalled();
      expect(mockEngine.revokePolicy).not.toHaveBeenCalled();
    },
  );

  it("revoke: a locked vault reports VAULT_LOCKED before the --secret refusal (T4)", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(VaultError.vaultLocked());
    try {
      await expect(run(["revoke", "pol-1", "--token", "jwt-value"])).rejects.toThrow(
        "process.exit",
      );
      expect(spies.errorSpy.mock.calls).toEqual([
        ["Error: Vault is locked. Run 'harpoc unlock' first."],
      ]);
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    } finally {
      vi.mocked(loadUnlockedEngine).mockReset();
      vi.mocked(loadUnlockedEngine).mockResolvedValue(mockEngine as never);
    }
  });

  it("list: with a handle, read scope is checked and the caller passed", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
    await run(["list", "secret://k", "--token", "jwt-value"]);
    expect(mockEngine.listPolicies).toHaveBeenCalledWith(
      "sid-1",
      expect.objectContaining({ interface: "cli" }),
      "secret://k",
    );
  });

  it("list: handle-less with a token passes the caller and no secret id (the refusal is the engine's)", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
    await run(["list", "--token", "jwt-value"]);
    expect(mockEngine.listPolicies).toHaveBeenCalledWith(
      undefined,
      expect.objectContaining({ interface: "cli" }),
      undefined,
    );
  });
});
