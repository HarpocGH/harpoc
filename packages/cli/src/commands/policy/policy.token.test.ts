import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import type { VaultApiToken } from "@harpoc/shared";

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
    revokePolicy: vi.fn().mockReturnValue(undefined),
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

function token(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "agent-1",
    vault_id: "vault-1",
    scope: ["read"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
    ...overrides,
  };
}

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
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
    if (savedEnvToken === undefined) delete process.env.HARPOC_TOKEN;
    else process.env.HARPOC_TOKEN = savedEnvToken;
  });

  async function run(args: string[]): Promise<void> {
    const program = new Command();
    program.option("--vault-dir <path>");
    const policy = program.command("policy");
    registerPolicyGrantCommand(policy);
    registerPolicyRevokeCommand(policy);
    registerPolicyListCommand(policy);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "policy", ...args]);
  }

  it("grant: admin-scoped token passes the caller and stamps createdBy = token sub", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["admin"] }));
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
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["use"] }));
    await expect(run([...GRANT_ARGS, "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(mockEngine.grantPolicy).not.toHaveBeenCalled();
  });

  it("revoke: a token without --secret is refused with guidance", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["admin"] }));
    await expect(run(["revoke", "pol-1", "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--secret <handle> is required"));
    expect(mockEngine.revokePolicy).not.toHaveBeenCalled();
  });

  it('revoke: --secret "" with a token is refused, never the trusted path', async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["admin"] }));
    await expect(run(["revoke", "pol-1", "--secret", "", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--secret <handle> is required"));
    expect(mockEngine.revokePolicy).not.toHaveBeenCalled();
    expect(mockEngine.listPolicies).not.toHaveBeenCalled();
  });

  it("revoke: with --secret it scope-checks, membership-checks caller-less and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["admin"] }));
    await run(["revoke", "pol-1", "--secret", "secret://k", "--token", "jwt-value"]);
    expect(mockEngine.listPolicies).toHaveBeenCalledWith("sid-1");
    expect(mockEngine.revokePolicy).toHaveBeenCalledWith(
      "pol-1",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("revoke: a policy id not belonging to --secret is refused", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["admin"] }));
    await expect(
      run(["revoke", "pol-other", "--secret", "secret://k", "--token", "jwt-value"]),
    ).rejects.toThrow("process.exit");
    expect(mockEngine.revokePolicy).not.toHaveBeenCalled();
  });

  it("revoke: tokenless without --secret is unchanged", async () => {
    await run(["revoke", "pol-1"]);
    expect(mockEngine.revokePolicy).toHaveBeenCalledWith("pol-1", undefined);
  });

  it("list: with a handle, read scope is checked and the caller passed", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await run(["list", "secret://k", "--token", "jwt-value"]);
    expect(mockEngine.listPolicies).toHaveBeenCalledWith(
      "sid-1",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("list: handle-less with a token still passes the caller — the engine refuses (fail-closed)", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await run(["list", "--token", "jwt-value"]);
    expect(mockEngine.listPolicies).toHaveBeenCalledWith(
      undefined,
      expect.objectContaining({ interface: "cli" }),
    );
  });
});
